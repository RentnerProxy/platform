import assert from 'node:assert/strict'
import { execFile } from 'node:child_process'
import { randomUUID } from 'node:crypto'
import { cp, mkdir, mkdtemp, rename, rm, writeFile } from 'node:fs/promises'
import { dirname, join, resolve } from 'node:path'
import { promisify } from 'node:util'
import { waitForSmoke } from '../../../../../scripts/smoke/wait.ts'
import { appEntrypoint, architecture, makeBootstrap, runtimeProfile } from './catalog.ts'
import type { Architecture } from './catalog.ts'
import { exerciseSockets } from './sockets.ts'

const appliance =
    'ghcr.io/rentnerproxy/platform@sha256:6a9ecb2330c20f366590f4c6c1c32441104a44c8435d7858cbef4d9496e07b46'
const builder =
    'mirror.gcr.io/library/rust:1.100-trixie@sha256:e19840879045c951c905d0eaa9887f3439c62000e429963371b376bac8d38c31'
const brokerSource = 'core/tests/fixtures/app-runtime-reference'
const uiSource = 'web/src/tests/fixtures/app-runtime-reference'
const installed = '/reference-install'
const bootstrapPath = '/tmp/reference-bootstrap'
const rootPath = '/tmp/reference-root.pem'
const installer = '/tmp/reference-catalog.ts'
const bunVersion = '1.4.4'
const applianceGlibc = '2.41'

const execute = promisify(execFile)

async function command(file: string, args: string[], timeout = 20_000) {
    const { stdout } = await execute(file, args, { timeout, windowsHide: true })
    return stdout.trim()
}

const docker = (args: string[], timeout?: number) => command('docker', args, timeout)
const inAppliance = (container: string, ...args: string[]) => docker(['exec', container, ...args])

async function removeContainer(name: string) {
    try {
        await docker(['rm', '--force', '--volumes', name])
    } catch (error) {
        if (!/no such container/iu.test(String(error))) throw error
    }
}

async function buildApp(work: string, arch: Architecture) {
    const source = join(work, 'app-source')
    await mkdir(source)
    await Promise.all(
        ['app.ts', 'app-providers.ts'].map((name) =>
            cp(join(import.meta.dir, name), join(source, name)),
        ),
    )
    const id = 'app-reference-build-' + randomUUID()
    try {
        await docker(
            [
                'create',
                '--name',
                id,
                '--network',
                'none',
                '--platform',
                'linux/' + arch,
                '--entrypoint',
                '/bin/sh',
                appliance,
                '-ceu',
                'cd /reference; test "$(bun --version)" = "$1"; ' +
                    'bun --no-env-file build --compile ./app.ts --outfile /reference/app',
                'build-native-app',
                bunVersion,
            ],
            180_000,
        )
        await docker(['cp', source, id + ':/reference'])
        await docker(['start', '--attach', id], 120_000)
        const backend = join(work, 'app')
        await docker(['cp', id + ':/reference/app', backend])
        return backend
    } finally {
        await removeContainer(id)
    }
}

async function buildRuntime(work: string, arch: Architecture) {
    const backend = await buildApp(work, arch)
    const source = join(work, 'broker-source')
    await mkdir(source)
    await Promise.all(
        ['Cargo.toml', 'Cargo.lock', 'src'].map((path) =>
            cp(join(brokerSource, path), join(source, path), { recursive: true }),
        ),
    )
    const executable = 'target/release/app-runtime-reference'
    const id = 'app-reference-broker-build-' + randomUUID()
    try {
        await docker(
            [
                'create',
                '--name',
                id,
                '--platform',
                'linux/' + arch,
                '--env',
                'RUSTFLAGS=-C target-cpu=generic',
                builder,
                'sh',
                '-ceu',
                [
                    'cd /reference',
                    'cargo build --release --locked',
                    'rustc -vV',
                    'readelf --wide --version-info ./app',
                    'readelf --notes ./app',
                ].join('\n'),
            ],
            180_000,
        )
        await docker(['cp', source, id + ':/reference'])
        await docker(['cp', backend, id + ':/reference/app'])
        const build = await docker(['start', '--attach', id], 240_000)
        const target = arch === 'amd64' ? 'x86_64-unknown-linux-gnu' : 'aarch64-unknown-linux-gnu'
        assert.ok(build.split('\n').includes('host: ' + target), 'Rust builder is not native')
        const requiredGlibc = [...new Set(build.match(/(?<=\bGLIBC_)\d+(?:\.\d+)+/gu))].toSorted(
            (left, right) => left.localeCompare(right, 'en', { numeric: true }),
        )
        const newestGlibc = requiredGlibc.at(-1)
        assert.ok(
            newestGlibc && newestGlibc.localeCompare(applianceGlibc, 'en', { numeric: true }) <= 0,
            'Fixture exceeds the Debian 13 glibc baseline',
        )
        const broker = join(work, 'broker')
        await docker(['cp', id + ':/reference/' + executable, broker])
        return {
            backend,
            broker,
            toolchain: {
                bunVersion,
                bunImage: appliance,
                target: 'linux-' + arch,
                brokerImage: builder,
                brokerRustc: build.split('\n').find((line) => line.startsWith('rustc ')),
                elfAbi: build
                    .split('\n')
                    .find((line) => line.includes('OS: Linux, ABI:'))
                    ?.trim(),
                requiredGlibc,
            },
        }
    } finally {
        await removeContainer(id)
    }
}

async function withAppliance<T>(
    arch: Architecture,
    volume: string,
    offline: boolean,
    exercise: (container: string) => Promise<T>,
) {
    const id = 'app-reference-appliance-' + randomUUID()
    try {
        await docker(
            [
                'run',
                '--name',
                id,
                '--detach',
                '--platform',
                'linux/' + arch,
                '--network',
                'none',
                '--mount',
                'type=volume,src=' + volume + ',dst=' + installed + (offline ? ',readonly' : ''),
                '--env',
                'PUBLIC_ORIGIN=https://fixture.invalid',
                '--env',
                'SMTP_FROM=fixture@fixture.invalid',
                '--env',
                'SMTP_HOST=127.0.0.1',
                '--env',
                'SMTP_PORT=2525',
                '--env',
                'SMTP_SECURE=false',
                appliance,
            ],
            180_000,
        )
        assert.equal(
            await docker(['inspect', '--format', '{{.HostConfig.NetworkMode}}', id]),
            'none',
        )
        assert.equal(await docker(['port', id]), '', 'Appliance published a port')
        await waitForSmoke(
            async () => {
                await inAppliance(
                    id,
                    'curl',
                    '--fail',
                    '--silent',
                    '--max-time',
                    '2',
                    'http://127.0.0.1:3000/health/ready',
                )
                return true
            },
            {
                timeoutMs: 45_000,
                intervalMs: 500,
                timeoutError: () => new Error('The production appliance did not become ready'),
            },
        )
        return await exercise(id)
    } catch (error) {
        console.error(await docker(['logs', '--tail', '24', id]).catch(() => 'No appliance log'))
        throw error
    } finally {
        await removeContainer(id)
    }
}

async function probeAppliance(container: string, arch: Architecture) {
    const [kernelMachine, kernel, packageArchitecture, libc, libraries, cpuInfo] =
        await Promise.all([
            inAppliance(container, 'uname', '-m'),
            inAppliance(container, 'uname', '-r'),
            inAppliance(container, 'dpkg', '--print-architecture'),
            inAppliance(container, 'getconf', 'GNU_LIBC_VERSION'),
            inAppliance(container, 'ldd', installed + '/' + appEntrypoint),
            inAppliance(container, 'cat', '/proc/cpuinfo'),
        ])
    assert.equal(kernelMachine, arch === 'amd64' ? 'x86_64' : 'aarch64')
    assert.equal(packageArchitecture, arch)
    assert.equal(libc, 'glibc ' + applianceGlibc)
    assert.ok(libraries.includes('libc.so.6') && !libraries.includes('not found'))
    const observedCpuFeatures = /^(?:flags|Features)[\t ]*:[\t ]*(.+)$/mu
        .exec(cpuInfo)?.[1]
        ?.trim()
        .split(/\s+/u)
    assert.ok(observedCpuFeatures?.includes(arch === 'amd64' ? 'sse4_2' : 'asimd'))
    return {
        kernelMachine,
        kernel,
        packageArchitecture,
        libc,
        observedCpuFeatures,
        libraries: libraries.split('\n').map((line) => line.trim()),
    }
}

async function exerciseBrowser(
    container: string,
    work: string,
    ready: () => Promise<{ status: number; body: unknown }>,
) {
    const assets = join(work, 'installed-ui')
    await docker(['cp', container + ':' + installed + '/ui', assets])
    const gateway = Bun.serve({
        hostname: '127.0.0.1',
        port: 0,
        async fetch(request) {
            if (request.method !== 'GET' || new URL(request.url).pathname !== '/health')
                return new Response(null, { status: 404 })
            const response = await ready()
            return Response.json(response.body, { status: response.status })
        },
    })
    try {
        const evidence = join(work, 'browser.json')
        await command(
            process.execPath,
            [
                '--no-env-file',
                join(uiSource, 'browser.mts'),
                assets,
                evidence,
                String(gateway.port),
            ],
            90_000,
        )
        const report = (await Bun.file(evidence).json()) as { checks: string[] }
        assert.ok(report.checks.includes('unix-health-through-bridge'))
    } finally {
        await gateway.stop(true)
    }
}

async function run(arch: Architecture, output: string) {
    const daemon = await docker(['version', '--format', '{{.Server.Os}}/{{.Server.Arch}}'])
    assert.equal(daemon, 'linux/' + arch, 'Expected a native Linux Docker daemon')
    assert.equal(process.arch, arch === 'amd64' ? 'x64' : 'arm64')
    const revision = await command('git', ['rev-parse', 'HEAD'])
    const hostKernel = process.platform === 'linux' ? await command('uname', ['-r']) : undefined
    await mkdir(output, { recursive: true })
    const reports = ['native.json', 'browser.json']
    await Promise.all(reports.map((name) => rm(join(output, name), { force: true })))
    const work = await mkdtemp(join(output, 'run-'))
    assert.equal(dirname(work), output)
    const volume = 'app-runtime-reference-' + randomUUID()
    try {
        console.log('Building the independent app backend and browser assets')
        const ui = join(work, 'ui')
        const [backendBuild, uiBuild] = await Promise.allSettled([
            buildRuntime(work, arch),
            command(process.execPath, ['--no-env-file', join(uiSource, 'build.ts'), ui]),
        ])
        if (backendBuild.status === 'rejected') throw backendBuild.reason
        if (uiBuild.status === 'rejected') throw uiBuild.reason
        const { backend, broker, toolchain } = backendBuild.value
        const { bootstrap, trustRoot } = await makeBootstrap(work, arch, backend, ui, revision)
        await docker(['volume', 'create', volume])

        console.log('Installing from the local signed catalog in a network-disabled appliance')
        const copyVerifier = async (id: string) => {
            await Promise.all([
                docker(['cp', join(import.meta.dir, 'catalog.ts'), id + ':' + installer]),
                docker(['cp', trustRoot, id + ':' + rootPath]),
            ])
        }
        const checks = await withAppliance(arch, volume, false, async (id) => {
            await Promise.all([
                copyVerifier(id),
                docker(['cp', bootstrap, id + ':' + bootstrapPath]),
            ])
            const catalog = await inAppliance(
                id,
                'bun',
                '--no-env-file',
                installer,
                'install',
                arch,
                installed,
                rootPath,
                bootstrapPath,
            )
            const sockets = await exerciseSockets(
                docker,
                id,
                work,
                broker,
                installed + '/' + appEntrypoint,
                1,
                bunVersion,
            )
            return { catalog, socket: sockets.evidence }
        })
        console.log('Restarting from the verified installation with the catalog and package absent')
        const offline = await withAppliance(arch, volume, true, async (id) => {
            await inAppliance(id, 'test', '!', '-e', bootstrapPath)
            await copyVerifier(id)
            const catalog = await inAppliance(
                id,
                'bun',
                '--no-env-file',
                installer,
                'verify',
                arch,
                installed,
                rootPath,
            )
            assert.equal(catalog, checks.catalog, 'Offline verification changed the installation')
            const native = await probeAppliance(id, arch)
            const sockets = await exerciseSockets(
                docker,
                id,
                work,
                broker,
                installed + '/' + appEntrypoint,
                2,
                bunVersion,
            )
            await exerciseBrowser(id, work, sockets.ready)
            const revocation = await sockets.verifyRevocation()
            assert.equal((await sockets.ready()).status, 503, 'A retired app reported healthy')
            return { native, socket: sockets.evidence, revocation }
        })
        if (hostKernel) assert.equal(offline.native.kernel, hostKernel)
        const evidence = {
            revision,
            appliance,
            daemon,
            hostKernel,
            runtimeProfile,
            toolchain,
            ...offline.native,
            bootstrap: {
                verification: JSON.parse(checks.catalog) as unknown,
                rejections: [
                    'invalid-signature',
                    'wrong-target',
                    'wrong-profile',
                    'archive-digest',
                ],
                socket: checks.socket,
            },
            offline: {
                socket: offline.socket,
                revocation: offline.revocation,
                catalogAbsent: true,
                installedReadOnly: true,
            },
        }
        await writeFile(join(work, 'native.json'), JSON.stringify(evidence, null, 2) + '\n')
        await Promise.all(reports.map((name) => rename(join(work, name), join(output, name))))
        console.log(JSON.stringify(evidence, null, 2))
    } finally {
        try {
            await docker(['volume', 'rm', volume]).catch((error: unknown) => {
                if (!String(error).includes('no such volume')) throw error
            })
        } finally {
            await rm(work, { recursive: true, force: true })
        }
    }
}

const output = process.argv[3]
assert.ok(output, 'Expected an evidence output directory')
await run(architecture(process.argv[2]), resolve(output))
