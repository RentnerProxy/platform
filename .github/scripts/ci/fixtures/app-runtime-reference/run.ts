import assert from 'node:assert/strict'
import { execFile } from 'node:child_process'
import { randomUUID } from 'node:crypto'
import { cp, mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises'
import { dirname, join, resolve } from 'node:path'
import { promisify } from 'node:util'
import { waitForSmoke } from '../../../../../scripts/smoke/wait.ts'
import { appEntrypoint, architecture, makeBootstrap, runtimeProfile } from './catalog.ts'
import type { Architecture } from './catalog.ts'
import { exerciseProviders } from './providers.ts'

const appliance =
    'ghcr.io/rentnerproxy/platform@sha256:6a9ecb2330c20f366590f4c6c1c32441104a44c8435d7858cbef4d9496e07b46'
const builder =
    'mirror.gcr.io/library/rust:1.100-trixie@sha256:e19840879045c951c905d0eaa9887f3439c62000e429963371b376bac8d38c31'
const backendSource = 'core/tests/fixtures/app-runtime-reference'
const uiSource = 'web/src/tests/fixtures/app-runtime-reference'
const installed = '/reference-install'
const bootstrapPath = '/tmp/reference-bootstrap'
const rootPath = '/tmp/reference-root.pem'
const installer = '/tmp/reference-catalog.ts'
const socketDirectory = '/tmp/reference-app'
const socket = socketDirectory + '/app.sock'
const appUid = '21001'
const brokerUid = '21002'
const installation = 'reference-install'
const cpu = 'generic'
const minimumGlibc = '2.41'

const execute = promisify(execFile)

async function command(file: string, args: string[], timeout = 20_000) {
    const { stdout } = await execute(file, args, { timeout, windowsHide: true })
    return stdout.trim()
}

const docker = (args: string[], timeout?: number) => command('docker', args, timeout)
const inAppliance = (container: string, ...args: string[]) => docker(['exec', container, ...args])

async function buildBackend(work: string, arch: Architecture) {
    const source = join(work, 'backend-source')
    await mkdir(source)
    await Promise.all(
        ['Cargo.toml', 'Cargo.lock', 'src'].map((path) =>
            cp(join(backendSource, path), join(source, path), { recursive: true }),
        ),
    )
    const executable = 'target/release/app-runtime-reference'
    const id = await docker(
        [
            'create',
            '--platform',
            'linux/' + arch,
            '--env',
            'RUSTFLAGS=-C target-cpu=' + cpu,
            builder,
            'sh',
            '-ceu',
            [
                'cd /reference',
                'cargo build --release --locked',
                'rustc -vV',
                'rustc --print cfg -C target-cpu=' + cpu,
                'readelf --wide --version-info ' + executable,
                'readelf --notes ' + executable,
            ].join('\n'),
        ],
        180_000,
    )
    try {
        await docker(['cp', source, id + ':/reference'])
        const build = await docker(['start', '--attach', id], 240_000)
        const target = arch === 'amd64' ? 'x86_64-unknown-linux-gnu' : 'aarch64-unknown-linux-gnu'
        assert.ok(build.split('\n').includes('host: ' + target), 'Rust builder is not native')
        const requiredGlibc = [...new Set(build.match(/(?<=\bGLIBC_)\d+(?:\.\d+)+/gu))].toSorted(
            (left, right) => left.localeCompare(right, 'en', { numeric: true }),
        )
        const newestGlibc = requiredGlibc.at(-1)
        assert.ok(
            newestGlibc && newestGlibc.localeCompare(minimumGlibc, 'en', { numeric: true }) <= 0,
            'Fixture exceeds the Debian 13 glibc baseline',
        )
        const backend = join(work, 'app')
        await docker(['cp', id + ':/reference/' + executable, backend])
        return {
            backend,
            toolchain: {
                image: builder,
                rustc: build.split('\n').find((line) => line.startsWith('rustc ')),
                target,
                cpu,
                features: build.split('\n').filter((line) => line.startsWith('target_feature=')),
                elfAbi: build
                    .split('\n')
                    .find((line) => line.includes('OS: Linux, ABI:'))
                    ?.trim(),
                requiredGlibc,
            },
        }
    } finally {
        await docker(['rm', '--force', id])
    }
}

async function withAppliance<T>(
    arch: Architecture,
    volume: string,
    offline: boolean,
    exercise: (container: string) => Promise<T>,
) {
    const id = await docker(
        [
            'run',
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
    try {
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
        await docker(['rm', '--force', '--volumes', id])
    }
}

async function rpc(
    container: string,
    generation: number,
    request?: Record<string, unknown>,
    uid = brokerUid,
    installId = installation,
) {
    const curl = [
        'curl',
        '--silent',
        '--show-error',
        '--noproxy',
        '*',
        '--max-time',
        '3',
        '--unix-socket',
        socket,
        '--header',
        'x-app-installation: ' + installId,
        '--header',
        'x-app-generation: ' + generation,
        '--write-out',
        '\n%{http_code}',
    ]
    if (request) curl.push('--json', JSON.stringify(request))
    const response = await docker(
        [
            'exec',
            '--user',
            uid + ':' + brokerUid,
            container,
            ...curl,
            'http://localhost/v1/' + (request ? 'probe' : 'ready'),
        ],
        5_000,
    )
    const separator = response.lastIndexOf('\n')
    assert.ok(separator > 0, 'Socket response is missing its body or status')
    const status = Number(response.slice(separator + 1))
    assert.ok(Number.isInteger(status) && status >= 100 && status <= 599)
    const text = response.slice(0, separator)
    const body: unknown = text.startsWith('{') ? JSON.parse(text) : text
    return { status, body }
}

async function exerciseSocket(container: string, generation: number) {
    await inAppliance(
        container,
        'install',
        '-d',
        '-m',
        '0710',
        '-o',
        appUid,
        '-g',
        brokerUid,
        socketDirectory,
    )
    await docker([
        'exec',
        '--detach',
        '--user',
        appUid + ':' + brokerUid,
        container,
        'sh',
        '-c',
        'exec "$@" 2>/tmp/reference-app/startup-error',
        'reference-backend',
        installed + '/' + appEntrypoint,
        socket,
        installation,
        String(generation),
        brokerUid,
    ])
    let readinessError: unknown
    try {
        await waitForSmoke(async () => (await rpc(container, generation)).status === 200, {
            timeoutMs: 10_000,
            intervalMs: 200,
            retryOnError(error) {
                readinessError = error
                return true
            },
            timeoutError: () =>
                new Error('Reference backend socket did not become ready', {
                    cause: readinessError,
                }),
        })
    } catch (error) {
        console.error(await inAppliance(container, 'cat', socketDirectory + '/startup-error'))
        throw error
    }
    const expected = { status: 403, body: { error: 'installationContextRejected' } }
    const [spoof, foreign, stale, mode] = await Promise.all([
        rpc(container, generation, undefined, '21003'),
        rpc(container, generation, undefined, brokerUid, 'another-installation'),
        rpc(container, generation - 1),
        inAppliance(container, 'stat', '-c', '%u:%g:%a', socket),
    ])
    assert.deepEqual(spoof, expected, 'Wrong peer UID reached the app')
    assert.deepEqual(foreign, expected, 'Wrong installation reached the app')
    assert.deepEqual(stale, expected, 'Stale generation reached the app')
    assert.equal(mode, appUid + ':' + brokerUid + ':660')
    return {
        providers: await exerciseProviders((request) => rpc(container, generation, request)),
        socket: {
            generation,
            wrongPeer: spoof.status,
            wrongInstall: foreign.status,
            stale: stale.status,
        },
    }
}

async function probeAppliance(container: string, arch: Architecture) {
    const [kernelMachine, kernel, packageArchitecture, libc, libraries] = await Promise.all([
        inAppliance(container, 'uname', '-m'),
        inAppliance(container, 'uname', '-r'),
        inAppliance(container, 'dpkg', '--print-architecture'),
        inAppliance(container, 'getconf', 'GNU_LIBC_VERSION'),
        inAppliance(container, 'ldd', installed + '/' + appEntrypoint),
    ])
    assert.equal(kernelMachine, arch === 'amd64' ? 'x86_64' : 'aarch64')
    assert.equal(packageArchitecture, arch)
    assert.equal(libc, 'glibc ' + minimumGlibc)
    assert.ok(libraries.includes('libc.so.6') && !libraries.includes('not found'))
    return {
        kernelMachine,
        kernel,
        packageArchitecture,
        libc,
        libraries: libraries.split('\n').map((line) => line.trim()),
    }
}

async function exerciseBrowser(container: string, work: string, output: string) {
    const assets = join(work, 'installed-ui')
    await docker(['cp', container + ':' + installed + '/ui', assets])
    const gateway = Bun.serve({
        hostname: '127.0.0.1',
        port: 0,
        async fetch(request) {
            if (request.method !== 'GET' || new URL(request.url).pathname !== '/health')
                return new Response(null, { status: 404 })
            const response = await rpc(container, 2)
            return Response.json(response.body, { status: response.status })
        },
    })
    try {
        const evidence = join(output, 'browser.json')
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
    const work = await mkdtemp(join(output, 'run-'))
    assert.equal(dirname(work), output)
    const volume = 'app-runtime-reference-' + randomUUID()
    try {
        console.log('Building the independent app backend and browser assets')
        const ui = join(work, 'ui')
        const [backendBuild, uiBuild] = await Promise.allSettled([
            buildBackend(work, arch),
            command(process.execPath, ['--no-env-file', join(uiSource, 'build.ts'), ui]),
        ])
        if (backendBuild.status === 'rejected') throw backendBuild.reason
        if (uiBuild.status === 'rejected') throw uiBuild.reason
        const { backend, toolchain } = backendBuild.value
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
            return { catalog, socket: await exerciseSocket(id, 1) }
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
            const socketCheck = await exerciseSocket(id, 2)
            await exerciseBrowser(id, work, output)
            return { native, socket: socketCheck }
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
            offline: { socket: offline.socket, catalogAbsent: true, installedReadOnly: true },
        }
        await writeFile(join(output, 'native.json'), JSON.stringify(evidence, null, 2) + '\n')
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
