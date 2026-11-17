import assert from 'node:assert/strict'
import { createHash, generateKeyPairSync, sign, verify } from 'node:crypto'
import { chmod, cp, mkdir, readFile, writeFile } from 'node:fs/promises'
import { join } from 'node:path'

export const runtimeProfile = 'rentnerproxy-linux-v1'
export const appEntrypoint = 'bin/app'
const appId = 'fixture.runtime-reference'
const version = '0.1.0-alpha.1'
const api = 'api/openapi.json'
const uiEntrypoint = 'ui/index.html'
const files = [
    appEntrypoint,
    'app.json',
    api,
    uiEntrypoint,
    'ui/app.js',
    'ui/app.css',
    'ui/icon.svg',
]
const catalogFile = 'catalog.json'
const signatureFile = 'catalog.sig'

export type Architecture = 'amd64' | 'arm64'

interface Catalog {
    target: string
    runtimeProfile: string
    archiveSha256: string
    files: Record<string, string>
}

export function architecture(value: string | undefined): Architecture {
    assert.ok(value === 'amd64' || value === 'arm64', 'Expected amd64 or arm64')
    return value
}

function archiveName(arch: Architecture) {
    return [appId, version, 'linux', arch].join('-') + '.tar.zst'
}

function sha256(bytes: Uint8Array) {
    return createHash('sha256').update(bytes).digest('hex')
}

function elfMachine(backend: Buffer, arch: Architecture) {
    assert.equal(backend.subarray(0, 6).toString('hex'), '7f454c460201', 'Expected ELF64 LE')
    const machine = backend.readUInt16LE(18)
    assert.equal(machine, arch === 'amd64' ? 62 : 183, 'ELF machine does not match target')
    return machine
}

async function inventory(directory: string) {
    return Object.fromEntries(
        await Promise.all(
            files.map(async (file) => [file, sha256(await readFile(join(directory, file)))]),
        ),
    )
}

function tar(args: string[]) {
    const result = Bun.spawnSync(['tar', ...args], {
        stdout: 'pipe',
        stderr: 'pipe',
        timeout: 15_000,
    })
    assert.equal(result.exitCode, 0, result.stderr.toString())
    return result.stdout
}

/** Prepare transient signed fixture data and keep the trust root outside the catalog. */
export async function makeBootstrap(
    work: string,
    arch: Architecture,
    backend: string,
    ui: string,
    revision: string,
) {
    const payload = join(work, 'payload')
    const bootstrap = join(work, 'bootstrap')
    const trustRoot = join(work, 'fixture-root.pem')
    await Promise.all(
        [join(payload, 'bin'), join(payload, 'api'), bootstrap].map((directory) =>
            mkdir(directory, { recursive: true }),
        ),
    )
    elfMachine(await readFile(backend), arch)
    await cp(ui, join(payload, 'ui'), { recursive: true })
    await cp(backend, join(payload, appEntrypoint))
    await chmod(join(payload, appEntrypoint), 0o755)
    const protocolRange = '>=1.0.0 <2.0.0'
    await writeFile(
        join(payload, 'app.json'),
        JSON.stringify({
            formatVersion: 1,
            id: appId,
            version,
            target: 'linux-' + arch,
            source: { repositoryId: '1347548091', commit: revision },
            display: {
                name: 'Internal runtime reference',
                summary: 'Exercise local app runtime boundaries.',
                license: 'MIT',
            },
            requires: {
                runtimeProfile,
                platformApi: protocolRange,
                appProtocol: protocolRange,
                uiBridge: protocolRange,
                engineCapabilities: [],
            },
            entrypoint: appEntrypoint,
            api,
            ui: { entrypoint: uiEntrypoint, slots: ['navigation'] },
            providers: [],
            capabilities: [],
            permissions: [],
            resources: {
                startupTimeoutMs: 10_000,
                drainTimeoutMs: 2_000,
                memoryMiB: 128,
                processLimit: 4,
            },
        }),
    )
    await writeFile(
        join(payload, api),
        JSON.stringify({
            openapi: '3.1.0',
            info: { title: 'Internal socket fixture', version },
            paths: {
                '/v1/ready': { get: { responses: { '200': { description: 'Socket ready' } } } },
                '/v1/probe': { post: { responses: { '200': { description: 'Fixture reply' } } } },
            },
        }),
    )
    const archive = Bun.zstdCompressSync(tar(['-cf', '-', '-C', payload, ...files]))
    const catalog: Catalog = {
        target: 'linux-' + arch,
        runtimeProfile,
        archiveSha256: sha256(archive),
        files: await inventory(payload),
    }
    const { privateKey, publicKey } = generateKeyPairSync('ed25519')
    const variants = {
        catalog,
        'wrong-target': { ...catalog, target: arch === 'amd64' ? 'linux-arm64' : 'linux-amd64' },
        'wrong-profile': { ...catalog, runtimeProfile: 'unknown-profile' },
    }
    await Promise.all([
        writeFile(trustRoot, publicKey.export({ type: 'spki', format: 'pem' })),
        writeFile(join(bootstrap, archiveName(arch)), archive),
        ...Object.entries(variants).flatMap(([name, entry]) => {
            const bytes = Buffer.from(JSON.stringify(entry))
            return [
                writeFile(join(bootstrap, name + '.json'), bytes),
                writeFile(join(bootstrap, name + '.sig'), sign(null, bytes, privateKey)),
            ]
        }),
    ])
    return { bootstrap, trustRoot }
}

function verifyCatalog(
    bytes: Buffer,
    signature: Buffer,
    trustRoot: Buffer,
    arch: Architecture,
): Catalog {
    assert.ok(verify(null, bytes, trustRoot, signature), 'Invalid fixture catalog signature')
    const catalog = JSON.parse(bytes.toString()) as Catalog
    assert.equal(catalog.target, 'linux-' + arch, 'Incompatible target')
    assert.equal(catalog.runtimeProfile, runtimeProfile, 'Incompatible runtime profile')
    return catalog
}

async function loadCatalog(directory: string, name = 'catalog') {
    return Promise.all([
        readFile(join(directory, name + '.json')),
        readFile(join(directory, name + '.sig')),
    ])
}

function assertArchive(archive: Buffer, catalog: Catalog) {
    assert.equal(sha256(archive), catalog.archiveSha256, 'Unexpected archive digest')
}

async function verifyInstalled(directory: string, trustRoot: Buffer, arch: Architecture) {
    const [bytes, signature] = await loadCatalog(directory)
    const catalog = verifyCatalog(bytes, signature, trustRoot, arch)
    assert.deepEqual(await inventory(directory), catalog.files, 'Installed bytes changed')
    const manifest = JSON.parse(await readFile(join(directory, 'app.json'), 'utf8')) as {
        target: string
        requires: { runtimeProfile: string }
    }
    assert.equal(manifest.target, catalog.target)
    assert.equal(manifest.requires.runtimeProfile, catalog.runtimeProfile)
    const machine = elfMachine(await readFile(join(directory, appEntrypoint)), arch)
    return { archiveSha256: catalog.archiveSha256, files: catalog.files, elfMachine: machine }
}

async function install(
    bootstrap: string,
    directory: string,
    trustRoot: Buffer,
    arch: Architecture,
) {
    const [bytes, signature] = await loadCatalog(bootstrap)
    const catalog = verifyCatalog(bytes, signature, trustRoot, arch)
    assert.throws(
        () => verifyCatalog(Buffer.concat([bytes, Buffer.from(' ')]), signature, trustRoot, arch),
        /Invalid fixture catalog signature/u,
    )
    const [wrongTarget, wrongProfile] = await Promise.all([
        loadCatalog(bootstrap, 'wrong-target'),
        loadCatalog(bootstrap, 'wrong-profile'),
    ])
    assert.throws(() => verifyCatalog(...wrongTarget, trustRoot, arch), /Incompatible target/u)
    assert.throws(
        () => verifyCatalog(...wrongProfile, trustRoot, arch),
        /Incompatible runtime profile/u,
    )
    const archive = await readFile(join(bootstrap, archiveName(arch)))
    assertArchive(archive, catalog)
    assert.throws(() => assertArchive(archive.subarray(1), catalog), /Unexpected archive digest/u)

    // Only the exact archive produced by this fixture reaches the extraction step.
    const uncompressed = join(bootstrap, 'verified.tar')
    await writeFile(uncompressed, Bun.zstdDecompressSync(archive))
    tar([
        '-xf',
        uncompressed,
        '-C',
        directory,
        '--no-same-owner',
        '--no-same-permissions',
        ...files,
    ])
    await Promise.all([
        ...files.map((file) =>
            chmod(join(directory, file), file === appEntrypoint ? 0o555 : 0o444),
        ),
        writeFile(join(directory, catalogFile), bytes),
        writeFile(join(directory, signatureFile), signature),
    ])
    return verifyInstalled(directory, trustRoot, arch)
}

if (import.meta.main) {
    const [, , mode, target, directory, trustRootPath, bootstrap] = process.argv
    assert.ok(directory && trustRootPath)
    const arch = architecture(target)
    const root = await readFile(trustRootPath)
    if (mode === 'install') {
        assert.ok(bootstrap)
        console.log(JSON.stringify(await install(bootstrap, directory, root, arch)))
    } else {
        assert.equal(mode, 'verify')
        console.log(JSON.stringify(await verifyInstalled(directory, root, arch)))
    }
}
