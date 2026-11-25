// oxlint-disable no-await-in-loop -- Exercise each independent corruption and filesystem failure.
import assert from 'node:assert/strict'
import { createCipheriv, createHash, hkdfSync } from 'node:crypto'
import * as filesystem from 'node:fs/promises'
import {
    link,
    mkdir,
    mkdtemp,
    open,
    readFile,
    readdir,
    rm,
    stat,
    symlink,
    writeFile,
    type FileHandle,
} from 'node:fs/promises'
import { join, resolve } from 'node:path'
import { pathToFileURL } from 'node:url'
import { spyOn, test } from 'bun:test'
import { copyCoverageFixtureModules } from '@/tests/Helpers/coverageFixture.ts'
import {
    createRecoveryKey,
    decryptBackup,
    encryptBackup,
    recoveryKeyId,
} from '../../../../../../../scripts/backup/offhost/envelope.ts'
import {
    publishProductionBackup,
    verifyPublishedBackup,
} from '../../../../../../../scripts/backup/publication.ts'
import { parseBackupMetadata } from '../../../../../../../scripts/backup/format.ts'
import { maximumBackupMetadataBytes } from '../../../../../../../scripts/backup/validation.ts'

const root = resolve(import.meta.dir, '../../../../../../..')
const names = [
    'metadata.json',
    'app-encryption-key',
    'postgres.dump',
    'controller-state.tar',
    'crowdsec-state.tar',
]
const digest = (bytes: Uint8Array | string) => createHash('sha256').update(bytes).digest('hex')
const applicationKey = Buffer.alloc(32, 11).toString('base64')
const maximumKeyBytes = 64 * 1024
const testController = '/usr/local/libexec/rentnerproxy-test-controller'

function directoryArchive(name = './') {
    const header = Buffer.alloc(512)
    header.write(name)
    header.write('0000700\0', 100)
    header.write('00000000000\0', 124)
    header.fill(32, 148, 156)
    header[156] = 53
    header.write(
        header
            .reduce((sum, byte) => sum + byte, 0)
            .toString(8)
            .padStart(6, '0') + '\0 ',
        148,
    )
    return Buffer.concat([header, Buffer.alloc(1024)])
}

async function fixture(
    run: (directory: string, source: string) => Promise<void>,
    dumpBytes = 200_000,
) {
    await mkdir(join(root, 'tmp'), { recursive: true })
    const directory = await mkdtemp(join(root, 'tmp', 'offhost-envelope-'))
    try {
        const staging = join(directory, 'staging')
        const source = join(directory, 'source')
        await mkdir(staging)
        const key = Buffer.from(applicationKey + '\n')
        const dump = Buffer.alloc(dumpBytes, 37)
        const archive = directoryArchive()
        await Promise.all([
            writeFile(join(staging, 'app-encryption-key'), key),
            writeFile(join(staging, 'postgres.dump'), dump),
            writeFile(join(staging, 'controller-state.tar'), archive),
            writeFile(join(staging, 'crowdsec-state.tar'), archive),
        ])
        await publishProductionBackup(
            staging,
            source,
            parseBackupMetadata({
                format: 'rentnerproxy-production-backup',
                version: 4,
                createdAt: '2026-10-31T00:00:00.000Z',
                redis: 'excluded',
                applicationEncryptionKey: {
                    file: 'app-encryption-key',
                    bytes: key.length,
                    sha256: digest(key),
                },
                postgres: {
                    database: 'rentnerproxy',
                    user: 'rentnerproxy',
                    dump: 'postgres.dump',
                    bytes: dump.length,
                    sha256: digest(dump),
                },
                controllerState: {
                    archive: 'controller-state.tar',
                    bytes: archive.length,
                    sha256: digest(archive),
                },
                crowdSecState: {
                    archive: 'crowdsec-state.tar',
                    bytes: archive.length,
                    sha256: digest(archive),
                },
                deployment: {
                    publicOrigin: 'https://proxy.example.test',
                    trustedProxyCidrs: '127.0.0.1/32',
                },
                source: {
                    imageId: null,
                    revision: 'a'.repeat(40),
                    version: '0.0.0-test',
                    buildSha256: 'b'.repeat(64),
                },
            }),
        )
        await run(directory, source)
    } finally {
        await rm(directory, { recursive: true, force: true })
    }
}

/**
 * Seal `bodies` in the given format independently of the module under test: v1 as one
 * AES-256-GCM stream, v2 as HKDF-keyed 64 KiB chunks with counter and final-chunk nonces.
 * `unterminated` seals the last v2 chunk as if more chunks followed.
 */
function sealEnvelope(
    format: 1 | 2,
    recoveryKey: string,
    template: Buffer,
    bodies: Buffer[],
    unterminated = false,
) {
    const key = Buffer.from(recoveryKey, 'base64')
    const header = Buffer.from(template.subarray(0, 96))
    header[8] = format
    bodies.forEach((body, index) => header.writeBigUInt64BE(BigInt(body.length), 56 + index * 8))
    const payload = Buffer.concat(bodies)
    if (format === 1) {
        const cipher = createCipheriv('aes-256-gcm', key, header.subarray(12, 24), {
            authTagLength: 16,
        })
        cipher.setAAD(header)
        return Buffer.concat([header, cipher.update(payload), cipher.final(), cipher.getAuthTag()])
    }
    const subkey = Buffer.from(
        hkdfSync('sha256', key, header.subarray(12, 24), 'RPBAKENC/2 AES-256-GCM payload key', 32),
    )
    const parts = [header]
    const count = Math.ceil(payload.length / 65_536)
    for (let index = 0; index < count; index++) {
        const nonce = Buffer.alloc(12)
        nonce.writeBigUInt64BE(BigInt(index), 3)
        nonce[11] = index + 1 === count && !unterminated ? 1 : 0
        const cipher = createCipheriv('aes-256-gcm', subkey, nonce, { authTagLength: 16 })
        cipher.setAAD(header)
        parts.push(
            cipher.update(payload.subarray(index * 65_536, (index + 1) * 65_536)),
            cipher.final(),
            cipher.getAuthTag(),
        )
    }
    return Buffer.concat(parts)
}

async function assertNoStaging(directory: string) {
    assert.deepEqual(
        (await readdir(directory)).filter((name) => name.startsWith('.rentnerproxy-')),
        [],
    )
}

test('recovery keys are independent canonical 32-byte keys and have stable SHA256 identities', () => {
    const key = createRecoveryKey()
    assert.equal(Buffer.from(key, 'base64').length, 32)
    assert.equal(Buffer.from(key, 'base64').toString('base64'), key)
    assert.equal(recoveryKeyId(key), digest(Buffer.from(key, 'base64')))
    assert.notEqual(createRecoveryKey(), key)
    for (const invalid of [
        '',
        key + '\n',
        key.replace(/=$/u, ''),
        'A'.repeat(42) + 'B=',
        applicationKey.replace('+', '-') + ' ',
    ])
        assert.throws(() => recoveryKeyId(invalid), /canonical base64/)
})

test('encrypts and restores all five complete v4 artifacts into a fresh private destination', () =>
    fixture(async (directory, source) => {
        const key = createRecoveryKey()
        const encrypted = join(directory, 'backup.encrypted')
        const second = join(directory, 'second.encrypted')
        const destination = join(directory, 'restored')
        const result = await encryptBackup(source, encrypted, key)
        const ciphertext = await readFile(encrypted)
        assert.equal(result.bytes, ciphertext.length)
        assert.equal(result.sha256, digest(ciphertext))
        assert.equal(result.keyId, recoveryKeyId(key))
        assert.equal(ciphertext.includes(Buffer.from(applicationKey)), false)
        assert.equal(ciphertext.includes(Buffer.from('rentnerproxy-production-backup')), false)
        await encryptBackup(source, second, key)
        assert.notDeepEqual((await readFile(second)).subarray(12, 24), ciphertext.subarray(12, 24))
        await decryptBackup(encrypted, destination, key)
        assert.deepEqual((await readdir(destination)).toSorted(), names.toSorted())
        for (const name of names) {
            assert.deepEqual(
                await readFile(join(destination, name)),
                await readFile(join(source, name)),
            )
            if (process.platform !== 'win32')
                assert.equal((await stat(join(destination, name))).mode & 0o777, 0o600)
        }
        assert.equal((await verifyPublishedBackup(destination)).metadata.version, 4)
        if (process.platform !== 'win32')
            assert.equal((await stat(destination)).mode & 0o777, 0o700)
        assert.deepEqual(await readFile(encrypted), ciphertext)
        await assertNoStaging(directory)
    }))

test('new backups are chunked v2 envelopes, and v1 envelopes of earlier releases still restore', () =>
    fixture(async (directory, source) => {
        const key = createRecoveryKey()
        const encrypted = join(directory, 'backup.encrypted')
        await encryptBackup(source, encrypted, key)
        const ciphertext = await readFile(encrypted)
        const bodies = await Promise.all(names.map((name) => readFile(join(source, name))))
        const payload = bodies.reduce((sum, body) => sum + body.length, 0)
        assert.equal(ciphertext[8], 2)
        assert.equal(ciphertext.length, 96 + payload + 16 * Math.ceil(payload / 65_536))
        // The module matches the independent reference of the format byte for byte.
        assert.deepEqual(sealEnvelope(2, key, ciphertext, bodies), ciphertext)

        const legacy = join(directory, 'legacy.encrypted')
        const restored = join(directory, 'legacy-restored')
        await writeFile(legacy, sealEnvelope(1, key, ciphertext, bodies))
        await decryptBackup(legacy, restored, key)
        for (const [index, name] of names.entries())
            assert.deepEqual(await readFile(join(restored, name)), bodies[index])
        await assertNoStaging(directory)
    }))

test('tampering, truncation, appended bytes and a wrong key expose no plaintext and preserve the encrypted input', () =>
    fixture(async (directory, source) => {
        const key = createRecoveryKey()
        const encrypted = join(directory, 'backup.encrypted')
        await encryptBackup(source, encrypted, key)
        const original = await readFile(encrypted)
        const altered = (offset: number) => {
            const copy = Buffer.from(original)
            copy[offset] = copy[offset]! ^ 1
            return copy
        }
        // Two full sealed chunks of 64 KiB plus their tags, exchanged.
        const sealedChunk = 65_536 + 16
        const swapped = Buffer.concat([
            original.subarray(0, 96),
            original.subarray(96 + sealedChunk, 96 + 2 * sealedChunk),
            original.subarray(96, 96 + sealedChunk),
            original.subarray(96 + 2 * sealedChunk),
        ])
        const bodies = await Promise.all(names.map((name) => readFile(join(source, name))))
        const payload = bodies.reduce((sum, body) => sum + body.length, 0)
        // A v2 envelope relabelled as v1 and cut to the v1 size, and a final chunk that
        // claims more chunks follow.
        const downgraded = Buffer.from(original.subarray(0, 96 + payload + 16))
        downgraded[8] = 1
        const candidates = [
            downgraded,
            sealEnvelope(2, key, original, bodies, true),
            altered(12),
            altered(24),
            altered(96),
            altered(96 + sealedChunk + 7),
            altered(original.length - 1),
            swapped,
            original.subarray(0, 70),
            original.subarray(0, -1),
            Buffer.concat([original, Buffer.from([0])]),
        ]
        for (const [index, bytes] of candidates.entries()) {
            const corrupt = join(directory, 'corrupt-' + index)
            const destination = join(directory, 'restored-' + index)
            await writeFile(corrupt, bytes)
            await assert.rejects(decryptBackup(corrupt, destination, key))
            await assert.rejects(stat(destination), /ENOENT/)
            assert.deepEqual(await readFile(corrupt), bytes)
            await assertNoStaging(directory)
        }
        await assert.rejects(
            decryptBackup(encrypted, join(directory, 'wrong-key'), createRecoveryKey()),
            /key does not match/,
        )
        assert.deepEqual(await readFile(encrypted), original)
    }))

test.skipIf(process.platform !== 'linux' || !(await Bun.file(testController).exists()))(
    'native and fallback implementations exchange verified envelopes and reject altered ciphertext',
    () =>
        fixture(async (directory, source) => {
            const code = join(directory, 'code')
            const moduleName = 'scripts/backup/offhost/envelope.ts'
            await copyCoverageFixtureModules(code, [moduleName], {
                '/usr/local/bin/rentnerproxy-controller': testController,
            })
            const nativeEnvelope = (await import(
                pathToFileURL(join(code, moduleName)).href
            )) as typeof import('../../../../../../../scripts/backup/offhost/envelope.ts')
            const key = createRecoveryKey()
            const nativeFile = join(directory, 'native.encrypted')
            const fallbackFile = join(directory, 'fallback.encrypted')
            const nativeRestore = join(directory, 'native-restore')
            const fallbackRestore = join(directory, 'fallback-restore')
            const receipt = await nativeEnvelope.encryptBackup(source, nativeFile, key)
            const encrypted = await readFile(nativeFile)
            assert.deepEqual(receipt, {
                bytes: encrypted.length,
                sha256: digest(encrypted),
                keyId: recoveryKeyId(key),
            })
            await decryptBackup(nativeFile, fallbackRestore, key)
            await encryptBackup(source, fallbackFile, key)
            await nativeEnvelope.decryptBackup(fallbackFile, nativeRestore, key)
            // The native controller still opens v1 envelopes of earlier releases.
            const bodies = await Promise.all(names.map((name) => readFile(join(source, name))))
            const legacyFile = join(directory, 'legacy.encrypted')
            const legacyRestore = join(directory, 'legacy-restore')
            await writeFile(legacyFile, sealEnvelope(1, key, encrypted, bodies))
            await nativeEnvelope.decryptBackup(legacyFile, legacyRestore, key)
            for (const destination of [fallbackRestore, nativeRestore, legacyRestore]) {
                await verifyPublishedBackup(destination)
                for (const name of names) {
                    assert.deepEqual(
                        await readFile(join(destination, name)),
                        await readFile(join(source, name)),
                    )
                }
            }

            encrypted[encrypted.length - 1] = encrypted[encrypted.length - 1]! ^ 1
            await writeFile(nativeFile, encrypted)
            const rejected = join(directory, 'rejected')
            await assert.rejects(
                nativeEnvelope.decryptBackup(nativeFile, rejected, key),
                /invalid or incomplete encrypted backup transfer/,
            )
            await assert.rejects(stat(rejected), /ENOENT/)
            await assertNoStaging(directory)
        }),
)

test('rejects unsupported headers and oversized or zero lengths before plaintext staging', () =>
    fixture(async (directory, source) => {
        const key = createRecoveryKey()
        const encrypted = join(directory, 'backup.encrypted')
        await encryptBackup(source, encrypted, key)
        const original = await readFile(encrypted)
        for (const [index, maximum] of [
            BigInt(maximumBackupMetadataBytes),
            BigInt(maximumKeyBytes),
            8n * 1024n ** 3n,
            8n * 1024n ** 3n,
            8n * 1024n ** 3n,
        ].entries()) {
            for (const size of [0n, maximum + 1n, 2n ** 64n - 1n]) {
                const bytes = Buffer.from(original)
                bytes.writeBigUInt64BE(size, 56 + index * 8)
                await writeFile(encrypted, bytes)
                await assert.rejects(
                    decryptBackup(encrypted, join(directory, 'restored'), key),
                    /size limit/,
                )
                await assertNoStaging(directory)
            }
        }
        for (const offset of [0, 8, 9, 10]) {
            const bytes = Buffer.from(original)
            bytes[offset] = bytes[offset]! ^ 1
            await writeFile(encrypted, bytes)
            await assert.rejects(
                decryptBackup(encrypted, join(directory, 'restored'), key),
                /unsupported/,
            )
        }
    }))

test('authenticated plaintext still must pass the complete backup metadata and artifact hash verification', () =>
    fixture(async (directory, source) => {
        const key = createRecoveryKey()
        const encrypted = join(directory, 'backup.encrypted')
        await encryptBackup(source, encrypted, key)
        const header = (await readFile(encrypted)).subarray(0, 96)
        const bodies = await Promise.all(names.map((name) => readFile(join(source, name))))
        bodies[2]![0] = bodies[2]![0]! ^ 1
        // Produce validly authenticated envelopes of both formats for inconsistent contents.
        for (const format of [1, 2] as const) {
            const bytes = sealEnvelope(format, key, header, bodies)
            await writeFile(encrypted, bytes)
            await assert.rejects(
                decryptBackup(encrypted, join(directory, 'restored'), key),
                /checksum mismatch/,
            )
            await assert.rejects(stat(join(directory, 'restored')), /ENOENT/)
            assert.deepEqual(await readFile(encrypted), bytes)
            await assertNoStaging(directory)
        }
    }))

test('rejects unexpected source entries, invalid artifacts and reuse of the application encryption key', () =>
    fixture(async (directory, source) => {
        const encrypted = join(directory, 'backup.encrypted')
        const key = createRecoveryKey()
        await assert.rejects(
            encryptBackup(source, join(source, 'encrypted'), key),
            /outside the complete source/,
        )
        assert.deepEqual((await readdir(source)).toSorted(), names.toSorted())
        await writeFile(join(source, 'unexpected'), 'not part of the backup')
        await assert.rejects(encryptBackup(source, encrypted, key), /exactly the five/)
        await rm(join(source, 'unexpected'))
        await assert.rejects(encryptBackup(source, encrypted, applicationKey), /must differ/)
        await writeFile(join(source, 'postgres.dump'), 'modified original')
        await assert.rejects(encryptBackup(source, encrypted, key))
        await assert.rejects(stat(encrypted), /ENOENT/)
        await assertNoStaging(directory)
    }))

test('authenticated archives with traversal paths are rejected before publishing', () =>
    fixture(async (directory, source) => {
        const key = createRecoveryKey()
        const encrypted = join(directory, 'backup.encrypted')
        await encryptBackup(source, encrypted, key)
        const header = Buffer.from((await readFile(encrypted)).subarray(0, 96))
        const bodies = await Promise.all(names.map((name) => readFile(join(source, name))))
        const archive = directoryArchive('../../escape')
        const metadata = (await verifyPublishedBackup(source)).metadata
        metadata.controllerState = {
            ...metadata.controllerState,
            bytes: archive.length,
            sha256: digest(archive),
        }
        bodies[0] = Buffer.from(JSON.stringify(metadata))
        bodies[3] = archive
        for (const format of [1, 2] as const) {
            await writeFile(encrypted, sealEnvelope(format, key, header, bodies))
            await assert.rejects(
                decryptBackup(encrypted, join(directory, 'restored'), key),
                /unsafe state archive path/,
            )
            await assert.rejects(stat(join(directory, 'restored')), /ENOENT/)
            await assert.rejects(stat(join(directory, 'escape')), /ENOENT/)
            await assertNoStaging(directory)
        }
    }))

test('encryption enforces metadata and application-key limits before processing backup contents', () =>
    fixture(async (directory, source) => {
        for (const [name, limit] of [
            ['metadata.json', maximumBackupMetadataBytes],
            ['app-encryption-key', maximumKeyBytes],
        ] as const) {
            const original = await readFile(join(source, name))
            await writeFile(join(source, name), Buffer.alloc(limit + 1, 32))
            await assert.rejects(
                encryptBackup(source, join(directory, 'backup.encrypted'), createRecoveryKey()),
                /invalid encrypted backup input size/,
            )
            await assert.rejects(stat(join(directory, 'backup.encrypted')), /ENOENT/)
            await writeFile(join(source, name), original)
        }
        await assertNoStaging(directory)
    }))

test('never overwrites existing output files or existing empty and nonempty destination directories', () =>
    fixture(async (directory, source) => {
        const encrypted = join(directory, 'backup.encrypted')
        const key = createRecoveryKey()
        await encryptBackup(source, encrypted, key)
        const bytes = await readFile(encrypted)
        await assert.rejects(encryptBackup(source, encrypted, key), /already exists/)
        assert.deepEqual(await readFile(encrypted), bytes)
        for (const nonempty of [false, true]) {
            const destination = join(directory, nonempty ? 'nonempty' : 'empty')
            await mkdir(destination)
            if (nonempty) await writeFile(join(destination, 'marker'), 'preserve me')
            await assert.rejects(decryptBackup(encrypted, destination, key), /already exists/)
            assert.deepEqual(await readdir(destination), nonempty ? ['marker'] : [])
            if (nonempty)
                assert.equal(await readFile(join(destination, 'marker'), 'utf8'), 'preserve me')
        }
        await assertNoStaging(directory)
    }))

test.skipIf(process.platform === 'win32')(
    'hardlinked sources and encrypted inputs are rejected',
    () =>
        fixture(async (directory, source) => {
            const key = createRecoveryKey()
            const encrypted = join(directory, 'backup.encrypted')
            await encryptBackup(source, encrypted, key)
            const alias = join(directory, 'ciphertext-alias')
            await link(encrypted, alias)
            await assert.rejects(
                decryptBackup(encrypted, join(directory, 'restored'), key),
                /invalid encrypted backup input/,
            )
            await rm(alias)
            await link(join(source, 'postgres.dump'), join(directory, 'dump-alias'))
            await assert.rejects(
                encryptBackup(source, join(directory, 'other'), key),
                /invalid encrypted backup input/,
            )
            await assertNoStaging(directory)
        }),
)

test.skipIf(process.platform === 'win32')(
    'symbolic links and symbolic link parent paths cannot supply or receive backup contents',
    () =>
        fixture(async (directory, source) => {
            const key = createRecoveryKey()
            const encrypted = join(directory, 'backup.encrypted')
            await encryptBackup(source, encrypted, key)
            const alias = join(directory, 'source-alias')
            await symlink(source, alias, 'dir')
            await assert.rejects(
                encryptBackup(alias, join(directory, 'other'), key),
                /symbolic links/,
            )
            await assert.rejects(
                decryptBackup(encrypted, join(alias, 'restore'), key),
                /symbolic links/,
            )
            const linkedInput = join(directory, 'ciphertext-link')
            await symlink(encrypted, linkedInput)
            await assert.rejects(
                decryptBackup(linkedInput, join(directory, 'restored'), key),
                /invalid encrypted backup input/,
            )
            await rm(join(source, 'postgres.dump'))
            await symlink(encrypted, join(source, 'postgres.dump'))
            await assert.rejects(encryptBackup(source, join(directory, 'other'), key))
            await assertNoStaging(directory)
        }),
)

async function abortDuringPayloadWrite(
    source: string,
    run: (signal: AbortSignal) => Promise<void>,
): Promise<void> {
    const controller = new AbortController()
    const probe = await open(source, 'r')
    const prototype = Object.getPrototypeOf(probe) as {
        write: (
            bytes: Uint8Array,
            offset: number,
            length: number,
        ) => Promise<{
            bytesWritten: number
            buffer: Uint8Array
        }>
    }
    await probe.close()
    const original = prototype.write
    const write = spyOn(prototype, 'write').mockImplementation(async function (
        this: FileHandle,
        bytes: Uint8Array,
        offset: number,
        length: number,
    ) {
        const result = await original.call(this, bytes, offset, length)
        // Header and key writes remain below this size. Abort after a real payload
        // write, so the composed operation signal must stop an in-progress copy.
        if (length >= 65_536) controller.abort(new Error('interrupted fixture'))
        return result
    })
    try {
        await run(controller.signal)
        assert.equal(controller.signal.aborted, true)
    } finally {
        write.mockRestore()
    }
}

test('interruption cleans ciphertext and private plaintext staging while preserving both original inputs', () =>
    fixture(
        async (directory, source) => {
            const key = createRecoveryKey()
            const encrypted = join(directory, 'backup.encrypted')
            const originalDump = await readFile(join(source, 'postgres.dump'))
            await abortDuringPayloadWrite(join(source, 'postgres.dump'), (signal) =>
                assert.rejects(
                    encryptBackup(source, encrypted, key, signal),
                    /interrupted fixture/,
                ),
            )
            await assert.rejects(stat(encrypted), /ENOENT/)
            assert.deepEqual(await readFile(join(source, 'postgres.dump')), originalDump)
            await assertNoStaging(directory)
            await encryptBackup(source, encrypted, key)
            const ciphertext = await readFile(encrypted)
            await abortDuringPayloadWrite(encrypted, (signal) =>
                assert.rejects(
                    decryptBackup(encrypted, join(directory, 'restored'), key, signal),
                    /interrupted fixture/,
                ),
            )
            await assert.rejects(stat(join(directory, 'restored')), /ENOENT/)
            assert.deepEqual(await readFile(encrypted), ciphertext)
            await assertNoStaging(directory)
        },
        2 * 1024 ** 2,
    ))

test('already aborted operations fail before accessing any files', async () => {
    const signal = AbortSignal.abort(new Error('cancelled fixture'))
    await assert.rejects(
        encryptBackup('never-read', 'never-write', createRecoveryKey(), signal),
        /cancelled fixture/,
    )
    await assert.rejects(
        decryptBackup('never-read', 'never-write', createRecoveryKey(), signal),
        /cancelled fixture/,
    )
})

test('interruption during publication removes only the newly created destination', () =>
    fixture(async (directory, source) => {
        const key = createRecoveryKey()
        const encrypted = join(directory, 'backup.encrypted')
        const destination = join(directory, 'restored')
        await encryptBackup(source, encrypted, key)
        const original = await readFile(encrypted)
        const controller = new AbortController()
        const originalRename = filesystem.rename
        const rename = spyOn(filesystem, 'rename').mockImplementation(async (from, to) => {
            await originalRename(from, to)
            if (to === join(destination, 'app-encryption-key'))
                controller.abort(new Error('publication interrupted fixture'))
        })
        try {
            await assert.rejects(
                decryptBackup(encrypted, destination, key, controller.signal),
                /publication interrupted fixture/,
            )
        } finally {
            rename.mockRestore()
        }
        assert.equal(controller.signal.aborted, true)
        await assert.rejects(stat(destination), /ENOENT/)
        assert.deepEqual(await readFile(encrypted), original)
        assert.equal((await verifyPublishedBackup(source)).metadata.version, 4)
        await assertNoStaging(directory)
    }))
