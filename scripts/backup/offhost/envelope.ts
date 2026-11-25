// oxlint-disable no-await-in-loop -- Stream bounded chunks and publish verified files in order.
import {
    createCipheriv,
    createDecipheriv,
    createHash,
    hkdfSync,
    randomBytes,
    timingSafeEqual,
} from 'node:crypto'
import { constants } from 'node:fs'
import { maximumBackupMetadataBytes } from '../validation.ts'
import {
    chmod,
    lstat,
    mkdir,
    mkdtemp,
    open,
    readdir,
    rename,
    rm,
    type FileHandle,
} from 'node:fs/promises'
import { dirname, join, parse, resolve } from 'node:path'
import {
    parseApplicationEncryptionKeyFile,
    readFileRange,
    writeFileChunk,
} from '../artifact-file.ts'
import { syncBackupDirectory, verifyPublishedBackup } from '../publication.ts'
import { assertBackupCapacity, backupCapacityGuard } from '../capacity.ts'
import { runMaintenanceProcess } from '../maintenance-process.ts'
import { BACKUP_RUNTIME_POLICY } from '../../../web/src/config/backup-runtime.config.ts'

// Both formats have a fixed 96-byte AAD header and exactly five artifact bodies in order.
// No names or paths are accepted from the envelope.
// - v1 (read only) encrypts the concatenated bodies as one AES-256-GCM stream with one tag.
// - v2 derives a payload key with HKDF-SHA256 from the recovery key and the header salt,
//   then seals every 64 KiB chunk of the bodies on its own. The nonce holds the chunk
//   counter and marks the final chunk, so no unauthenticated plaintext is ever written.
const magic = Buffer.from('RPBAKENC', 'ascii')
const streamFormat = 1
const chunkedFormat = 2
const payloadKeyInfo = 'RPBAKENC/2 AES-256-GCM payload key'
const headerBytes = 96
const tagBytes = 16
const chunkBytes = 65_536
const names = [
    'metadata.json',
    'app-encryption-key',
    'postgres.dump',
    'controller-state.tar',
    'crowdsec-state.tar',
] as const
const limits = [
    maximumBackupMetadataBytes,
    65_536,
    BACKUP_RUNTIME_POLICY.maximumArtifactBytes,
    BACKUP_RUNTIME_POLICY.maximumArtifactBytes,
    BACKUP_RUNTIME_POLICY.maximumArtifactBytes,
]
const maximumPayloadBytes = limits.reduce((sum, bytes) => sum + bytes, 0)
const nativeController = '/usr/local/bin/rentnerproxy-controller'

const chunkCount = (payloadBytes: number) => Math.ceil(payloadBytes / chunkBytes)

function envelopeBytes(format: number, payloadBytes: number): number {
    const tags = format === chunkedFormat ? chunkCount(payloadBytes) : 1
    return headerBytes + payloadBytes + tags * tagBytes
}

function payloadKey(key: Buffer, header: Buffer): Buffer {
    return Buffer.from(hkdfSync('sha256', key, header.subarray(12, 24), payloadKeyInfo, 32))
}

function chunkNonce(index: number, last: boolean): Buffer {
    const nonce = Buffer.alloc(12)
    nonce.writeBigUInt64BE(BigInt(index), 3)
    nonce[11] = last ? 1 : 0
    return nonce
}

async function hasNativeEnvelope(signal: AbortSignal): Promise<boolean> {
    if (process.platform !== 'linux' || !(await Bun.file(nativeController).exists())) return false
    try {
        const result = await runMaintenanceProcess(
            [nativeController, '--backup-envelope', 'version'],
            {
                cwd: process.cwd(),
                env: {},
                signal,
                timeoutMs: 2_000,
                maximumOutputBytes: 64,
            },
        )
        signal.throwIfAborted()
        return (
            result.stopped &&
            !result.failed &&
            // A v2 controller seals v2 and opens both formats.
            Buffer.from(result.stdout).toString('ascii') === 'RPBAKENC/2\n'
        )
    } catch {
        signal.throwIfAborted()
        return false
    }
}

async function transformNativeEnvelope(
    operation: 'seal' | 'open' | 'publish',
    source: string,
    target: string,
    frame: Buffer,
    signal: AbortSignal,
): Promise<Uint8Array> {
    try {
        const result = await runMaintenanceProcess(
            [nativeController, '--backup-envelope', operation, resolve(source), resolve(target)],
            {
                cwd: process.cwd(),
                env: {},
                signal,
                timeoutMs: BACKUP_RUNTIME_POLICY.operationTimeoutMs,
                maximumOutputBytes: 1024,
                input: frame,
            },
        )
        signal.throwIfAborted()
        if (result.failed || !result.stopped)
            throw new Error('invalid or incomplete encrypted backup transfer')
        return result.stdout
    } finally {
        frame.fill(0)
    }
}

function parseRecoveryKey(value: string): Buffer {
    if (!/^[A-Za-z0-9+/]{43}=$/u.test(value))
        throw new Error('recovery key must be a canonical base64-encoded independent 32-byte key')
    const key = Buffer.from(value, 'base64')
    if (key.length !== 32 || key.toString('base64') !== value)
        throw new Error('recovery key must be a canonical base64-encoded independent 32-byte key')
    return key
}

export function createRecoveryKey(): string {
    const key = randomBytes(32)
    try {
        return key.toString('base64')
    } finally {
        key.fill(0)
    }
}

export function recoveryKeyId(value: string): string {
    const key = parseRecoveryKey(value)
    try {
        return createHash('sha256').update(key).digest('hex')
    } finally {
        key.fill(0)
    }
}

async function safeDirectory(directory: string): Promise<void> {
    let path = resolve(directory)
    while (true) {
        const info = await lstat(path)
        if (!info.isDirectory() || info.isSymbolicLink())
            throw new Error('backup paths must not contain symbolic links or non-directories')
        const parent = dirname(path)
        if (parent === path) return
        path = parent
    }
}

async function absent(path: string): Promise<void> {
    try {
        await lstat(path)
    } catch (error) {
        if (error instanceof Error && 'code' in error && error.code === 'ENOENT') return
        throw error
    }
    throw new Error('backup destination already exists')
}

async function regularFile(path: string, maximum: number): Promise<FileHandle> {
    const expected = await lstat(path)
    if (!expected.isFile() || expected.isSymbolicLink() || expected.nlink !== 1)
        throw new Error('invalid encrypted backup input')
    const file = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK)
    try {
        const info = await file.stat()
        if (
            !info.isFile() ||
            info.nlink !== 1 ||
            info.dev !== expected.dev ||
            info.ino !== expected.ino ||
            info.size < 1 ||
            info.size > maximum
        )
            throw new Error('invalid encrypted backup input size or file')
        return file
    } catch (error) {
        await file.close()
        throw error
    }
}

function payloadLengths(header: Buffer): { format: number; lengths: number[] } {
    const format = header[8]!
    if (
        !header.subarray(0, 8).equals(magic) ||
        (format !== streamFormat && format !== chunkedFormat) ||
        header[9] !== 1 ||
        header.readUInt16BE(10) !== 0
    )
        throw new Error('unsupported encrypted backup envelope')
    const lengths = limits.map((maximum, index) => {
        const bytes = header.readBigUInt64BE(56 + index * 8)
        if (bytes < 1n || bytes > BigInt(maximum))
            throw new Error('encrypted backup artifact exceeds size limit')
        return Number(bytes)
    })
    if (lengths.reduce((sum, bytes) => sum + bytes, 0) > maximumPayloadBytes)
        throw new Error('encrypted backup exceeds total size limit')
    return { format, lengths }
}

/** Open a v2 envelope chunk by chunk and stage each chunk only after it authenticated. */
async function openChunks(
    input: FileHandle,
    staging: string,
    header: Buffer,
    key: Buffer,
    lengths: number[],
    checkCapacity: () => Promise<void>,
    signal?: AbortSignal,
): Promise<void> {
    const payloadBytes = lengths.reduce((sum, bytes) => sum + bytes, 0)
    const count = chunkCount(payloadBytes)
    const subkey = payloadKey(key, header)
    let output: FileHandle | undefined
    let artifact = 0
    let remaining = 0
    let inputOffset = headerBytes
    try {
        for (let index = 0; index < count; index++) {
            if ((index * chunkBytes) % BACKUP_RUNTIME_POLICY.capacityCheckBytes === 0)
                await checkCapacity()
            signal?.throwIfAborted()
            const plain = Math.min(chunkBytes, payloadBytes - index * chunkBytes)
            const sealed = await readFileRange(input, inputOffset, plain + tagBytes)
            inputOffset += plain + tagBytes
            const decipher = createDecipheriv(
                'aes-256-gcm',
                subkey,
                chunkNonce(index, index + 1 === count),
                { authTagLength: tagBytes },
            )
            decipher.setAAD(header)
            decipher.setAuthTag(sealed.subarray(plain))
            // final() throws for an altered chunk before any of its plaintext is written.
            const data = Buffer.concat([decipher.update(sealed.subarray(0, plain)), decipher.final()])
            let position = 0
            while (position < data.length) {
                if (!output) {
                    const name = names[artifact]
                    if (!name) throw new Error('invalid encrypted backup payload')
                    output = await open(join(staging, name), 'wx', 0o600)
                    await output.chmod(0o600)
                    remaining = lengths[artifact]!
                }
                const part = Math.min(remaining, data.length - position)
                await writeFileChunk(output, data.subarray(position, position + part))
                position += part
                remaining -= part
                if (remaining === 0) {
                    await output.sync()
                    await output.close()
                    output = undefined
                    artifact += 1
                }
            }
            data.fill(0)
        }
        if (artifact !== names.length) throw new Error('invalid encrypted backup payload')
    } finally {
        subkey.fill(0)
        await output?.close()
    }
}

async function independentKey(file: FileHandle, key: Buffer, signal?: AbortSignal): Promise<void> {
    const applicationKey = await parseApplicationEncryptionKeyFile(file, signal)
    try {
        if (timingSafeEqual(applicationKey, key))
            throw new Error('recovery key must differ from the application encryption key')
    } finally {
        applicationKey.fill(0)
    }
}

export async function encryptBackup(
    directory: string,
    outputFile: string,
    recoveryKey: string,
    signal?: AbortSignal,
): Promise<{ bytes: number; sha256: string; keyId: string }> {
    signal = AbortSignal.any([
        AbortSignal.timeout(BACKUP_RUNTIME_POLICY.operationTimeoutMs),
        ...(signal ? [signal] : []),
    ])
    signal?.throwIfAborted()
    const key = parseRecoveryKey(recoveryKey)
    const files: FileHandle[] = []
    let output: FileHandle | undefined
    let ownsOutput = false
    try {
        await safeDirectory(directory)
        if (dirname(resolve(outputFile)) === resolve(directory))
            throw new Error('encrypted output must be outside the complete source backup directory')
        await safeDirectory(dirname(resolve(outputFile)))
        await absent(outputFile)
        const entries = await readdir(directory)
        if (
            entries.length !== names.length ||
            entries.some((name) => !names.some((expected) => expected === name))
        )
            throw new Error('backup must contain exactly the five complete backup artifact files')
        for (const [index, name] of names.entries()) {
            signal?.throwIfAborted()
            files.push(await regularFile(join(directory, name), limits[index]!))
        }
        const verified = await verifyPublishedBackup(directory, signal)
        await independentKey(files[1]!, key, signal)
        const lengths = await Promise.all(files.map(async (file) => (await file.stat()).size))
        const payloadBytes = lengths.reduce((sum, length) => sum + length, 0)
        const sealedBytes = envelopeBytes(chunkedFormat, payloadBytes)
        await assertBackupCapacity([{ path: dirname(resolve(outputFile)), bytes: sealedBytes }])
        const checkCapacity = backupCapacityGuard([dirname(resolve(outputFile))])
        const header = Buffer.alloc(headerBytes)
        magic.copy(header)
        header[8] = chunkedFormat
        header[9] = 1 // AES-256-GCM with a full 128-bit authentication tag.
        randomBytes(12).copy(header, 12)
        const keyId = createHash('sha256').update(key).digest('hex')
        Buffer.from(keyId, 'hex').copy(header, 24)
        lengths.forEach((bytes, index) => header.writeBigUInt64BE(BigInt(bytes), 56 + index * 8))
        payloadLengths(header)
        const expected = [
            verified.metadataSha256,
            verified.metadata.applicationEncryptionKey.sha256,
            verified.metadata.postgres.sha256,
            verified.metadata.controllerState.sha256,
            verified.metadata.crowdSecState.sha256,
        ]
        if (await hasNativeEnvelope(signal)) {
            const privateDirectory = await mkdtemp(
                join(dirname(resolve(outputFile)), '.rentnerproxy-encrypt-'),
            )
            const sealed = join(privateDirectory, 'envelope')
            let result: { bytes: number; sha256: string; keyId: string }
            try {
                const frame = Buffer.concat([
                    key,
                    header,
                    ...expected.map((hash) => Buffer.from(hash, 'hex')),
                ])
                const raw = await transformNativeEnvelope('seal', directory, sealed, frame, signal)
                const receipt: unknown = JSON.parse(new TextDecoder().decode(raw))
                if (
                    typeof receipt !== 'object' ||
                    receipt === null ||
                    !('bytes' in receipt) ||
                    receipt.bytes !== sealedBytes ||
                    !('sha256' in receipt) ||
                    typeof receipt.sha256 !== 'string' ||
                    !/^[a-f0-9]{64}$/u.test(receipt.sha256)
                )
                    throw new Error('invalid native encrypted backup receipt')
                signal.throwIfAborted()
                const sealedIdentity = await lstat(sealed, { bigint: true })
                try {
                    await transformNativeEnvelope(
                        'publish',
                        sealed,
                        outputFile,
                        Buffer.alloc(0),
                        signal,
                    )
                } finally {
                    const published = await lstat(outputFile, { bigint: true }).catch(() => null)
                    ownsOutput =
                        published?.dev === sealedIdentity.dev &&
                        published.ino === sealedIdentity.ino
                }
                if (!ownsOutput) throw new Error('encrypted backup publication changed')
                await syncBackupDirectory(dirname(resolve(outputFile)))
                result = { bytes: receipt.bytes, sha256: receipt.sha256, keyId }
            } finally {
                await rm(privateDirectory, { recursive: true, force: true })
            }
            signal.throwIfAborted()
            ownsOutput = false
            return result
        }
        output = await open(outputFile, 'wx', 0o600)
        ownsOutput = true
        await output.chmod(0o600)
        const hash = createHash('sha256')
        let bytes = 0
        const write = async (chunk: Buffer) => {
            await writeFileChunk(output!, chunk)
            hash.update(chunk)
            bytes += chunk.length
        }
        await write(header)
        const subkey = payloadKey(key, header)
        try {
            const count = chunkCount(payloadBytes)
            let index = 0
            let pending: Buffer[] = []
            let pendingBytes = 0
            const seal = async () => {
                if ((index * chunkBytes) % BACKUP_RUNTIME_POLICY.capacityCheckBytes === 0)
                    await checkCapacity()
                signal?.throwIfAborted()
                const cipher = createCipheriv(
                    'aes-256-gcm',
                    subkey,
                    chunkNonce(index, index + 1 === count),
                    { authTagLength: tagBytes },
                )
                cipher.setAAD(header)
                const plaintext = Buffer.concat(pending)
                await write(
                    Buffer.concat([cipher.update(plaintext), cipher.final(), cipher.getAuthTag()]),
                )
                for (const part of [plaintext, ...pending]) part.fill(0)
                pending = []
                pendingBytes = 0
                index += 1
            }
            for (const [artifact, file] of files.entries()) {
                const artifactHash = createHash('sha256')
                let offset = 0
                while (offset < lengths[artifact]!) {
                    const take = Math.min(chunkBytes - pendingBytes, lengths[artifact]! - offset)
                    const chunk = await readFileRange(file, offset, take)
                    artifactHash.update(chunk)
                    pending.push(chunk)
                    pendingBytes += take
                    offset += take
                    if (pendingBytes === chunkBytes) await seal()
                }
                if (
                    (await file.stat()).size !== lengths[artifact] ||
                    artifactHash.digest('hex') !== expected[artifact]
                )
                    throw new Error('backup changed during encryption')
            }
            if (pendingBytes > 0) await seal()
            if (index !== count) throw new Error('backup changed during encryption')
        } finally {
            subkey.fill(0)
        }
        await output.sync()
        await output.close()
        output = undefined
        signal?.throwIfAborted()
        await syncBackupDirectory(dirname(resolve(outputFile)))
        signal?.throwIfAborted()
        ownsOutput = false
        return { bytes, sha256: hash.digest('hex'), keyId }
    } finally {
        key.fill(0)
        await output?.close()
        await Promise.all(files.map((file) => file.close()))
        if (ownsOutput) await rm(outputFile, { force: true })
    }
}

export async function decryptBackup(
    inputFile: string,
    destinationDirectory: string,
    recoveryKey: string,
    signal?: AbortSignal,
): Promise<void> {
    signal = AbortSignal.any([
        AbortSignal.timeout(BACKUP_RUNTIME_POLICY.operationTimeoutMs),
        ...(signal ? [signal] : []),
    ])
    signal?.throwIfAborted()
    const key = parseRecoveryKey(recoveryKey)
    let input: FileHandle | undefined
    let staging: string | undefined
    let ownsDestination = false
    try {
        await safeDirectory(dirname(resolve(inputFile)))
        const destination = resolve(destinationDirectory)
        if (destination === parse(destination).root) throw new Error('invalid backup destination')
        await safeDirectory(dirname(destination))
        await absent(destination)
        input = await regularFile(inputFile, envelopeBytes(chunkedFormat, maximumPayloadBytes))
        const header = await readFileRange(input, 0, headerBytes)
        const { format, lengths } = payloadLengths(header)
        const payloadBytes = lengths.reduce((sum, bytes) => sum + bytes, 0)
        const sealedBytes = envelopeBytes(format, payloadBytes)
        if ((await input.stat()).size !== sealedBytes)
            throw new Error('truncated or trailing encrypted backup data')
        if (!timingSafeEqual(header.subarray(24, 56), createHash('sha256').update(key).digest()))
            throw new Error('encrypted backup recovery key does not match')
        await assertBackupCapacity([{ path: dirname(destination), bytes: payloadBytes }])
        const checkCapacity = backupCapacityGuard([dirname(destination)])
        staging = await mkdtemp(join(dirname(destination), '.rentnerproxy-decrypt-'))
        await chmod(staging, 0o700)
        if (await hasNativeEnvelope(signal)) {
            await transformNativeEnvelope(
                'open',
                inputFile,
                staging,
                Buffer.concat([key, header]),
                signal,
            )
        } else if (format === chunkedFormat) {
            await openChunks(input, staging, header, key, lengths, checkCapacity, signal)
        } else {
            const decipher = createDecipheriv('aes-256-gcm', key, header.subarray(12, 24), {
                authTagLength: tagBytes,
            })
            decipher.setAAD(header)
            decipher.setAuthTag(await readFileRange(input, headerBytes + payloadBytes, tagBytes))
            let inputOffset = headerBytes
            for (const [index, name] of names.entries()) {
                const output = await open(join(staging, name), 'wx', 0o600)
                try {
                    await output.chmod(0o600)
                    for (let offset = 0; offset < lengths[index]!; offset += chunkBytes) {
                        if (offset % BACKUP_RUNTIME_POLICY.capacityCheckBytes === 0)
                            await checkCapacity()
                        signal?.throwIfAborted()
                        const bytes = Math.min(chunkBytes, lengths[index]! - offset)
                        await writeFileChunk(
                            output,
                            decipher.update(await readFileRange(input, inputOffset, bytes)),
                        )
                        inputOffset += bytes
                    }
                    await output.sync()
                } finally {
                    await output.close()
                }
            }
            if (decipher.final().length !== 0) throw new Error('invalid encrypted backup payload')
        }
        if ((await input.stat()).size !== sealedBytes)
            throw new Error('encrypted backup changed during decryption')
        signal?.throwIfAborted()
        await verifyPublishedBackup(staging, signal)
        const applicationKeyFile = await regularFile(
            join(staging, 'app-encryption-key'),
            limits[1]!,
        )
        try {
            await independentKey(applicationKeyFile, key, signal)
        } finally {
            await applicationKeyFile.close()
        }
        await syncBackupDirectory(staging)
        signal?.throwIfAborted()
        // mkdir is exclusive on every platform. Publish metadata last so partial moves
        // cannot be mistaken for a complete v4 backup; callers use it only on success.
        await mkdir(destination, { mode: 0o700 })
        ownsDestination = true
        await chmod(destination, 0o700)
        for (const name of [...names.slice(1), names[0]]) {
            signal?.throwIfAborted()
            await rename(join(staging, name), join(destination, name))
        }
        await syncBackupDirectory(destination)
        await syncBackupDirectory(dirname(destination))
        signal?.throwIfAborted()
        ownsDestination = false
    } finally {
        key.fill(0)
        await input?.close()
        if (staging) await rm(staging, { recursive: true, force: true })
        if (ownsDestination)
            await rm(resolve(destinationDirectory), { recursive: true, force: true })
    }
}
