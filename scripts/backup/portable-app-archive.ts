// oxlint-disable no-await-in-loop -- Archive reads and appended blocks must advance in order.
import { createHash } from 'node:crypto'
import { constants } from 'node:fs'
import { open } from 'node:fs/promises'
import { BACKUP_RUNTIME_POLICY } from '../../web/src/config/backup-runtime.config.ts'
import { readFileRange, writeFileChunk } from './artifact-file.ts'
import { isReservedAppStatePath, portableAppStateName } from './app-state.ts'
import { validateStateArchiveFile } from './format.ts'

const block = 512
const chunkBytes = 65_536
// A ustar size field holds eleven octal digits.
const maximumMemberBytes = 0o77777777777

function octal(value: number, width: number): string {
    return value.toString(8).padStart(width - 1, '0') + '\0'
}

function memberHeader(size: number): Buffer {
    const header = Buffer.alloc(block)
    header.write(portableAppStateName, 0)
    header.write(octal(0o600, 8), 100)
    header.write(octal(0, 8), 108)
    header.write(octal(0, 8), 116)
    header.write(octal(size, 12), 124)
    header.write(octal(Math.floor(Date.now() / 1000), 12), 136)
    header.fill(32, 148, 156)
    header.write('0', 156)
    header.write('ustar\u000000', 257)
    const checksum = header.reduce((sum, byte) => sum + byte, 0)
    header.write(octal(checksum, 7) + ' ', 148)
    return header
}

/**
 * Appends a captured portable app state to a controller state archive, as the managed backup's
 * archive does in the appliance. The state must be the exact inspected snapshot.
 */
export async function appendPortableAppState(
    archivePath: string,
    statePath: string,
    expected: Readonly<{ bytes: number; sha256: string }>,
    signal?: AbortSignal,
): Promise<{ bytes: number; sha256: string }> {
    const archive = await open(
        archivePath,
        constants.O_RDWR | constants.O_APPEND | constants.O_NOFOLLOW,
    )
    try {
        const state = await open(statePath, constants.O_RDONLY | constants.O_NOFOLLOW)
        try {
            const info = await state.stat()
            if (
                !info.isFile() ||
                info.nlink !== 1 ||
                info.size !== expected.bytes ||
                info.size < 1 ||
                info.size > maximumMemberBytes
            )
                throw new Error('Invalid captured app state')
            const entries = await validateStateArchiveFile(archive, 'controller', signal)
            if (entries.some(({ name }) => isReservedAppStatePath(name)))
                throw new Error('Controller state already contains an app snapshot')
            // The validator accepts only zero blocks after the last entry, so this drops the trailer.
            const end = entries.reduce(
                (offset, entry) =>
                    Math.max(offset, entry.bodyOffset + Math.ceil(entry.size / block) * block),
                0,
            )
            const padding = (block - (info.size % block)) % block
            const bytes = end + block + info.size + padding + 2 * block
            if (bytes > BACKUP_RUNTIME_POLICY.maximumArtifactBytes)
                throw new Error('Controller state archive exceeds size limit')
            const archiveHash = createHash('sha256')
            for (let offset = 0; offset < end; offset += chunkBytes) {
                signal?.throwIfAborted()
                archiveHash.update(
                    await readFileRange(archive, offset, Math.min(chunkBytes, end - offset)),
                )
            }
            await archive.truncate(end)
            const append = async (chunk: Buffer) => {
                archiveHash.update(chunk)
                await writeFileChunk(archive, chunk)
            }
            await append(memberHeader(info.size))
            const stateHash = createHash('sha256')
            for (let offset = 0; offset < info.size; offset += chunkBytes) {
                signal?.throwIfAborted()
                const chunk = await readFileRange(
                    state,
                    offset,
                    Math.min(chunkBytes, info.size - offset),
                )
                stateHash.update(chunk)
                await append(chunk)
            }
            if (stateHash.digest('hex') !== expected.sha256)
                throw new Error('Captured app state changed before archiving')
            await append(Buffer.alloc(padding + 2 * block))
            await archive.sync()
            if ((await archive.stat()).size !== bytes)
                throw new Error('Controller state archive size changed')
            return { bytes, sha256: archiveHash.digest('hex') }
        } finally {
            await state.close()
        }
    } finally {
        await archive.close()
    }
}
