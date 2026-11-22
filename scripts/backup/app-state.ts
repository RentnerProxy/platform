import { createHash } from 'node:crypto'
import { BACKUP_RUNTIME_POLICY } from '../../web/src/config/backup-runtime.config.ts'
import {
    APP_AWARE_BACKUP_VERSION,
    PORTABLE_APP_BACKUP_VERSION,
} from '../../web/src/config/compatibility.config.ts'
import { lstat, open, rm, writeFile, type FileHandle } from 'node:fs/promises'
import { readFileRange, writeFileChunk } from './artifact-file.ts'
import { stateArchiveAllocationEvidence } from './capacity.ts'
import {
    appBackupInstallations,
    legacyAppBackupSummary,
    portableAppBackupHeader,
} from './validation.ts'
import type { StateArchiveAllocationEvidence } from './Types/capacity.types.ts'
import type {
    AppStateValidationOptions,
    BackupMetadata,
    StateArchiveFileEntry,
} from './Types/format.types.ts'

export const appStateName = '.rentnerproxy-app-state-v1'
export const portableAppStateName = '.rentnerproxy-app-state-v2'
export const maximumAppStateBytes = BACKUP_RUNTIME_POLICY.maximumAppStateBytes
export const appBackupCommand = '/usr/local/bin/rentnerproxy-controller'

const reservedAppStatePrefix = '.rentnerproxy-app-state-'
const portableMagic = Buffer.from('RPAPPB2\0')
const portablePrefixBytes = portableMagic.length + 4
const fileDataPayloadLimit = 32 * 1024 ** 2
const packagePayloadLimit = 256 * 1024 ** 2
const packageArchiveLimit = 257 * 1024 ** 2
const checkpointLimit = 96 * 1024 ** 2
const kindOrder = { data: 0, checkpoint: 1, package: 2, database: 3 } as const

export function appStateNameForVersion(version: BackupMetadata['version']): string | undefined {
    if (version === APP_AWARE_BACKUP_VERSION) return appStateName
    if (version === PORTABLE_APP_BACKUP_VERSION) return portableAppStateName
    return undefined
}

export async function hasNativeAppStorage() {
    const present = await Promise.all(
        ['/var/lib/rentnerproxy/apps', '/var/lib/rentnerproxy/app-manager'].map(async (path) => {
            try {
                await lstat(path)
                return true
            } catch (error) {
                if (error instanceof Error && 'code' in error && error.code === 'ENOENT')
                    return false
                throw error
            }
        }),
    )
    return present.some(Boolean)
}

export function appStateInstallations(bytes: Buffer) {
    if (!bytes.length || bytes.length > maximumAppStateBytes)
        throw new Error('Invalid app snapshot size')
    const summary = legacyAppBackupSummary.parse(JSON.parse(bytes.toString('utf8')))
    return installationSummary(summary.installations)
}

function installationSummary(
    installations: ReturnType<typeof legacyAppBackupSummary.parse>['installations'],
) {
    const items = appBackupInstallations.parse(
        Object.entries(installations).map(([id, slot]) => Object.assign({ id }, slot)),
    )
    if (new Set(items.map(({ uid }) => uid)).size !== items.length)
        throw new Error('Duplicate installation identity')
    return items
}

export function isReservedAppStatePath(name: string): boolean {
    return (
        name.includes(reservedAppStatePrefix) &&
        name.split('/').some((part) => part.startsWith(reservedAppStatePrefix))
    )
}

function findAppStateMember(entries: StateArchiveFileEntry[], metadata: BackupMetadata) {
    const reserved = entries.filter(({ name }) => isReservedAppStatePath(name))
    if (metadata.version === 4 && !reserved.length) return undefined
    const entry = reserved[0]
    if (
        metadata.version === 4 ||
        reserved.length !== 1 ||
        !entry ||
        entry.name !== appStateNameForVersion(metadata.version) ||
        entry.directory ||
        entry.size !== metadata.applications.bytes
    )
        throw new Error('App snapshot does not match backup version')
    return entry
}

export async function readAppStateMember(
    file: FileHandle,
    entries: StateArchiveFileEntry[],
    metadata: BackupMetadata,
) {
    const entry = findAppStateMember(entries, metadata)
    if (!entry) return undefined
    if (metadata.version !== APP_AWARE_BACKUP_VERSION || entry.size > maximumAppStateBytes)
        throw new Error('App snapshot does not match backup version')
    const bytes = await readFileRange(file, entry.bodyOffset, entry.size)
    if (createHash('sha256').update(bytes).digest('hex') !== metadata.applications.sha256)
        throw new Error('App snapshot checksum mismatch')
    if (
        JSON.stringify(appStateInstallations(bytes)) !==
        JSON.stringify(metadata.applications.installations)
    )
        throw new Error('App snapshot identities differ from metadata')
    return bytes
}

async function readPortableAppState(
    file: FileHandle,
    offset: number,
    size: number,
    options: AppStateValidationOptions,
    expected?: Extract<
        BackupMetadata,
        { version: typeof PORTABLE_APP_BACKUP_VERSION }
    >['applications'],
) {
    const { target, signal, progress, checkCapacity } = options
    signal?.throwIfAborted()
    if (size <= portablePrefixBytes || size > BACKUP_RUNTIME_POLICY.maximumArtifactBytes)
        throw new Error('Invalid portable app snapshot size')
    const prefix = await readFileRange(file, offset, portablePrefixBytes)
    if (!prefix.subarray(0, portableMagic.length).equals(portableMagic))
        throw new Error('Invalid portable app snapshot magic')
    const headerSize = prefix.readUInt32BE(portableMagic.length)
    if (
        headerSize < 1 ||
        headerSize > BACKUP_RUNTIME_POLICY.maximumPortableAppStateHeaderBytes ||
        headerSize > size - portablePrefixBytes
    )
        throw new Error('Invalid portable app snapshot header size')
    const headerBytes = await readFileRange(file, offset + portablePrefixBytes, headerSize)
    const header = portableAppBackupHeader.parse(
        JSON.parse(new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(headerBytes)),
    )
    const installations = installationSummary(header.installations)
    if (expected && JSON.stringify(installations) !== JSON.stringify(expected.installations))
        throw new Error('App snapshot identities differ from metadata')

    const uids = new Set(installations.map(({ uid }) => String(uid)))
    let declaredBytes = portablePrefixBytes + headerSize
    let packages = 0
    let databaseBytes = 0
    for (const [index, member] of header.members.entries()) {
        const previous = header.members[index - 1]
        if (
            (previous &&
                (kindOrder[previous.kind] > kindOrder[member.kind] ||
                    (previous.kind === member.kind && previous.key >= member.key))) ||
            (member.kind === 'data' &&
                (member.key !== 'files' || member.bytes > maximumAppStateBytes)) ||
            (member.kind === 'checkpoint' &&
                (member.key !== 'catalog' || member.bytes > checkpointLimit)) ||
            (member.kind === 'package' &&
                (member.key !== member.sha256 || member.bytes > packageArchiveLimit)) ||
            (member.kind === 'database' && !uids.has(member.key))
        )
            throw new Error('Invalid portable app snapshot member')
        if (member.kind === 'package') packages++
        if (member.kind === 'database') {
            databaseBytes += 2 * Math.max(member.bytes, member.allocationBytes)
            if (!Number.isSafeInteger(databaseBytes))
                throw new Error('Invalid app database restoration capacity')
        }
        declaredBytes += member.bytes
    }
    const data = header.members[0]
    if (
        declaredBytes !== size ||
        data?.kind !== 'data' ||
        (packages > 0 && header.members[1]?.kind !== 'checkpoint')
    )
        throw new Error('Invalid portable app snapshot member layout')

    const hash = createHash('sha256').update(prefix).update(headerBytes)
    let output: FileHandle | undefined
    try {
        if (target) {
            await checkCapacity?.()
            output = await open(target, 'wx', 0o600)
            await output.chmod(0o600)
            await writeFileChunk(output, prefix)
            await writeFileChunk(output, headerBytes)
        }
        let position = portablePrefixBytes + headerSize
        let nextCapacityCheck = position + BACKUP_RUNTIME_POLICY.capacityCheckBytes
        for (const member of header.members) {
            const memberHash = createHash('sha256')
            const end = position + member.bytes
            // oxlint-disable no-await-in-loop -- Consume sized bodies and write the snapshot in order.
            while (position < end) {
                signal?.throwIfAborted()
                if (output && position >= nextCapacityCheck) {
                    await checkCapacity?.()
                    nextCapacityCheck = position + BACKUP_RUNTIME_POLICY.capacityCheckBytes
                }
                const chunk = await readFileRange(
                    file,
                    offset + position,
                    Math.min(65_536, end - position),
                )
                hash.update(chunk)
                memberHash.update(chunk)
                if (output) await writeFileChunk(output, chunk)
                position += chunk.length
                progress?.()
            }
            // oxlint-enable no-await-in-loop
            if (memberHash.digest('hex') !== member.sha256)
                throw new Error('Portable app snapshot member checksum mismatch')
        }
        const sha256 = hash.digest('hex')
        if (expected && sha256 !== expected.sha256)
            throw new Error('App snapshot checksum mismatch')
        await output?.sync()
        signal?.throwIfAborted()
        return {
            applications: { bytes: size, sha256, installations },
            allocation: {
                // Reserve staged members, decoded data, installed package trees and one
                // decompression workspace. Allow the measured database footprint and WAL headroom.
                payloadBytes:
                    size +
                    Math.min(data.bytes, fileDataPayloadLimit) +
                    (packages ? (packages + 1) * packagePayloadLimit : 0) +
                    databaseBytes,
                nodes: 8192 + 2 * installations.length + header.members.length,
            },
        }
    } catch (error) {
        if (target && output) {
            await output.close()
            output = undefined
            await rm(target, { force: true })
        }
        throw error
    } finally {
        await output?.close()
    }
}

export async function inspectPortableAppStateFile(
    file: FileHandle,
    signal?: AbortSignal,
    progress?: () => void,
) {
    const info = await file.stat()
    if (!info.isFile() || info.nlink !== 1) throw new Error('Invalid portable app snapshot file')
    const { applications } = await readPortableAppState(file, 0, info.size, { signal, progress })
    if ((await file.stat()).size !== info.size)
        throw new Error('Portable app snapshot size changed')
    return applications
}

export async function validateAppStateMember(
    file: FileHandle,
    entries: StateArchiveFileEntry[],
    metadata: BackupMetadata,
    options: AppStateValidationOptions = {},
): Promise<StateArchiveAllocationEvidence | undefined> {
    options.signal?.throwIfAborted()
    if (metadata.version === PORTABLE_APP_BACKUP_VERSION) {
        const entry = findAppStateMember(entries, metadata)
        if (!entry) throw new Error('Missing portable app snapshot')
        const verified = await readPortableAppState(
            file,
            entry.bodyOffset,
            entry.size,
            options,
            metadata.applications,
        )
        return verified.allocation
    }
    const bytes = await readAppStateMember(file, entries, metadata)
    if (!bytes || metadata.version === 4) return undefined
    options.signal?.throwIfAborted()
    if (options.target) {
        await options.checkCapacity?.()
        await writeFile(options.target, bytes, { mode: 0o600, flag: 'wx', signal: options.signal })
    }
    options.progress?.()
    return {
        payloadBytes: bytes.length,
        nodes: 8192 + 2 * metadata.applications.installations.length,
    }
}

export function controllerAllocation(
    entries: StateArchiveFileEntry[],
    metadata: BackupMetadata,
    appAllocation?: StateArchiveAllocationEvidence,
) {
    if (metadata.version === PORTABLE_APP_BACKUP_VERSION) {
        if (!appAllocation) throw new Error('Missing portable app snapshot capacity evidence')
        const evidence = stateArchiveAllocationEvidence(
            entries.filter(({ name }) => name !== portableAppStateName),
        )
        return {
            payloadBytes: evidence.payloadBytes + appAllocation.payloadBytes,
            nodes: evidence.nodes + appAllocation.nodes,
        }
    }
    const evidence = stateArchiveAllocationEvidence(entries)
    if (metadata.version === 4) return evidence
    // The encoded controller member already covers the file payload. Reserve inode and
    // directory allocations for the native decoder's total node limit plus each UID root.
    return {
        ...evidence,
        nodes: evidence.nodes + 8192 + 2 * metadata.applications.installations.length,
    }
}

export const rejectAppDatabasesSql = `SELECT 1 / (NOT EXISTS (
    SELECT FROM pg_catalog.pg_database WHERE datname ~ '^rp_app_[0-9]+$'
    UNION ALL SELECT FROM pg_catalog.pg_roles WHERE rolname ~ '^rp_(app|migrate)_[0-9]+$'
))::integer;`

export const rejectLegacyAppRowsSql = `DO $guard$ BEGIN
    IF to_regclass('rentnerproxy.app_runtime_installations') IS NOT NULL THEN
        IF EXISTS (SELECT FROM rentnerproxy.app_runtime_installations) THEN
            RAISE EXCEPTION 'App-aware restore required';
        END IF;
    END IF;
END $guard$;`
