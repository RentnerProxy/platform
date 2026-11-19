import { createHash } from 'node:crypto'
import { lstat, type FileHandle } from 'node:fs/promises'
import { z } from 'zod'
import { readFileRange } from './artifact-file.ts'
import { stateArchiveAllocationEvidence } from './capacity.ts'
import { appBackupInstallations } from './validation.ts'
import type { BackupMetadata, StateArchiveFileEntry } from './Types/format.types.ts'

export const appStateName = '.rentnerproxy-app-state-v1'
export const maximumAppStateBytes = 48 * 1024 * 1024
export const appBackupCommand = '/usr/local/bin/rentnerproxy-controller'

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
    const summary = z
        .object({
            formatVersion: z.literal(1),
            installations: z.record(
                z.string(),
                z.object({
                    uid: z.number(),
                    appId: z.string(),
                    generation: z.number(),
                    authorityRecorded: z.boolean().optional(),
                }),
            ),
        })
        .parse(JSON.parse(bytes.toString('utf8')))
    const items = appBackupInstallations.parse(
        Object.entries(summary.installations).map(([id, slot]) => Object.assign({ id }, slot)),
    )
    if (new Set(items.map(({ uid }) => uid)).size !== items.length)
        throw new Error('Duplicate installation identity')
    return items
}

export async function readAppStateMember(
    file: FileHandle,
    entries: StateArchiveFileEntry[],
    metadata: BackupMetadata,
) {
    const reserved = entries.filter(
        ({ name }) => name === appStateName || name.startsWith(appStateName + '/'),
    )
    if (metadata.version === 4 && !reserved.length) return undefined
    if (entries.some(({ name }) => name.split('/').slice(1).includes(appStateName)))
        throw new Error('Ambiguous app snapshot archive path')
    const entry = reserved[0]
    if (
        metadata.version !== 5 ||
        reserved.length !== 1 ||
        entry?.name !== appStateName ||
        entry.directory ||
        entry.size !== metadata.applications.bytes ||
        entry.size > maximumAppStateBytes
    )
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

export function controllerAllocation(entries: StateArchiveFileEntry[], metadata: BackupMetadata) {
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
