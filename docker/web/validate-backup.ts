// oxlint-disable no-await-in-loop -- Every stored secret and migration is checked before replacement.
import { SQL } from 'bun'
import { Database } from 'bun:sqlite'
import { createDecipheriv, createHash } from 'node:crypto'
import { mkdir, readFile, stat } from 'node:fs/promises'
import { join } from 'node:path'
import {
    APP_AWARE_BACKUP_VERSION,
    PORTABLE_APP_BACKUP_VERSION,
    isSupportedBackupVersion,
    supportedBackupFormatLabel,
} from '../../web/src/lib/ApplicationVersion/backupCompatibility.ts'
import type {
    BackupAppDatabaseEvidence,
    BackupCertificateJobRow,
    BackupCrowdSecSettingRow,
    BackupHandoffPartRow,
    BackupMigrationJournal,
    BackupMigrationRow,
    BackupTotpSecretRow,
} from './Types/validate-backup.types.ts'

function isRecord(value: unknown): value is Record<string, unknown> {
    return typeof value === 'object' && value !== null && !Array.isArray(value)
}

export function isMigrationJournal(value: unknown): value is BackupMigrationJournal {
    return (
        isRecord(value) &&
        Array.isArray(value.entries) &&
        value.entries.every(
            (entry: unknown) =>
                isRecord(entry) && typeof entry.tag === 'string' && typeof entry.when === 'number',
        )
    )
}

export async function assertCompatibleBackupHistory(
    rows: readonly BackupMigrationRow[],
    journal: BackupMigrationJournal,
    readMigration: (tag: string) => Promise<Uint8Array>,
): Promise<void> {
    if (rows.length === 0 || rows.length > journal.entries.length) {
        throw new Error('unsupported backup database version')
    }
    for (const [index, row] of rows.entries()) {
        const migration = journal.entries[index]
        if (!migration) {
            throw new Error('backup migration history is incompatible with the target image')
        }
        const expected = createHash('sha256')
            .update(await readMigration(migration.tag))
            .digest('hex')
        if (row.hash !== expected || String(row.created_at) !== String(migration.when)) {
            throw new Error('backup migration history is incompatible with the target image')
        }
    }
}

export function decryptBackupSecret(
    key: Buffer,
    ciphertext: Buffer,
    iv: Buffer,
    context: string,
): Buffer {
    if (key.length !== 32 || iv.length !== 12 || ciphertext.length < 17) {
        throw new Error('invalid encrypted backup secret')
    }
    try {
        const decipher = createDecipheriv('aes-256-gcm', key, iv)
        decipher.setAAD(Buffer.from(context, 'utf8'))
        decipher.setAuthTag(ciphertext.subarray(ciphertext.length - 16))
        return Buffer.concat([decipher.update(ciphertext.subarray(0, -16)), decipher.final()])
    } catch {
        throw new Error('backup application key cannot decrypt persisted secrets')
    }
}

const unsupportedBackupVersion = `unsupported backup metadata version (supported: ${supportedBackupFormatLabel()})`

export function assertSupportedBackupVersion(metadata: unknown): void {
    if (!isRecord(metadata) || !isSupportedBackupVersion(metadata.version)) {
        throw new Error(unsupportedBackupVersion)
    }
}

export function assertBackupAppRows(installations: unknown, rows: readonly unknown[]): void {
    if (!Array.isArray(installations) || installations.length > 256 || rows.length > 256)
        throw new Error('Invalid application backup inventory')
    const active = installations.filter((slot: unknown) => {
        if (
            !isRecord(slot) ||
            typeof slot.generation !== 'number' ||
            (slot.authorityRecorded !== undefined && typeof slot.authorityRecorded !== 'boolean')
        )
            throw new Error('Invalid application backup inventory')
        return slot.authorityRecorded ?? slot.generation > 0
    })
    if (
        active.length !== rows.length ||
        new Set(rows.map((row) => (isRecord(row) ? row.id : null))).size !== rows.length ||
        rows.some(
            (row) =>
                !isRecord(row) ||
                !active.some(
                    (slot: unknown) =>
                        isRecord(slot) &&
                        slot.id === row.id &&
                        slot.appId === row.appId &&
                        slot.uid === row.uid,
                ),
        )
    )
        throw new Error('App database identities differ from the native installation journal')
}

// Every table whose rows belong to one installation. Migration 0035 created all of them together.
const appInstallationTables = [
    'app_runtime_generations',
    'app_runtime_grants',
    'app_runtime_role_permissions',
    'app_runtime_delegations',
    'app_runtime_secrets',
    'app_runtime_pending_secrets',
    'app_runtime_events',
    'app_runtime_event_retention',
    'app_runtime_messages',
    'app_runtime_owned_proxy_hosts',
    'app_runtime_operations',
    'app_runtime_operation_requests',
] as const

const maximumAppEvidenceBytes = 256 * 1024

/**
 * Read the installation rows, every installation that dependent rows refer to and the highest
 * recorded generation per installation as one JSON document. Schemas before the handoff journal
 * lack its table, so the caller states whether it exists.
 */
export function appDatabaseEvidenceSql(handoffs: boolean): string {
    const references = [...appInstallationTables, ...(handoffs ? ['legacy_feature_handoffs'] : [])]
        .map((table) => 'SELECT installation_id FROM rentnerproxy.' + table)
        .join(' UNION ')
    return `SELECT json_build_object(
    'installations', (SELECT coalesce(json_agg(installation), '[]') FROM (
        SELECT id, app_id AS "appId", uid::integer AS uid
        FROM rentnerproxy.app_runtime_installations ORDER BY id LIMIT 257) installation),
    'references', (SELECT coalesce(json_agg(installation_id), '[]') FROM (
        ${references} ORDER BY 1 LIMIT 257) reference),
    'generations', (SELECT coalesce(json_agg(latest), '[]') FROM (
        SELECT installation_id AS "installationId", max(generation) AS generation
        FROM rentnerproxy.app_runtime_generations
        GROUP BY installation_id ORDER BY 1 LIMIT 257) latest)
)::text AS evidence`
}

export function parseAppDatabaseEvidence(value: unknown): BackupAppDatabaseEvidence {
    let evidence: unknown
    try {
        if (typeof value === 'string' && value.length <= maximumAppEvidenceBytes)
            evidence = JSON.parse(value)
    } catch {
        evidence = undefined
    }
    if (
        !isRecord(evidence) ||
        !Array.isArray(evidence.installations) ||
        !Array.isArray(evidence.references) ||
        !Array.isArray(evidence.generations)
    )
        throw new Error('Invalid application schema evidence')
    return {
        installations: evidence.installations,
        references: evidence.references,
        generations: evidence.generations,
    }
}

/**
 * Compare all app rows of one database with the installation journal that governs it. Rows of
 * dependent tables must belong to an active installation. The next launch registers the journal
 * generation plus one, and a database that already recorded a higher generation rejects that
 * registration as a conflict, so the journal must not be behind the database.
 */
export function assertBackupAppState(
    installations: unknown,
    evidence: BackupAppDatabaseEvidence,
): void {
    assertBackupAppRows(installations, evidence.installations)
    const active = new Set(evidence.installations.map((row) => (isRecord(row) ? row.id : null)))
    if (
        evidence.references.length > 256 ||
        evidence.references.some((id) => typeof id !== 'string' || !active.has(id))
    )
        throw new Error('App database rows reference installations outside the backup inventory')
    const slots: unknown[] = Array.isArray(installations) ? installations : []
    const journal = new Map(slots.filter(isRecord).map((slot) => [slot.id, slot.generation]))
    if (evidence.generations.length > 256) throw new Error('Invalid application schema evidence')
    for (const latest of evidence.generations) {
        if (!isRecord(latest) || !active.has(latest.installationId))
            throw new Error(
                'App database rows reference installations outside the backup inventory',
            )
        const recorded = journal.get(latest.installationId)
        if (
            typeof latest.generation !== 'number' ||
            !Number.isSafeInteger(latest.generation) ||
            typeof recorded !== 'number'
        )
            throw new Error('Invalid application schema evidence')
        if (recorded < latest.generation)
            throw new Error('App database generation is ahead of the native installation journal')
    }
}

// LEGACY_HANDOFF_LIMITS.partBytes plus the AES-GCM tag. The runtime image ships this script
// without the web configuration, so a test keeps the restated limit in sync.
export const maximumHandoffPartCiphertextBytes = 262_144 + 16
const maximumHandoffRows = 64
const invalidHandoffParts = () => new Error('Invalid legacy feature handoff parts')

/** Exported handoffs keep exactly their parts 0..n-1; committed handoffs keep none. */
export function assertLegacyHandoffParts(
    handoffs: readonly unknown[],
    parts: readonly unknown[],
): void {
    if (handoffs.length > maximumHandoffRows || parts.length > maximumHandoffRows)
        throw invalidHandoffParts()
    const expected = new Map<string, number>()
    for (const row of handoffs) {
        if (
            !isRecord(row) ||
            typeof row.domain !== 'string' ||
            expected.has(row.domain) ||
            typeof row.installation_id !== 'string' ||
            (row.state !== 'exported' && row.state !== 'committed') ||
            typeof row.part_count !== 'number' ||
            !Number.isSafeInteger(row.part_count) ||
            row.part_count < 0 ||
            row.part_count > 1024
        )
            throw invalidHandoffParts()
        expected.set(row.domain, row.state === 'exported' ? row.part_count : 0)
    }
    for (const summary of parts) {
        if (!isRecord(summary) || typeof summary.domain !== 'string') throw invalidHandoffParts()
        const count = expected.get(summary.domain)
        // Parts of a committed handoff, or without any journal row, give no count here.
        if (
            !count ||
            summary.count !== count ||
            summary.distinct !== count ||
            summary.first !== 0 ||
            summary.last !== count - 1
        )
            throw invalidHandoffParts()
        expected.delete(summary.domain)
    }
    if ([...expected.values()].some((count) => count > 0)) throw invalidHandoffParts()
}

/** Authenticate every stored handoff part with the backed-up key before anything is replaced. */
export async function validateLegacyHandoffParts(sql: SQL, key: Buffer): Promise<void> {
    const handoffs = await sql<unknown[]>`SELECT domain, installation_id, state, part_count
        FROM rentnerproxy.legacy_feature_handoffs ORDER BY domain LIMIT 65`
    const parts = await sql<unknown[]>`SELECT domain, count(*)::integer AS count,
            count(DISTINCT sequence)::integer AS "distinct",
            min(sequence) AS first, max(sequence) AS last
        FROM rentnerproxy.legacy_feature_handoff_parts GROUP BY domain ORDER BY domain LIMIT 65`
    assertLegacyHandoffParts(handoffs, parts)
    let domain = ''
    let sequence = -1
    while (true) {
        const rows = await sql<BackupHandoffPartRow[]>`SELECT stored.domain, stored.sequence,
                stored.sha256, journal.installation_id, stored.iv,
                CASE WHEN octet_length(stored.ciphertext) <= ${maximumHandoffPartCiphertextBytes}
                    THEN stored.ciphertext END AS ciphertext
            FROM rentnerproxy.legacy_feature_handoff_parts stored
            JOIN rentnerproxy.legacy_feature_handoffs journal ON journal.domain = stored.domain
            WHERE (stored.domain, stored.sequence) > (${domain}::varchar, ${sequence}::integer)
            ORDER BY stored.domain, stored.sequence LIMIT 16`
        for (const row of rows) {
            if (!row.ciphertext) throw invalidHandoffParts()
            const plaintext = decryptBackupSecret(
                key,
                Buffer.from(row.ciphertext),
                Buffer.from(row.iv),
                `legacy-feature-handoff:v1:${row.domain}:${row.installation_id}:${row.sequence}:${row.sha256}`,
            )
            if (createHash('sha256').update(plaintext).digest('hex') !== row.sha256)
                throw invalidHandoffParts()
            domain = row.domain
            sequence = row.sequence
        }
        if (rows.length < 16) break
    }
}

export function validateNotificationBackupSecrets(key: Buffer, input: unknown): void {
    try {
        if (typeof input === 'string' && input.length > 2 * 1_024 * 1_024) throw new Error()
        const value: unknown = typeof input === 'string' ? JSON.parse(input) : input
        if (
            !isRecord(value) ||
            JSON.stringify(value).length > 2 * 1_024 * 1_024 ||
            value.version !== 1 ||
            typeof value.revision !== 'number' ||
            !Number.isSafeInteger(value.revision) ||
            value.revision < 0 ||
            value.revision > 4_294_967_295 ||
            typeof value.enabled !== 'boolean' ||
            typeof value.pausedAfterRestore !== 'boolean' ||
            !Array.isArray(value.channels) ||
            value.channels.length > 256
        )
            throw new Error()
        const ids = new Set<string>()
        for (const channel of value.channels) {
            if (
                !isRecord(channel) ||
                typeof channel.id !== 'string' ||
                !/^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/u.test(
                    channel.id,
                ) ||
                ids.has(channel.id) ||
                !isRecord(channel.destination)
            )
                throw new Error()
            ids.add(channel.id)
            const { ciphertext, iv } = channel.destination
            if (
                typeof ciphertext !== 'string' ||
                ciphertext.length > 65_536 ||
                !/^[A-Za-z0-9_-]+$/u.test(ciphertext) ||
                typeof iv !== 'string' ||
                iv.length !== 16 ||
                !/^[A-Za-z0-9_-]+$/u.test(iv)
            )
                throw new Error()
            const encrypted = Buffer.from(ciphertext, 'base64url')
            const nonce = Buffer.from(iv, 'base64url')
            if (
                encrypted.toString('base64url') !== ciphertext ||
                nonce.toString('base64url') !== iv
            )
                throw new Error()
            decryptBackupSecret(
                key,
                encrypted,
                nonce,
                'rentnerproxy:notifications:v1:' + channel.id,
            )
        }
    } catch {
        throw new Error('invalid encrypted notification backup configuration')
    }
}

export async function validateDatabase(
    backupDirectory = '/backup',
    port = 5432,
    crowdSecDirectory = '/tmp/backup-crowdsec',
    socketDirectory?: string,
): Promise<void> {
    const metadata: unknown = JSON.parse(
        await readFile(join(backupDirectory, 'metadata.json'), 'utf8'),
    )
    assertSupportedBackupVersion(metadata)
    if (
        isRecord(metadata) &&
        (metadata.version === APP_AWARE_BACKUP_VERSION ||
            metadata.version === PORTABLE_APP_BACKUP_VERSION)
    ) {
        const portable = metadata.version === PORTABLE_APP_BACKUP_VERSION
        const child = Bun.spawn(
            [
                '/usr/local/bin/rentnerproxy-controller',
                '--app-backup',
                portable ? 'inspect-portable' : 'inspect',
                join(
                    backupDirectory,
                    portable ? '.rentnerproxy-app-state-v2' : '.rentnerproxy-app-state-v1',
                ),
            ],
            { stdout: 'ignore', stderr: 'ignore' },
        )
        if ((await child.exited) !== 0) throw new Error('Invalid application file snapshot')
    }
    const key = Buffer.from(
        (await readFile(join(backupDirectory, 'app-encryption-key'), 'utf8')).trim(),
        'base64',
    )
    const sql = new SQL({
        hostname: '127.0.0.1',
        ...(socketDirectory === undefined ? {} : { path: socketDirectory }),
        port,
        password: '',
        tls: false,
        connectionTimeout: 10,
        database: 'rentnerproxy',
        username: 'postgres',
        max: 1,
    })
    try {
        const migrationsPath = '/opt/rentnerproxy/web/web/drizzle'
        const journal: unknown = JSON.parse(
            await readFile(join(migrationsPath, 'meta/_journal.json'), 'utf8'),
        )
        if (!isMigrationJournal(journal)) {
            throw new Error('backup migration history is incompatible with the target image')
        }
        const rows = await sql<
            BackupMigrationRow[]
        >`select hash, created_at from drizzle.__drizzle_migrations order by id`
        await assertCompatibleBackupHistory(rows, journal, (tag) =>
            readFile(join(migrationsPath, tag + '.sql')),
        )
        const [schema] = await sql<{ present: boolean; handoffs: boolean; parts: boolean }[]>`SELECT
            to_regclass('rentnerproxy.app_runtime_installations') IS NOT NULL AS present,
            to_regclass('rentnerproxy.legacy_feature_handoffs') IS NOT NULL AS handoffs,
            to_regclass('rentnerproxy.legacy_feature_handoff_parts') IS NOT NULL AS parts`
        if (
            typeof schema?.present !== 'boolean' ||
            typeof schema.handoffs !== 'boolean' ||
            schema.parts !== schema.handoffs ||
            (schema.handoffs && !schema.present)
        )
            throw new Error('Invalid application schema evidence')
        const apps =
            isRecord(metadata) &&
            (metadata.version === 5 || metadata.version === PORTABLE_APP_BACKUP_VERSION) &&
            isRecord(metadata.applications)
                ? metadata.applications.installations
                : []
        let appRows: readonly unknown[] = []
        if (schema.present) {
            const [row] = await sql.unsafe<{ evidence: unknown }[]>(
                appDatabaseEvidenceSql(schema.handoffs),
            )
            const evidence = parseAppDatabaseEvidence(row?.evidence)
            assertBackupAppState(apps, evidence)
            appRows = evidence.installations
        } else assertBackupAppRows(apps, appRows)
        if (appRows.length) {
            const [generation] = await sql<{ quiet: boolean }[]>`SELECT
                NOT EXISTS (SELECT FROM rentnerproxy.app_runtime_generations WHERE state <> 'revoked')
                AND NOT EXISTS (SELECT FROM rentnerproxy.app_runtime_pending_secrets) AS quiet`
            if (generation?.quiet !== true) throw new Error('App generation has not retired')
            let installation = ''
            let secret = ''
            while (true) {
                const secrets = await sql<
                    {
                        installation_id: string
                        id: string
                        ciphertext: Uint8Array | null
                        iv: Uint8Array
                    }[]
                >`SELECT installation_id, id, CASE WHEN octet_length(ciphertext) <= 65552 THEN ciphertext END AS ciphertext, iv
                     FROM rentnerproxy.app_runtime_secrets
                     WHERE (installation_id, id) > (${installation}, ${secret})
                     ORDER BY installation_id, id LIMIT 64`
                for (const row of secrets) {
                    if (!row.ciphertext) throw new Error('Invalid application backup secret')
                    decryptBackupSecret(
                        key,
                        Buffer.from(row.ciphertext),
                        Buffer.from(row.iv),
                        `app-runtime-secret:v1:${row.installation_id}:${row.id}`,
                    )
                    installation = row.installation_id
                    secret = row.id
                }
                if (secrets.length < 64) break
            }
        }
        if (schema.handoffs) await validateLegacyHandoffParts(sql, key)
        const factors = await sql<
            BackupTotpSecretRow[]
        >`select user_id, secret_ciphertext, secret_iv from rentnerproxy.user_totp_factors`
        for (const row of factors) {
            decryptBackupSecret(
                key,
                Buffer.from(row.secret_ciphertext),
                Buffer.from(row.secret_iv),
                'rentnerproxy:totp:' + row.user_id,
            )
        }
        const jobs = await sql<
            BackupCertificateJobRow[]
        >`select id, request_ciphertext, request_iv from rentnerproxy.certificate_binding_jobs where request_ciphertext is not null`
        for (const row of jobs) {
            decryptBackupSecret(
                key,
                Buffer.from(row.request_ciphertext),
                Buffer.from(row.request_iv),
                'certificate-binding-job:' + row.id,
            )
        }
        let requiresCrowdSecDatabase = false
        const notificationSettings = await sql<
            { value: unknown }[]
        >`select value from rentnerproxy.system_settings where key = 'notification_configuration_v1'`
        for (const row of notificationSettings) validateNotificationBackupSecrets(key, row.value)
        const settings = await sql<
            BackupCrowdSecSettingRow[]
        >`select value from rentnerproxy.system_settings where key = 'crowdsec_configuration_v1'`
        for (const row of settings) {
            const value: unknown = typeof row.value === 'string' ? JSON.parse(row.value) : row.value
            if (!isRecord(value)) throw new Error('invalid encrypted backup secret')
            requiresCrowdSecDatabase = value.mode === 'managed'
            const apiKey = isRecord(value.external) ? value.external.apiKey : undefined
            if (apiKey) {
                if (
                    !isRecord(apiKey) ||
                    typeof apiKey.ciphertext !== 'string' ||
                    typeof apiKey.iv !== 'string'
                ) {
                    throw new Error('invalid encrypted backup secret')
                }
                decryptBackupSecret(
                    key,
                    Buffer.from(apiKey.ciphertext, 'base64url'),
                    Buffer.from(apiKey.iv, 'base64url'),
                    'crowdsec_configuration_v1:external_api_key',
                )
            }
        }
        await mkdir(crowdSecDirectory, { mode: 0o700 })
        const child = Bun.spawn(
            [
                'tar',
                '--extract',
                '--no-same-owner',
                '--no-same-permissions',
                '--file=' + join(backupDirectory, 'crowdsec-state.tar'),
                '--directory=' + crowdSecDirectory,
            ],
            { stdout: 'ignore', stderr: 'ignore' },
        )
        if ((await child.exited) !== 0) throw new Error('invalid CrowdSec archive')
        const dbPath = join(crowdSecDirectory, 'data/crowdsec.db')
        const dbExists = await stat(dbPath).catch(() => null)
        if (!dbExists && requiresCrowdSecDatabase)
            throw new Error('managed CrowdSec database is missing')
        if (dbExists) {
            const crowdSec = new Database(dbPath, { readonly: true })
            try {
                const result = crowdSec
                    .query<{ quick_check: unknown }, []>('PRAGMA quick_check')
                    .all()
                if (result.length !== 1 || result[0]?.quick_check !== 'ok')
                    throw new Error('invalid CrowdSec database')
            } finally {
                crowdSec.close()
            }
            const credentials: unknown = Bun.YAML.parse(
                await readFile(
                    join(crowdSecDirectory, 'credentials/local_api_credentials.yaml'),
                    'utf8',
                ),
            )
            if (
                !isRecord(credentials) ||
                typeof credentials.url !== 'string' ||
                !['http://127.0.0.1:18080', 'http://127.0.0.1:18080/'].includes(credentials.url) ||
                typeof credentials.login !== 'string' ||
                !credentials.login ||
                typeof credentials.password !== 'string' ||
                !credentials.password
            )
                throw new Error('invalid CrowdSec local credentials')
            const bouncerKey = (
                await readFile(join(crowdSecDirectory, 'bouncer/caddy-bouncer-key'), 'utf8')
            ).trim()
            const legacyKey = /^[a-f0-9]{64}$/u.test(bouncerKey)
            const rawKey = /^[A-Za-z0-9+/]{42}[AEIMQUYcgkosw048]$/u.test(bouncerKey)
            if (!legacyKey && !rawKey) throw new Error('invalid CrowdSec bouncer key')
        }
        console.log('Backup database version and encrypted secrets verified.')
    } finally {
        await sql.close()
    }
}

if (import.meta.main) {
    try {
        await validateDatabase()
    } catch (error) {
        const failures: Readonly<Record<string, string>> = {
            'unsupported backup database version': 'database_version',
            'backup migration history is incompatible with the target image': 'migration_history',
            [unsupportedBackupVersion]: 'database_version',
            'invalid encrypted backup secret': 'application_key',
            'invalid encrypted notification backup configuration': 'application_key',
            'backup application key cannot decrypt persisted secrets': 'application_key',
            'invalid CrowdSec archive': 'crowdsec_archive',
            'managed CrowdSec database is missing': 'crowdsec_database',
            'invalid CrowdSec database': 'crowdsec_database',
            'invalid CrowdSec local credentials': 'crowdsec_credentials',
            'invalid CrowdSec bouncer key': 'crowdsec_credentials',
            'Invalid application file snapshot': 'application_state',
            'Invalid application schema evidence': 'application_state',
            'Invalid application backup inventory': 'application_state',
            'App database identities differ from the native installation journal':
                'application_state',
            'App database rows reference installations outside the backup inventory':
                'application_state',
            'App database generation is ahead of the native installation journal':
                'application_state',
            'App generation has not retired': 'application_state',
            'Invalid application backup secret': 'application_state',
            'Invalid legacy feature handoff parts': 'application_state',
        }
        const reason =
            error instanceof Error
                ? (failures[error.message] ?? 'runtime_validation')
                : 'runtime_validation'
        console.error('BACKUP_VALIDATION=' + reason)
        console.error('Backup database version or application encryption key is incompatible.')
        process.exitCode = 1
    }
}
