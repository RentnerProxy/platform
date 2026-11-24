import {
    appDatabaseEvidenceSql,
    assertBackupAppRows,
    assertBackupAppState,
    parseAppDatabaseEvidence,
} from '../../web/validate-backup.ts'
import { rejectAppDatabasesSql } from '../../../scripts/backup/app-state.ts'
import { runMaintenanceProcess } from '../../../scripts/backup/maintenance-process.ts'
import type { BackupMetadata } from '../../../scripts/backup/Types/format.types.ts'

type Inventory = Exclude<BackupMetadata, { version: 4 }>['applications']['installations']

const rejectPortableAppDatabasesSql = `SELECT 1 / (NOT EXISTS (
    SELECT FROM pg_catalog.pg_database
    WHERE starts_with(datname, 'rp_app_') OR starts_with(datname, 'rp_migrate_')
    UNION ALL SELECT FROM pg_catalog.pg_roles
    WHERE starts_with(rolname, 'rp_app_') OR starts_with(rolname, 'rp_migrate_')
))::integer;`

/**
 * Compare the live app rows with an installation inventory. The `installations` scope checks
 * identities only, for a target whose database the restore will replace. The `journal` scope also
 * requires every dependent row and recorded generation to match, for a database that the inventory
 * governs: at capture, on a resumed portable restore and after a restore has been applied.
 */
export async function checkLiveAppDatabase(
    expected: Inventory,
    signal?: AbortSignal,
    mode: 'legacy' | 'portable' | 'portable-fresh' | 'portable-resume' = 'legacy',
    scope: 'installations' | 'journal' = 'installations',
) {
    const result = await runMaintenanceProcess(
        [
            'gosu',
            'postgres',
            'psql',
            '--no-psqlrc',
            '--no-password',
            '--quiet',
            '--tuples-only',
            '--no-align',
            '--set=ON_ERROR_STOP=1',
            '--host=/var/run/postgresql',
            '--username=postgres',
            '--dbname=rentnerproxy',
        ],
        {
            cwd: '/',
            timeoutMs: 30_000,
            signal,
            maximumOutputBytes: 512 * 1024,
            input: Buffer.from(
                [
                    mode === 'legacy'
                        ? rejectAppDatabasesSql
                        : mode === 'portable-fresh'
                          ? rejectPortableAppDatabasesSql
                          : 'SELECT 1;',
                    "SELECT to_regclass('rentnerproxy.app_runtime_installations') IS NOT NULL AS has_apps, to_regclass('rentnerproxy.legacy_feature_handoffs') IS NOT NULL AS has_handoffs",
                    '\\gset',
                    '\\if :has_apps',
                    "DO $check$ BEGIN IF EXISTS (SELECT FROM rentnerproxy.app_runtime_generations WHERE state <> 'revoked') OR EXISTS (SELECT FROM rentnerproxy.app_runtime_pending_secrets) THEN RAISE EXCEPTION 'App generation has not retired'; END IF; END $check$;",
                    '\\if :has_handoffs',
                    appDatabaseEvidenceSql(true) + ';',
                    '\\else',
                    appDatabaseEvidenceSql(false) + ';',
                    '\\endif',
                    '\\else',
                    `SELECT '{"installations":[],"references":[],"generations":[]}';`,
                    '\\endif',
                ].join('\n'),
            ),
        },
    )
    if (!result.stopped || result.failed)
        throw new Error('Unsupported live application database state')
    const output = Buffer.from(result.stdout).toString('utf8').trim()
    if (!output.startsWith('1\n')) throw new Error('Invalid live application database evidence')
    const evidence = parseAppDatabaseEvidence(output.slice(2))
    // A resumed portable restore may stop before its database was replaced.
    if (
        mode === 'portable-resume' &&
        [evidence.installations, evidence.references, evidence.generations].every(
            (rows) => rows.length === 0,
        )
    )
        return
    if (scope === 'journal') assertBackupAppState(expected, evidence)
    else assertBackupAppRows(expected, evidence.installations)
}
