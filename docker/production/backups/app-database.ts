import { assertBackupAppRows } from '../../web/validate-backup.ts'
import { rejectAppDatabasesSql } from '../../../scripts/backup/app-state.ts'
import { runMaintenanceProcess } from '../../../scripts/backup/maintenance-process.ts'
import type { BackupMetadata } from '../../../scripts/backup/Types/format.types.ts'

type Inventory = Extract<BackupMetadata, { version: 5 }>['applications']['installations']

export async function checkLiveAppDatabase(expected: Inventory, signal?: AbortSignal) {
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
            maximumOutputBytes: 65_536,
            input: Buffer.from(
                [
                    rejectAppDatabasesSql,
                    "SELECT to_regclass('rentnerproxy.app_runtime_installations') IS NOT NULL AS has_apps",
                    '\\gset',
                    '\\if :has_apps',
                    "DO $check$ BEGIN IF EXISTS (SELECT FROM rentnerproxy.app_runtime_generations WHERE state <> 'revoked') OR EXISTS (SELECT FROM rentnerproxy.app_runtime_pending_secrets) THEN RAISE EXCEPTION 'App generation has not retired'; END IF; END $check$;",
                    'SELECT coalesce(json_agg(t),\'[]\') FROM (SELECT id, app_id AS "appId", uid::int AS uid FROM rentnerproxy.app_runtime_installations LIMIT 257) t;',
                    '\\else',
                    "SELECT '[]';",
                    '\\endif',
                ].join('\n'),
            ),
        },
    )
    if (!result.stopped || result.failed)
        throw new Error('Unsupported live application database state')
    const output = Buffer.from(result.stdout).toString('utf8').trim()
    if (!output.startsWith('1\n')) throw new Error('Invalid live application database evidence')
    const rows: unknown = JSON.parse(output.slice(2))
    if (!Array.isArray(rows)) throw new Error('Invalid application inventory')
    assertBackupAppRows(expected, rows)
}
