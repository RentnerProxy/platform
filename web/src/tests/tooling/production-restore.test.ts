import { describe, expect, test } from 'bun:test'
import { readFile } from 'node:fs/promises'
import { postgresCommand } from '../../../../scripts/production-restore.ts'
import { controllerRestoreCommand } from '../../../../scripts/backup/volume-commands.ts'
import { PORTABLE_APP_BACKUP_VERSION } from '@/config/compatibility.config.ts'
import { NOTIFICATION_SETTINGS_KEY, NOTIFICATION_STATE_KEY } from '@/config/notifications.config.ts'

describe('notification restore pause command contract', () => {
    test('pauses configuration and removes queued state in the actual restore transaction', () => {
        const command = postgresCommand(false)
        const pause = command.indexOf('UPDATE rentnerproxy.system_settings AS settings SET value =')
        const cancel = command.indexOf('DELETE FROM rentnerproxy.system_settings')
        const execute = command.indexOf('psql --host=')
        expect(pause).toBeGreaterThan(command.indexOf('cat "$rendered_sql_path"'))
        expect(cancel).toBeGreaterThan(pause)
        expect(execute).toBeGreaterThan(cancel)
        expect(command).toContain("'{enabled}', 'false'::jsonb")
        expect(command).toContain("'{pausedAfterRestore}', 'true'::jsonb")
        expect(command).toContain("least((normalized.value->>'revision')::bigint + 1, 4294967295)")
        expect(command).toContain("WHERE key = '" + NOTIFICATION_SETTINGS_KEY + "'")
        expect(command).toContain("WHERE key = '" + NOTIFICATION_STATE_KEY + "';")
        expect(command).toContain('--single-transaction --set=ON_ERROR_STOP=1')
        expect(command).toContain('--username=rentnerproxy --dbname=rentnerproxy')
        expect(command).not.toContain('SET channels')
    })

    test('normalizes JSONB objects and serialized objects once before pausing the same row', () => {
        const command = postgresCommand(false)
        const sql = command
            .split("<<'RESTORE_NOTIFICATION_SQL'\n")[1]
            ?.split('\nRESTORE_NOTIFICATION_SQL')[0]
        expect(sql).toBeDefined()
        expect(sql).toContain('WITH normalized AS MATERIALIZED (')
        expect(sql).toContain(
            "SELECT id, CASE jsonb_typeof(value) WHEN 'string' THEN (value #>> '{}')::jsonb ELSE value END AS value",
        )
        expect(sql?.match(/CASE jsonb_typeof\(value\)/gu)).toHaveLength(1)
        expect(sql).toContain('jsonb_set(jsonb_set(jsonb_set(normalized.value,')
        expect(sql).toContain("least((normalized.value->>'revision')::bigint + 1, 4294967295)")
        expect(sql).toContain('FROM normalized WHERE settings.id = normalized.id;')
        expect(sql).not.toContain("(value->>'revision')")
    })

    test('isolated validation keeps notification configuration and queue unchanged', () => {
        const command = postgresCommand(true)
        expect(command).not.toContain(NOTIFICATION_SETTINGS_KEY)
        expect(command).not.toContain(NOTIFICATION_STATE_KEY)
        expect(command).not.toContain('managed_backup_audit_cursor_v1')
        expect(command).not.toContain('RESTORE_NOTIFICATION_SQL')
        expect(command).toContain('data_directory=/tmp/backup-postgres')
        expect(command).toContain('bun /opt/rentnerproxy/web/docker/web/validate-backup.ts')
    })

    test('only the committed restore explicitly rebases the surviving root journal consumer', () => {
        const command = postgresCommand(false)
        const sql = command
            .split("<<'RESTORE_NOTIFICATION_SQL'\n")[1]
            ?.split('\nRESTORE_NOTIFICATION_SQL')[0]
        const statement = sql
            ?.split('\n')
            .find((line) => line.includes('managed_backup_audit_cursor_v1'))
        expect(statement).toBeDefined()
        const serialized = /'([^']+)'::jsonb/u.exec(statement!)?.[1]
        expect(JSON.parse(serialized!)).toEqual({
            storeId: null,
            sequence: 0,
            restorePending: true,
        })
        expect(statement).toContain('ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value')
        expect(command.indexOf(statement!)).toBeGreaterThan(
            command.indexOf('cat "$rendered_sql_path"'),
        )
        expect(command.indexOf(statement!)).toBeLessThan(command.indexOf('psql --host='))
        expect(command).toContain('--single-transaction --set=ON_ERROR_STOP=1')
    })
})

describe('restore target maintenance entrypoint', () => {
    const bash = process.platform === 'win32' ? 'C:/Program Files/Git/bin/bash.exe' : 'bash'
    const entrypoint = readFile(
        new URL('../../../../docker/production/entrypoint.sh', import.meta.url),
        'utf8',
    )

    test('reserves the full web and CrowdSec drain after apps while state services stay up', async () => {
        const shutdown = /^shutdown_children\(\) \{[\s\S]*?^\}/mu.exec(await entrypoint)?.[0]
        expect(shutdown).toBeDefined()
        const result = Bun.spawnSync([
            bash,
            '-c',
            [
                'set -eu',
                'child_names=(web postgres app-manager crowdsec-supervisor); child_pids=(101 102 103 104)',
                'unset SECONDS; SECONDS=0',
                'web_exit=100; crowdsec_exit=100',
                'backup_stop_consumer_phase() { echo "drain-$1"; SECONDS=18; unset "child_names[2]" "child_pids[2]"; }',
                'backup_stop_retained_caddy() { :; }',
                'kill() {',
                '  if [[ $1 == -0 ]]; then',
                '    [[ $2 == 101 && $SECONDS -lt $web_exit || $2 == 104 && $SECONDS -lt $crowdsec_exit ]]; return',
                '  fi',
                '  echo "$1-$2-$SECONDS"',
                '  if [[ $1 == -TERM && $2 == 101 ]]; then web_exit=$((SECONDS + 23)); fi',
                '  if [[ $1 == -TERM && $2 == 104 ]]; then crowdsec_exit=$((SECONDS + 16)); fi',
                '}',
                'sleep() { SECONDS=$((SECONDS + 1)); }',
                'wait() { :; }',
                shutdown!,
                'shutdown_children',
            ].join('\n'),
        ])
        expect(result.exitCode, result.stderr.toString()).toBe(0)
        const signals = result.stdout.toString().trim().split(/\r?\n/u)
        expect(signals[0]).toBe('drain-apps')
        expect(signals).toContain('-TERM-101-18')
        expect(signals).toContain('-TERM-104-18')
        expect(signals).toContain('-TERM-102-41')
        expect(signals.some((line) => line.startsWith('-KILL-104-'))).toBe(false)
    })

    test.each([false, true])(
        'database preparation (failure: %s) never starts application consumers',
        async (failure) => {
            const source = await entrypoint
            const maintenance = /^initialize_restore_target\(\) \{[\s\S]*?^\}/mu.exec(source)?.[0]
            expect(maintenance).toBeDefined()
            const dispatcher = source.slice(source.indexOf('trap shutdown_children EXIT'))
            const steps = [
                'initialize_layout',
                'initialize_secrets',
                'initialize_postgres_data_directory',
                'start_postgres',
                'start_crowdsec_supervisor',
                'start_controller',
                'start_valkey',
                'run_migrations',
                'start_web',
                'monitor_children',
                'shutdown_children',
            ]
            const probes = steps
                .map(
                    (step) =>
                        `${step}() { printf '%s\n' '${step}'; ${failure && step === 'start_postgres' ? 'return 7;' : ':;'} }`,
                )
                .join('\n')
            const script = [
                'set -Eeuo pipefail',
                probes,
                'on_shutdown_signal() { exit 1; }',
                maintenance,
                dispatcher,
            ].join('\n')
            const child = Bun.spawn(
                [
                    bash,
                    '--noprofile',
                    '--norc',
                    '-c',
                    script,
                    'restore-fixture',
                    '--initialize-restore-target',
                ],
                { stdin: 'ignore', stdout: 'pipe', stderr: 'pipe' },
            )
            const [exit, stdout, stderr] = await Promise.all([
                child.exited,
                new Response(child.stdout).text(),
                new Response(child.stderr).text(),
            ])
            expect(stderr).toBe('')
            expect(exit).toBe(failure ? 7 : 0)
            expect(stdout.trim().split('\n')).toEqual([
                'initialize_layout',
                'initialize_secrets',
                'initialize_postgres_data_directory',
                'start_postgres',
                'shutdown_children',
            ])
        },
    )
})

describe('portable application restore commands', () => {
    test('measures capacity from the existing isolated restore only for the portable format', () => {
        const isolated = postgresCommand(true, '/backup', PORTABLE_APP_BACKUP_VERSION)
        const measurement = isolated.indexOf('PORTABLE_RESTORE_CAPACITY=')
        expect(measurement).toBeGreaterThan(isolated.indexOf('validate-backup.ts'))
        expect(isolated).toContain('du --summarize --bytes "$data_directory"')
        expect(isolated).toContain('stat --format=%s "$rendered_sql_path"')
        expect(isolated).toContain('stat --format=%s "$restore_sql_path"')
        expect(postgresCommand(true, '/backup', true)).not.toContain('PORTABLE_RESTORE_CAPACITY=')
        expect(postgresCommand(true)).not.toContain('PORTABLE_RESTORE_CAPACITY=')
    })

    test('verifies the package before touching the target and passes explicit resume evidence', () => {
        const backupId = 'a'.repeat(64)
        const version = PORTABLE_APP_BACKUP_VERSION
        const preflight = postgresCommand('inventory', '/backup', version, backupId)
        const resumed = postgresCommand('inventory', '/backup', version, backupId, true)
        expect(
            preflight.indexOf('verify-portable /backup/.rentnerproxy-app-state-v2'),
        ).toBeLessThan(preflight.indexOf('postgres -D'))
        expect(preflight).toContain(
            '--check-portable-app-restore-inventory /backup ' + backupId + ' false',
        )
        expect(resumed).toContain(
            '--check-portable-app-restore-inventory /backup ' + backupId + ' true',
        )
        expect(resumed).toContain('test -s /var/lib/rentnerproxy/postgres-data/PG_VERSION')
        expect(preflight).not.toContain('restore-portable')
        expect(() => postgresCommand('inventory', '/backup', version)).toThrow()
    })

    test('publishes the app state only with ready, protected PostgreSQL sockets', () => {
        const version = PORTABLE_APP_BACKUP_VERSION
        const command = postgresCommand('portable-apps', '/backup', version)
        expect(command).toContain(
            'unix_socket_directories="$socket_directory",/run/rentnerproxy/app-db',
        )
        expect(command).toContain('hba_file=/usr/local/etc/rentnerproxy/pg_hba.conf')
        expect(command).toContain('ident_file=/usr/local/etc/rentnerproxy/pg_ident.conf')
        expect(
            command.indexOf('restore-portable /backup/.rentnerproxy-app-state-v2'),
        ).toBeGreaterThan(command.indexOf('"$ready"'))
        expect(command).not.toContain('postgres.dump')
        expect(controllerRestoreCommand(version)).toContain('--exclude=.rentnerproxy-app-state-v2')
    })
})

describe('restored application state check', () => {
    test.each([false, true, PORTABLE_APP_BACKUP_VERSION] as const)(
        'compares the applied database with the verified backup (app-aware: %s)',
        (appAware) => {
            const backupId = 'c'.repeat(64)
            const command = postgresCommand('restored', '/backup', appAware, backupId)
            const ready = command.indexOf('"$ready"')
            const check = command.indexOf(
                'backup-export.js --check-restored-app-inventory /backup ' + backupId,
            )
            expect(ready).toBeGreaterThan(command.indexOf('test -s "$data_directory/PG_VERSION"'))
            expect(check).toBeGreaterThan(ready)
            expect(command).toContain('data_directory=/var/lib/rentnerproxy/postgres-data')
            expect(command).not.toContain('pg_restore')
            expect(command).not.toContain('createdb')
            expect(command).not.toContain('--app-backup')
            expect(command).not.toContain('validate-backup.ts')
        },
    )

    test('requires the verified backup identity', () => {
        expect(() => postgresCommand('restored', '/backup', true)).toThrow(
            'Missing verified app backup identity',
        )
        expect(() => postgresCommand('restored', '/backup', false, 'not-a-digest')).toThrow(
            'Missing verified app backup identity',
        )
    })
})
