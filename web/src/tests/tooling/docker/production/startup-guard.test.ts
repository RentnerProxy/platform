import { expect, test } from 'bun:test'
import { readFile } from 'node:fs/promises'

import { DATABASE_NEWER_THAN_IMAGE_EXIT_CODE } from '@/db/migrate.ts'

const entrypoint = new URL('../../../../../../docker/production/entrypoint.sh', import.meta.url)

/** Copy the startup guard out of the entrypoint so it runs against fixture children only. */
async function startupGuard(): Promise<string> {
    const source = await readFile(entrypoint, 'utf8')
    const pieces = [
        /^database_newer_than_image_status=\d+$/mu,
        /^hold_proxy_only\(\) \{[\s\S]*?^\}$/mu,
        /^migrate_or_hold_proxy\(\) \{[\s\S]*?^\}$/mu,
    ].map((pattern) => {
        const match = pattern.exec(source)
        if (!match) throw new Error('entrypoint startup guard changed shape: ' + String(pattern))
        return match[0]
    })
    return pieces.join('\n')
}

async function boot(migrationStatus: number) {
    const script = [
        'set -Eeuo pipefail',
        'log() { printf \'LOG %s\\n\' "$*"; }',
        'fatal() { printf \'FATAL %s\\n\' "$*"; exit 1; }',
        "assert_children_running() { printf 'CHECK\\n'; }",
        // The guard holds forever; the first sleep proves it stayed after checking children.
        'sleep() { printf \'HELD %s\\n\' "$supervisor_phase"; exit 3; }',
        `run_migrations() { return ${migrationStatus}; }`,
        await startupGuard(),
        'migrate_or_hold_proxy',
        "printf 'WEB STARTED\\n'",
    ].join('\n')
    const child = Bun.spawn(['bash', '-c', script], { stdout: 'pipe', stderr: 'pipe' })
    const [stdout, exitCode] = await Promise.all([new Response(child.stdout).text(), child.exited])
    return { stdout, exitCode }
}

test('the entrypoint status for a newer database matches the migration exit code', async () => {
    expect(await startupGuard()).toContain(
        `database_newer_than_image_status=${DATABASE_NEWER_THAN_IMAGE_EXIT_CODE}`,
    )
})

test.skipIf(Bun.which('bash') === null)(
    'a newer database keeps only the proxy running while other migration failures stop the appliance',
    async () => {
        const migrated = await boot(0)
        expect(migrated).toEqual({ stdout: 'WEB STARTED\n', exitCode: 0 })

        const newer = await boot(DATABASE_NEWER_THAN_IMAGE_EXIT_CODE)
        expect(newer.exitCode).toBe(3)
        expect(newer.stdout).toContain('LOG database is newer than this image')
        expect(newer.stdout).toContain('CHECK\nHELD proxy-only\n')
        expect(newer.stdout).not.toContain('WEB STARTED')

        const failed = await boot(1)
        expect(failed.exitCode).toBe(1)
        expect(failed.stdout).toContain('FATAL database migrations failed with status 1')
        expect(failed.stdout).not.toContain('WEB STARTED')
    },
)

/** Run the entrypoint's child supervision with one exited and one running fixture child. */
async function supervise(exited: string, running: string) {
    const source = await readFile(entrypoint, 'utf8')
    const supervision = /^assert_children_running\(\) \{[\s\S]*?^\}$/mu.exec(source)
    if (!supervision) throw new Error('entrypoint child supervision changed shape')
    const script = [
        'set -Eeuo pipefail',
        'log() { printf \'LOG %s\\n\' "$*"; }',
        'fatal() { printf \'FATAL %s\\n\' "$*"; exit 1; }',
        "recover_web() { printf 'RECOVER\\n'; }",
        'child_pids=()',
        'child_names=()',
        'trap \'kill "${child_pids[@]}" 2>/dev/null || true\' EXIT',
        'true &',
        'child_pids+=("$!")',
        'child_names+=(' + exited + ')',
        // Reap the exited child first, so the supervision cannot see it as a running zombie.
        'wait "${child_pids[0]}"',
        'sleep 30 >/dev/null 2>&1 &',
        'child_pids+=("$!")',
        'child_names+=(' + running + ')',
        supervision[0],
        'assert_children_running',
        'printf \'RUNNING %s\\n\' "${child_names[*]}"',
    ].join('\n')
    const child = Bun.spawn(['bash', '-c', script], { stdout: 'pipe', stderr: 'pipe' })
    const [stdout, exitCode] = await Promise.all([new Response(child.stdout).text(), child.exited])
    return { stdout, exitCode }
}

test.skipIf(Bun.which('bash') === null)(
    'a stopped app manager leaves the proxy and administration running, another owned child does not',
    async () => {
        // An older image whose app manager refuses newer app state takes this path.
        expect(await supervise('app-manager', 'controller')).toEqual({
            stdout: 'LOG app manager stopped; installed app operations are unavailable\nRUNNING controller\n',
            exitCode: 0,
        })
        expect(await supervise('controller', 'app-manager')).toEqual({
            stdout: 'FATAL controller stopped unexpectedly\n',
            exitCode: 1,
        })
    },
)
