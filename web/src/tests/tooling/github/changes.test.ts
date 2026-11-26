import { mkdir, mkdtemp, rename, rm, writeFile, readFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { describe, expect, test } from 'bun:test'
import {
    selectChecks,
    detectChanges,
    deferRuntime,
} from '../../../../../.github/scripts/ci/changes.ts'

function git(cwd: string, ...args: string[]): string {
    const result = Bun.spawnSync(['git', ...args], {
        cwd,
        env: {
            ...process.env,
            GIT_CONFIG_NOSYSTEM: '1',
            GIT_CONFIG_GLOBAL: process.platform === 'win32' ? 'NUL' : '/dev/null',
            GIT_AUTHOR_NAME: 'CI Fixture',
            GIT_AUTHOR_EMAIL: 'fixture@example.invalid',
            GIT_COMMITTER_NAME: 'CI Fixture',
            GIT_COMMITTER_EMAIL: 'fixture@example.invalid',
        },
        stdout: 'pipe',
        stderr: 'pipe',
    })
    if (result.exitCode !== 0) throw new Error(result.stderr.toString())
    return result.stdout.toString().trim()
}

async function fixture(run: (directory: string, base: string) => Promise<void>) {
    const directory = await mkdtemp(join(tmpdir(), 'rentnerproxy-caddy-changes-'))
    try {
        git(directory, 'init', '--quiet')
        await mkdir(join(directory, 'core/caddy-modules/responsecache'), { recursive: true })
        await writeFile(join(directory, 'README.md'), 'fixture documentation')
        await writeFile(
            join(directory, 'core/caddy-modules/responsecache/cache.go'),
            'fixture module',
        )
        git(directory, 'add', '.')
        git(directory, 'commit', '--quiet', '-m', 'fixture base')
        await run(directory, git(directory, 'rev-parse', 'HEAD'))
    } finally {
        await rm(directory, { recursive: true, force: true })
    }
}

function commit(directory: string): string {
    git(directory, 'add', '--all')
    git(directory, 'commit', '--quiet', '-m', 'fixture change')
    return git(directory, 'rev-parse', 'HEAD')
}

describe('affected CI selection', () => {
    test('documentation avoids heavy checks and unknown ownership runs the full suite', () => {
        expect(Object.values(selectChecks(['README.md', 'docs/architecture.md']))).toEqual(
            Array(12).fill(false),
        )
        expect(Object.values(selectChecks(['new-area/input']))).toEqual(Array(12).fill(true))
        expect(selectChecks(['package.json']).full).toBe(true)
        expect(selectChecks(['tsconfig.scripts.json']).full).toBe(true)
    })
    test('client presentation selects web without native and runtime tests', () => {
        const checks = selectChecks(['web/src/features/Hosts/Components/HostCard.tsx'])
        expect(checks.web).toBe(true)
        expect(checks.build_web).toBe(true)
        for (const name of ['rust', 'go', 'caddy', 'runtime'] as const)
            expect(checks[name]).toBe(false)
    })
    test.each([
        'web/src/features/Hosts/middleware.ts',
        'web/src/routes/api/session.ts',
        'web/src/features/Hosts/validation.ts',
        'web/src/shared/contract.ts',
        'web/src/db/schema.ts',
    ])('%s retains runtime checks', (path) => {
        expect(selectChecks([path]).runtime).toBe(true)
    })
    test('language and automation ownership remain independent', () => {
        expect(selectChecks(['core/src/main.rs'])).toMatchObject({
            rust: true,
            build_core: true,
            runtime: true,
            web: false,
            go: false,
        })
        expect(selectChecks(['core/caddy-modules/responsecache/cache.go'])).toMatchObject({
            go: true,
            caddy: true,
            runtime: true,
            rust: false,
        })
        expect(selectChecks(['.github/workflows/codeql.yml'])).toMatchObject({
            actions: true,
            web: true,
            scripts: true,
            rust: true,
        })
        expect(selectChecks(['.github/scripts/ci/go-coverage-check.go']).go).toBe(true)
        expect(selectChecks(['docker/tooling/buildinfo/verify.go']).go).toBe(true)
        expect(selectChecks(['.github/scripts/ci/changes.ts']).full).toBe(true)
    })
    test.each([
        'core/src/app_manager.rs',
        'core/src/app_install/catalog.rs',
        'core/tests/private/app_manager/lifecycle/published_greeting.rs',
        'core/tests/fixtures/app-manager/app.rs',
        'core/Cargo.lock',
        'core/rust-toolchain.toml',
        'docker/production/Dockerfile',
        'docker-compose.yml',
        'scripts/backup/portable-app-archive.ts',
        'scripts/production-restore.ts',
        'web/src/lib/AppCatalog/contract.ts',
        'web/src/tests/fixtures/app-runtime-reference/package.json',
        '.github/workflows/app-runtime-reference.yml',
        '.github/scripts/ci/fixtures/app-ipc-boundaries.sh',
    ])('%s selects the native app runtime reference', (path) => {
        expect(selectChecks([path]).app_runtime).toBe(true)
    })
    test.each([
        'core/src/main.rs',
        'core/tests/private/backup_envelope.rs',
        'web/src/features/Hosts/middleware.ts',
        'scripts/coverage/report.ts',
        '.github/workflows/codeql.yml',
        '.github/scripts/ci/rust-coverage.sh',
    ])('%s leaves the native app runtime reference unaffected', (path) => {
        expect(selectChecks([path]).app_runtime).toBe(false)
    })
    test.each([
        'scripts/assets/prepare-country-flags.ts',
        'scripts/assets/download-geoip.ts',
        'scripts/assets/Types/download-geoip.types.ts',
    ])('%s retains production build and integration verification', (path) => {
        expect(selectChecks([path])).toMatchObject({ build_web: true, runtime: true })
    })
    test.each([
        '.github/scripts/security/scan-image.sh',
        '.github/scripts/security/extract-image-input.sh',
        '.github/scripts/security/install-dependency-tools.sh',
    ])('%s retains source and production image assessment', (path) => {
        expect(selectChecks([path])).toMatchObject({ dependencies: true, runtime: true })
    })
    test.each([
        'scripts/coverage/coverage.config.ts',
        'scripts/coverage/summary.ts',
        'scripts/coverage/report.ts',
        'scripts/coverage/Types/report.types.ts',
    ])('%s verifies the shared coverage contract against every producer', (path) => {
        expect(selectChecks([path])).toMatchObject({ web: true, go: true, rust: true })
    })
    test('manual, invalid and absent revisions select full verification', () => {
        expect(detectChanges('workflow_dispatch', '', '').full).toBe(true)
        expect(detectChanges('pull_request', '', '').full).toBe(true)
        expect(detectChanges('push', '0'.repeat(40), 'a'.repeat(40)).full).toBe(true)
    })
    test('PR uses merge base while push includes changes from the previous tip', async () => {
        await fixture(async (directory, base) => {
            await writeFile(join(directory, 'README.md'), 'PR documentation')
            const head = commit(directory)
            git(directory, 'checkout', '--detach', base)
            await writeFile(join(directory, 'core/base-only.rs'), 'base change')
            const advanced = commit(directory)
            expect(detectChanges('pull_request', advanced, head, directory).full).toBe(false)
            expect(detectChanges('pull_request', advanced, head, directory).rust).toBe(false)
            expect(detectChanges('merge_group', advanced, head, directory).rust).toBe(false)
            expect(detectChanges('push', advanced, head, directory).rust).toBe(true)
        })
    })
    test('only opted-in pull requests defer affected runtime verification to the merge queue', () => {
        const runtime = selectChecks(['core/src/main.rs'])
        expect(deferRuntime('pull_request', 'true', runtime)).toEqual({
            selected: { ...runtime, runtime: false, full: false },
            deferred: true,
        })
        for (const [event, requested] of [
            ['pull_request', 'false'],
            ['pull_request', undefined],
            ['merge_group', 'true'],
            ['push', 'true'],
            ['workflow_dispatch', 'true'],
        ] as const)
            expect(deferRuntime(event, requested, runtime)).toEqual({
                selected: runtime,
                deferred: false,
            })
        const documentation = selectChecks(['README.md'])
        expect(deferRuntime('pull_request', 'true', documentation).deferred).toBe(false)
    })
    test('deletion and rename retain old runtime input, including unusual path characters', async () => {
        await fixture(async (directory, base) => {
            await mkdir(join(directory, 'docs'))
            await rename(
                join(directory, 'core/caddy-modules/responsecache/cache.go'),
                join(directory, 'docs/cache name.md'),
            )
            expect(detectChanges('push', base, commit(directory), directory).caddy).toBe(true)
            await writeFile(join(directory, 'core/new input.rs'), 'new')
            const added = commit(directory)
            await rm(join(directory, 'core/new input.rs'))
            expect(detectChanges('push', added, commit(directory), directory).rust).toBe(true)
        })
    })
    test('unresolvable comparison fails closed', async () => {
        await fixture(async (directory, base) => {
            expect(() => detectChanges('push', 'a'.repeat(40), base, directory)).toThrow(
                'Cannot resolve',
            )
        })
    })
})

test('required CI jobs guard detector failures and preserve successful unaffected statuses', async () => {
    const workflow = Bun.YAML.parse(
        await readFile(new URL('../../../../../.github/workflows/ci.yml', import.meta.url), 'utf8'),
    ) as {
        jobs: Record<
            string,
            {
                name: string
                if?: string
                needs?: string | string[]
                steps?: { name: string; run?: string; env?: Record<string, string>; if?: string }[]
            }
        >
    }
    for (const id of ['lint', 'typecheck', 'web-tests', 'rust', 'build', 'caddy-response-cache']) {
        const job = workflow.jobs[id]!
        expect(job.needs).toBe('changes')
        expect(job.if).toBe('${{ !cancelled() }}')
        expect(job.steps?.[0]?.env?.DETECTION_RESULT).toBe('${{ needs.changes.result }}')
        expect(job.steps?.[0]?.run).toContain('test "$DETECTION_RESULT" = success')
        expect(job.steps?.[1]?.name).toBe('Explain unaffected check')
    }
    // Fuzz tests run inside Web Tests; no pass-through runner restates that result.
    expect(workflow.jobs.fuzz).toBeUndefined()
    expect(workflow.jobs['full-verification']?.if).toContain("needs.changes.outputs.full == 'true'")
    expect(workflow.jobs.coverage?.steps?.some((step) => step.run?.includes('--producers'))).toBe(
        true,
    )
})

test('the native app runtime reference reports on every pull request and runs only when affected', async () => {
    const workflow = Bun.YAML.parse(
        await readFile(
            new URL('../../../../../.github/workflows/app-runtime-reference.yml', import.meta.url),
            'utf8',
        ),
    ) as {
        on: { pull_request: unknown; push: { branches: string[]; paths?: string[] } }
        jobs: Record<
            string,
            {
                uses?: string
                if?: string
                needs?: string
                env?: Record<string, string>
                steps?: { name: string; run?: string; env?: Record<string, string>; if?: string }[]
            }
        >
    }
    // A path filter would leave the required check pending for unrelated pull requests.
    expect(workflow.on.pull_request).toBeNull()
    expect(workflow.on.push).toEqual({ branches: ['main'] })
    expect(workflow.jobs.changes?.uses).toBe('./.github/workflows/detect-changes.yml')
    const native = workflow.jobs.native!
    expect(native.needs).toBe('changes')
    expect(native.if).toBe('${{ !cancelled() }}')
    expect(native.env?.RUN_CHECK).toBe("${{ needs.changes.outputs.app_runtime != 'false' }}")
    const [detection, unaffected, ...work] = native.steps ?? []
    expect(detection?.env?.CHANGE_RESULT).toBe('${{ needs.changes.result }}')
    expect(detection?.run).toContain('test "$CHANGE_RESULT" = success')
    expect(unaffected?.if).toBe("env.RUN_CHECK != 'true'")
    expect(work.length).toBeGreaterThan(10)
    for (const step of work) expect(step.if).toStartWith("env.RUN_CHECK == 'true'")
    expect(work.some((step) => step.run?.includes('app-ipc-boundaries.sh'))).toBe(true)
})

test('test-only web changes receive native type checking without building production assets', async () => {
    const selected = selectChecks(['web/src/tests/features/Hosts/host.test.tsx'])
    expect(selected.web).toBe(true)
    expect(selected.build_web).toBe(false)
    const workflow = Bun.YAML.parse(
        await readFile(new URL('../../../../../.github/workflows/ci.yml', import.meta.url), 'utf8'),
    ) as { jobs: Record<string, { steps: { name: string; if?: string; run?: string }[] }> }
    const typecheck = workflow.jobs.lint?.steps.find((step) =>
        step.run?.includes('--check --tsconfig-override tsconfig.json'),
    )
    expect(typecheck?.if).toBe(
        "${{ needs.changes.outputs.web == 'true' && needs.changes.outputs.build_web != 'true' }}",
    )
    expect(typecheck?.run).toBe('bun --no-env-file --check --tsconfig-override tsconfig.json')
})
