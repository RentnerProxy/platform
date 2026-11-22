import { describe, expect, test } from 'bun:test'
import { YAML } from 'bun'
import { readFile } from 'node:fs/promises'
import {
    arrayPages,
    createGitHubRequest,
    GitHubRequestError,
    record,
} from '../../../../../.github/scripts/automation/github.ts'
import { maintainPullRequests } from '../../../../../.github/scripts/automation/pr-maintenance.ts'
import type { GitHubRequest } from '../../../../../.github/scripts/automation/Types/pr-maintenance.types.ts'

const repository = 'RentnerProxy/RentnerProxy'
const prefix = '/repos/rentnerproxy/rentnerproxy'
const headSha = 'a'.repeat(40)
const baseSha = 'b'.repeat(40)
const bot = { login: 'dependabot[bot]', id: 49699333, type: 'Bot' }
const head = (number: number) => number.toString(16).padStart(40, '0')

function fixture() {
    const pull = {
        number: 42,
        state: 'open',
        draft: false,
        mergeable: true as boolean | null,
        maintainer_can_modify: true,
        user: { ...bot },
        title: 'chore(deps): bump example',
        labels: [{ name: 'dependencies' }],
        base: { ref: 'main', sha: baseSha, repo: { full_name: repository } },
        head: {
            ref: 'dependabot/bun/example-1.2.4',
            sha: headSha,
            repo: { full_name: repository },
        },
        commits: 1,
        changed_files: 1,
    }
    const commits = [
        {
            sha: headSha,
            parents: [{ sha: 'c'.repeat(40) }],
            author: bot,
            committer: { login: 'web-flow', id: 19864447 },
            commit: {
                author: {
                    name: 'dependabot[bot]',
                    email: '49699333+dependabot[bot]@users.noreply.github.com',
                },
                committer: { name: 'GitHub', email: 'noreply@github.com' },
                verification: { verified: true, reason: 'valid' },
                message: `chore(deps): bump example

Bumps example from 1.2.3 to 1.2.4.

---
updated-dependencies:
- dependency-name: example
  dependency-version: 1.2.4
  update-type: version-update:semver-patch
...
`,
            },
        },
    ]
    const graph = {
        headRefOid: headSha,
        baseRefOid: baseSha,
        state: 'OPEN',
        isDraft: false,
        reviewDecision: 'REVIEW_REQUIRED',
        reviewThreads: {
            nodes: [] as { isResolved: boolean }[],
            pageInfo: { hasNextPage: false },
        },
        commits: { nodes: [{ commit: { oid: headSha, statusCheckRollup: { state: 'SUCCESS' } } }] },
    }
    const settings = {
        behind: 0,
        headChanged: false,
        breakingLabelAdded: false,
        changeOnClose: '' as '' | 'head' | 'security',
        graphErrors: false,
        refusal: 0,
        reads: 0,
    }
    const calls: { method: string; path: string; body: unknown }[] = []
    const files: Record<string, unknown>[] = [{ filename: 'package.json', status: 'modified' }]
    const request: GitHubRequest = (method, path, body) => {
        calls.push({ method, path, body })
        if (method === 'PATCH') {
            const state = record(body).state
            const value = { ...structuredClone(pull), state }
            if (state === 'closed' && settings.changeOnClose === 'head')
                value.head.sha = 'd'.repeat(40)
            if (state === 'closed' && settings.changeOnClose === 'security')
                value.labels.push({ name: 'security' })
            return Promise.resolve(value)
        }
        if (method === 'PUT') {
            if (settings.refusal) throw new GitHubRequestError(settings.refusal)
            return Promise.resolve({ merged: true })
        }
        if (path.startsWith(`${prefix}/pulls?`)) return Promise.resolve([{ number: pull.number }])
        if (path === `${prefix}/pulls/42`) {
            settings.reads++
            const value = structuredClone(pull)
            if (settings.headChanged && settings.reads > 1) value.head.sha = 'd'.repeat(40)
            if (settings.breakingLabelAdded && settings.reads > 1) {
                value.labels.push({ name: 'breaking-change' })
            }
            return Promise.resolve(value)
        }
        if (path === `${prefix}/git/ref/heads/main`) {
            return Promise.resolve({ object: { sha: baseSha } })
        }
        if (path.startsWith(`${prefix}/compare/`)) {
            return Promise.resolve({ ahead_by: settings.behind })
        }
        if (path.includes('/commits?')) return Promise.resolve(commits)
        if (path.includes('/files?')) {
            return Promise.resolve(files)
        }
        if (path === '/graphql') {
            if (settings.graphErrors) return Promise.resolve({ errors: [{ message: 'denied' }] })
            return Promise.resolve({ data: { repository: { pullRequest: graph } } })
        }
        throw new Error(`Unexpected test request: ${method} ${path}`)
    }
    const writes = () => calls.filter((call) => call.method === 'PUT' || call.method === 'PATCH')
    const run = (dryRun = false) => maintainPullRequests(request, { repository, dryRun })
    return { pull, commits, files, graph, settings, calls, request, writes, run }
}

describe('Docker digest-only updates', () => {
    const oldDigest = 'a'.repeat(64)
    const newDigest = 'b'.repeat(64)

    function dockerUpdate(previousTag = '1.0.0', nextTag = previousTag) {
        const state = fixture()
        state.pull.head.ref = 'dependabot/docker/example'
        state.settings.behind = 1
        state.files[0] = {
            filename: 'Dockerfile',
            status: 'modified',
            additions: 1,
            deletions: 1,
            patch: `@@ -1 +1 @@\n-FROM example:${previousTag}@sha256:${oldDigest}\n+FROM example:${nextTag}@sha256:${newDigest}`,
        }
        return state
    }

    test('closes an unchanged Docker tag before updating the branch or waiting for CI', async () => {
        const state = dockerUpdate()
        expect((await state.run())[0]?.action).toBe('closed')
        expect(state.writes()).toEqual([
            { method: 'PATCH', path: `${prefix}/pulls/42`, body: { state: 'closed' } },
        ])
    })

    test('reports a quoted Compose digest refresh in a dry run', async () => {
        const state = dockerUpdate()
        state.pull.head.ref = 'dependabot/docker-compose/example'
        state.files[0] = {
            ...state.files[0],
            filename: 'docker-compose.yml',
            patch: `@@ -1 +1 @@\n-    image: 'example:1.0.0@sha256:${oldDigest}'\n+    image: 'example:1.0.0@sha256:${newDigest}'`,
        }
        expect((await state.run(true))[0]?.action).toBe('would-close')
        expect(state.writes()).toHaveLength(0)
    })

    test('preserves version changes, including patch releases with a new digest', async () => {
        const state = dockerUpdate('1.0.0', '1.0.1')
        expect((await state.run())[0]?.action).toBe('update-requested')
        expect(state.writes()[0]?.method).toBe('PUT')
    })

    test('preserves security-labeled updates and updates with incomplete diffs', async () => {
        const securityUpdate = dockerUpdate()
        securityUpdate.pull.labels.push({ name: 'security' })
        expect((await securityUpdate.run())[0]?.action).toBe('update-requested')
        const incomplete = dockerUpdate()
        incomplete.files[0]!.deletions = 2
        expect((await incomplete.run())[0]?.action).toBe('update-requested')
    })

    test('leaves a PR open if its head changes during validation', async () => {
        const state = dockerUpdate()
        state.settings.headChanged = true
        expect((await state.run())[0]?.action).toBe('skipped')
        expect(state.writes()).toHaveLength(0)
    })

    test.each(['head', 'security'] as const)(
        'reopens a PR when its %s changes during closure',
        async (change) => {
            const state = dockerUpdate()
            state.settings.changeOnClose = change
            expect((await state.run())[0]?.action).toBe('skipped')
            expect(state.writes()).toEqual([
                { method: 'PATCH', path: `${prefix}/pulls/42`, body: { state: 'closed' } },
                { method: 'PATCH', path: `${prefix}/pulls/42`, body: { state: 'open' } },
            ])
        },
    )
})

describe('PR branch maintenance', () => {
    test('updates stale human and draft branches with the expected head and never merges them', async () => {
        const state = fixture()
        state.settings.behind = 2
        state.pull.user.login = 'human'
        state.pull.draft = true
        expect((await state.run())[0]?.action).toBe('update-requested')
        expect(state.writes()).toEqual([
            {
                method: 'PUT',
                path: `${prefix}/pulls/42/update-branch`,
                body: { expected_head_sha: headSha },
            },
        ])
        expect(state.calls.some((call) => call.path === '/graphql')).toBe(false)
    })

    test('leaves conflicts untouched', async () => {
        const state = fixture()
        state.settings.behind = 2
        state.pull.mergeable = false
        expect((await state.run())[0]?.reason).toContain('conflict')
        expect(state.writes()).toHaveLength(0)
    })

    test('respects fork maintainer permissions', async () => {
        const state = fixture()
        state.settings.behind = 2
        state.pull.head.repo.full_name = 'contributor/RentnerProxy'
        state.pull.maintainer_can_modify = false
        expect((await state.run())[0]?.reason).toContain('Fork owner')
        expect(state.writes()).toHaveLength(0)
    })

    test('attempts allowed fork updates and reports API permission refusals without forcing', async () => {
        const state = fixture()
        state.settings.behind = 2
        state.pull.head.repo.full_name = 'contributor/RentnerProxy'
        state.settings.refusal = 403
        expect((await state.run())[0]?.action).toBe('skipped')
        expect(state.writes()[0]?.path).toEndWith('/update-branch')
    })

    test('does not auto-merge current human PRs', async () => {
        const state = fixture()
        state.pull.user.login = 'human'
        expect((await state.run())[0]?.action).toBe('skipped')
        expect(state.writes()).toHaveLength(0)
    })

    test('dry runs never update branches', async () => {
        const state = fixture()
        state.settings.behind = 1
        expect((await state.run(true))[0]?.action).toBe('would-update')
        expect(state.writes()).toHaveLength(0)
    })
})

describe('Dependabot merge orchestration', () => {
    test('squash-merges only the validated head after successful current CI', async () => {
        const state = fixture()
        expect((await state.run())[0]?.action).toBe('merged')
        expect(state.writes()).toEqual([
            {
                method: 'PUT',
                path: `${prefix}/pulls/42/merge`,
                body: { sha: headSha, merge_method: 'squash' },
            },
        ])
    })

    test.each(['PENDING', 'FAILURE', 'ERROR', 'EXPECTED'])(
        'does not merge CI rollup %s',
        async (checkState) => {
            const state = fixture()
            state.graph.commits.nodes[0]!.commit.statusCheckRollup.state = checkState
            expect((await state.run())[0]?.action).toBe('skipped')
            expect(state.writes()).toHaveLength(0)
        },
    )

    test('does not merge when main moved while checking CI', async () => {
        const state = fixture()
        state.graph.baseRefOid = 'c'.repeat(40)
        expect((await state.run())[0]?.action).toBe('skipped')
        expect(state.writes()).toHaveLength(0)
    })

    test('does not merge a new head that arrived during validation', async () => {
        const state = fixture()
        state.settings.headChanged = true
        expect((await state.run())[0]?.action).toBe('skipped')
        expect(state.writes()).toHaveLength(0)
    })

    test('respects requested changes and unresolved discussions despite the app review exception', async () => {
        const rejectedReview = fixture()
        rejectedReview.graph.reviewDecision = 'CHANGES_REQUESTED'
        expect((await rejectedReview.run())[0]?.action).toBe('skipped')
        expect(rejectedReview.writes()).toHaveLength(0)
        const discussion = fixture()
        discussion.graph.reviewThreads.nodes.push({ isResolved: false })
        expect((await discussion.run())[0]?.action).toBe('skipped')
        expect(discussion.writes()).toHaveLength(0)
    })

    test('revalidates breaking-change markers immediately before merging', async () => {
        const state = fixture()
        state.settings.breakingLabelAdded = true
        expect((await state.run())[0]?.action).toBe('skipped')
        expect(state.writes()).toHaveLength(0)
    })

    test('does not merge without reported checks or when the CI query fails', async () => {
        const noChecks = fixture()
        Object.assign(noChecks.graph.commits.nodes[0]!.commit, { statusCheckRollup: null })
        expect((await noChecks.run())[0]?.action).toBe('skipped')
        expect(noChecks.writes()).toHaveLength(0)
        const queryFailure = fixture()
        queryFailure.settings.graphErrors = true
        expect((await queryFailure.run())[0]?.action).toBe('failed')
        expect(queryFailure.writes()).toHaveLength(0)
    })

    test('leaves major updates for manual review even with green CI', async () => {
        const state = fixture()
        state.commits[0]!.commit.message = state.commits[0]!.commit.message.replaceAll(
            '1.2.4',
            '2.0.0',
        ).replace('semver-patch', 'semver-major')
        expect((await state.run())[0]?.action).toBe('skipped')
        expect(state.writes()).toHaveLength(0)
    })

    test.each([405, 409, 422])('respects GitHub merge rejection HTTP %s', async (status) => {
        const state = fixture()
        state.settings.refusal = status
        expect((await state.run())[0]?.action).toBe('skipped')
        expect(state.writes()).toHaveLength(1)
    })

    test('reports unexpected server errors as failed rather than merged', async () => {
        const state = fixture()
        state.settings.refusal = 503
        expect((await state.run())[0]?.action).toBe('failed')
    })

    test('dry runs evaluate eligibility and CI without merging', async () => {
        const state = fixture()
        expect((await state.run(true))[0]?.action).toBe('would-merge')
        expect(state.writes()).toHaveLength(0)
    })

    test('refreshes main for later PRs after an earlier merge advances the base', async () => {
        const state = fixture()
        const newBase = 'e'.repeat(40)
        const laterHead = 'f'.repeat(40)
        let main = baseSha
        const request: GitHubRequest = async (method, path, body) => {
            if (path.startsWith(`${prefix}/pulls?`)) return [{ number: 42 }, { number: 43 }]
            if (path === `${prefix}/git/ref/heads/main`) return { object: { sha: main } }
            if (path === `${prefix}/pulls/43`) {
                return {
                    ...state.pull,
                    number: 43,
                    base: { ...state.pull.base, sha: main },
                    head: { ...state.pull.head, sha: laterHead },
                }
            }
            if (path === `${prefix}/compare/${laterHead}...${newBase}`) return { ahead_by: 1 }
            const response = await state.request(method, path, body)
            if (path === `${prefix}/pulls/42/merge`) main = newBase
            return response
        }
        const results = await maintainPullRequests(request, { repository, dryRun: false })
        expect(results.map((result) => result.action)).toEqual(['merged', 'update-requested'])
        expect(state.writes().map((call) => call.path)).toEqual([
            `${prefix}/pulls/42/merge`,
            `${prefix}/pulls/43/update-branch`,
        ])
    })
})

describe('Dependabot update queue', () => {
    const now = Date.parse('2026-11-22T12:00:00Z')
    interface Entry {
        number: number
        behind: number
        login?: string
        rollup?: string
        committed?: string
        major?: boolean
        refusal?: number
    }

    function queue(entries: Entry[]) {
        const template = fixture()
        const byNumber = new Map(entries.map((entry) => [entry.number, entry]))
        const byHead = new Map(entries.map((entry) => [head(entry.number), entry]))
        const calls: { method: string; path: string; body: unknown }[] = []
        const entry = (path: string) => byNumber.get(Number(/\/pulls\/(\d+)/u.exec(path)?.[1]))!
        const request: GitHubRequest = async (method, path, body) => {
            calls.push({ method, path, body })
            if (path.startsWith(`${prefix}/pulls?`)) {
                return entries.map(({ number }) => ({ number }))
            }
            if (path === `${prefix}/git/ref/heads/main`) return { object: { sha: baseSha } }
            if (path.startsWith(`${prefix}/compare/`)) {
                const [compared] = path.slice(`${prefix}/compare/`.length).split('...')
                return { ahead_by: byHead.get(compared!)!.behind }
            }
            if (path === '/graphql') {
                const selected = byNumber.get(Number(record(record(body).variables).number))!
                const graph = structuredClone(template.graph)
                graph.headRefOid = head(selected.number)
                graph.commits.nodes[0]!.commit = {
                    oid: head(selected.number),
                    statusCheckRollup: { state: selected.rollup ?? 'PENDING' },
                }
                return { data: { repository: { pullRequest: graph } } }
            }
            const selected = entry(path)
            if (method === 'PUT') {
                if (selected.refusal) throw new GitHubRequestError(selected.refusal)
                return { merged: true }
            }
            if (path.includes('/commits?')) {
                const commit = structuredClone(template.commits[0]!)
                commit.sha = head(selected.number)
                Object.assign(commit.commit.committer, {
                    date: selected.committed ?? '2026-11-22T11:00:00Z',
                })
                if (selected.major) {
                    commit.commit.message = commit.commit.message
                        .replaceAll('1.2.4', '2.0.0')
                        .replace('semver-patch', 'semver-major')
                }
                return [commit]
            }
            if (path.includes('/files?')) return template.files
            const pull = structuredClone(template.pull)
            pull.number = selected.number
            pull.head.sha = head(selected.number)
            pull.user.login = selected.login ?? bot.login
            return pull
        }
        const run = (dryRun = false) => maintainPullRequests(request, { repository, dryRun, now })
        const writes = () =>
            calls
                .filter((call) => call.method === 'PUT')
                .map((call) => call.path.slice(prefix.length))
        return { run, writes }
    }

    test('updates only the oldest auto-mergeable Dependabot branch at a time', async () => {
        const state = queue([
            { number: 45, behind: 2 },
            { number: 43, behind: 1 },
            { number: 44, behind: 3 },
        ])
        const results = await state.run()
        expect(results.map((result) => [result.number, result.action])).toEqual([
            [45, 'skipped'],
            [43, 'update-requested'],
            [44, 'skipped'],
        ])
        expect(results[0]?.reason).toContain('one at a time')
        expect(state.writes()).toEqual(['/pulls/43/update-branch'])
    })

    test('waits while a current Dependabot update listed later is still in CI', async () => {
        const state = queue([
            { number: 50, behind: 1 },
            { number: 42, behind: 0, rollup: 'PENDING' },
        ])
        expect((await state.run()).map((result) => result.action)).toEqual(['skipped', 'skipped'])
        expect(state.writes()).toEqual([])
    })

    test.each(['FAILURE', 'ERROR'])(
        'a %s current update does not hold the queue',
        async (rollup) => {
            const state = queue([
                { number: 42, behind: 0, rollup },
                { number: 50, behind: 1 },
            ])
            await state.run()
            expect(state.writes()).toEqual(['/pulls/50/update-branch'])
        },
    )

    test('an update pending for too long stops holding the queue', async () => {
        const state = queue([
            { number: 42, behind: 0, rollup: 'PENDING', committed: '2026-11-22T08:30:00Z' },
            { number: 50, behind: 1 },
        ])
        await state.run()
        expect(state.writes()).toEqual(['/pulls/50/update-branch'])
    })

    test('a merged update lets the next Dependabot update start in the same run', async () => {
        const state = queue([
            { number: 42, behind: 0, rollup: 'SUCCESS' },
            { number: 50, behind: 1 },
        ])
        expect((await state.run()).map((result) => result.action)).toEqual([
            'merged',
            'update-requested',
        ])
        expect(state.writes()).toEqual(['/pulls/42/merge', '/pulls/50/update-branch'])
    })

    test('human and manual-review Dependabot branches stay current immediately', async () => {
        const state = queue([
            { number: 60, behind: 1, login: 'human' },
            { number: 61, behind: 1, major: true },
            { number: 42, behind: 0, rollup: 'PENDING' },
        ])
        expect((await state.run()).map((result) => result.action)).toEqual([
            'update-requested',
            'update-requested',
            'skipped',
        ])
        expect(state.writes()).toEqual(['/pulls/60/update-branch', '/pulls/61/update-branch'])
    })

    test('dry runs report only the next queued update', async () => {
        const state = queue([
            { number: 43, behind: 1 },
            { number: 44, behind: 1 },
        ])
        expect((await state.run(true)).map((result) => result.action)).toEqual([
            'would-update',
            'skipped',
        ])
        expect(state.writes()).toEqual([])
    })

    test('a refused update hands its turn to the next queued update', async () => {
        const state = queue([
            { number: 43, behind: 1, refusal: 422 },
            { number: 44, behind: 1 },
        ])
        const results = await state.run()
        expect(results.map((result) => result.action)).toEqual(['skipped', 'update-requested'])
        expect(results[0]?.reason).toContain('HTTP 422')
        expect(state.writes()).toEqual(['/pulls/43/update-branch', '/pulls/44/update-branch'])
    })
})

test('paginates complete API results', async () => {
    const calls: string[] = []
    const request: GitHubRequest = (_method, path) => {
        calls.push(path)
        return Promise.resolve(
            calls.length === 1 ? Array.from({ length: 100 }, (_, id) => id) : [100],
        )
    }
    expect(await arrayPages(request, `${prefix}/pulls?state=open`)).toHaveLength(101)
    expect(calls[1]).toEndWith('&per_page=100&page=2')
})

test('rejects missing credentials and invalid repository names before any API request', () => {
    expect(() => createGitHubRequest(repository, '')).toThrow('Missing GitHub App token')
    expect(() => createGitHubRequest('owner/repo/other', 'test-token')).toThrow(
        'Invalid GitHub repository',
    )
})

test('the privileged workflow executes only trusted main with a repository-scoped app token', async () => {
    const source = await readFile(
        new URL('../../../../../.github/workflows/pr-maintenance.yml', import.meta.url),
        'utf8',
    )
    const workflow = YAML.parse(source) as {
        permissions: Record<string, string>
        jobs: {
            maintain: {
                steps: {
                    uses?: string
                    run?: string
                    with?: Record<string, unknown>
                }[]
            }
        }
    }
    const steps = workflow.jobs.maintain.steps
    expect(workflow.permissions).toEqual({ contents: 'read' })
    expect(steps[0]?.with).toEqual({ ref: 'refs/heads/main', 'persist-credentials': false })
    expect(steps.flatMap((step) => (step.run ? [step.run] : []))).toEqual([
        'bun --no-env-file .github/scripts/automation/pr-maintenance.ts',
    ])
    const token = steps.find((step) => step.uses?.startsWith('actions/create-github-app-token@'))
    expect(token?.with?.repositories).toBe('${{ github.event.repository.name }}')
    expect(token?.with?.['permission-checks']).toBe('read')
    expect(token?.with?.['permission-statuses']).toBe('read')
    expect(token?.with?.['permission-administration']).toBeUndefined()
    for (const step of steps) {
        if (step.uses) expect(step.uses).toMatch(/@[a-f0-9]{40}$/)
    }
})

test('the workflow skips completions that cannot make a pull request mergeable', async () => {
    const workflow = YAML.parse(
        await readFile(
            new URL('../../../../../.github/workflows/pr-maintenance.yml', import.meta.url),
            'utf8',
        ),
    ) as { on: Record<string, unknown>; jobs: { maintain: { if: string } } }
    const condition = workflow.jobs.maintain.if
    expect(condition).toContain("vars.PR_AUTOMATION_CLIENT_ID != ''")
    expect(condition).toContain("github.event_name != 'workflow_run'")
    for (const skipped of [
        "github.event.workflow_run.event != 'push'",
        "github.event.workflow_run.event != 'schedule'",
        "github.event.workflow_run.conclusion != 'cancelled'",
        "github.event.workflow_run.conclusion != 'skipped'",
    ])
        expect(condition).toContain(skipped)
    // Main pushes and the schedule still run maintenance directly.
    expect(Object.keys(workflow.on)).toEqual(
        expect.arrayContaining(['push', 'pull_request_target', 'workflow_run', 'schedule']),
    )
})
