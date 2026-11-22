import { appendFile } from 'node:fs/promises'
import { evaluateDependabotEligibility } from './dependabot-policy.ts'
import { closeDigestOnlyDockerUpdate } from './docker-digest-update.ts'
import {
    arrayPages,
    commitSha,
    createGitHubRequest,
    GitHubRequestError,
    record,
    repositoryName,
} from './github.ts'
import type {
    GitHubRequest,
    MaintenanceOptions,
    MaintenanceResult,
} from './Types/pr-maintenance.types.ts'

const CI_QUERY = `query($owner: String!, $name: String!, $number: Int!) {
  repository(owner: $owner, name: $name) {
    pullRequest(number: $number) {
      headRefOid baseRefOid state isDraft reviewDecision
      reviewThreads(first: 100) {
        nodes { isResolved }
        pageInfo { hasNextPage }
      }
      commits(last: 1) {
        nodes { commit { oid statusCheckRollup { state } } }
      }
    }
  }
}`

/**
 * Every branch update reruns the complete CI suite, and with strict required checks each merge
 * outdates all other PRs again. Auto-mergeable Dependabot updates therefore advance one at a time.
 * An update counts as in CI only for this long, so a stuck run cannot stall the queue.
 */
const DEPENDABOT_IN_FLIGHT_MS = 3 * 60 * 60 * 1000
/** Tolerated difference between GitHub's commit timestamps and the runner clock. */
const CLOCK_SKEW_MS = 5 * 60 * 1000

type CheckState = 'success' | 'pending' | 'blocked'

interface MaintenanceContext {
    /** An eligible Dependabot update is current with main and still waiting for its CI. */
    dependabotInFlight: boolean
    clock: () => number
}

interface QueuedUpdate {
    number: number
    action: 'queued'
    headSha: string
}

async function currentChecks(
    request: GitHubRequest,
    repository: string,
    number: number,
    headSha: string,
    baseSha: string,
): Promise<CheckState> {
    const [owner, name] = repository.split('/')
    const response = record(
        await request('POST', '/graphql', {
            query: CI_QUERY,
            variables: { owner, name, number },
        }),
    )
    if (response.errors !== undefined) throw new Error('GitHub CI query failed')
    const pull = record(record(record(response.data).repository).pullRequest)
    // A moved head or base means a new CI run is about to start for this PR.
    if (pull.headRefOid !== headSha || pull.baseRefOid !== baseSha) return 'pending'
    if (
        pull.state !== 'OPEN' ||
        pull.isDraft !== false ||
        pull.reviewDecision === 'CHANGES_REQUESTED'
    ) {
        return 'blocked'
    }
    const threads = record(pull.reviewThreads)
    if (
        record(threads.pageInfo).hasNextPage !== false ||
        !Array.isArray(threads.nodes) ||
        threads.nodes.some((thread: unknown) => record(thread).isResolved !== true)
    ) {
        return 'blocked'
    }
    const nodes = record(pull.commits).nodes
    if (!Array.isArray(nodes) || nodes.length !== 1) return 'blocked'
    const commit = record(record(nodes[0]).commit)
    if (commit.oid !== headSha) return 'pending'
    if (commit.statusCheckRollup === null) return 'pending'
    const state = record(commit.statusCheckRollup).state
    if (state === 'SUCCESS') return 'success'
    return state === 'PENDING' || state === 'EXPECTED' ? 'pending' : 'blocked'
}

/** Measures the head's age when it is inspected, not when the maintenance run started. */
function recentHead(commits: unknown[], headSha: string, clock: () => number): boolean {
    const head = commits.map(record).find((commit) => commit.sha === headSha)
    const date = head ? record(record(head.commit).committer).date : undefined
    const time = typeof date === 'string' ? Date.parse(date) : Number.NaN
    if (!Number.isFinite(time)) return false
    const age = clock() - time
    return age > -CLOCK_SKEW_MS && age < DEPENDABOT_IN_FLIGHT_MS
}

/** GitHub definitely rejected the request, so nothing was changed. */
function definiteRefusal(error: unknown): boolean {
    return error instanceof GitHubRequestError && [403, 404, 405, 409, 422].includes(error.status)
}

function failureResult(number: number, error: unknown): MaintenanceResult {
    return {
        number,
        action: definiteRefusal(error) ? 'skipped' : 'failed',
        reason:
            error instanceof GitHubRequestError
                ? `GitHub HTTP ${error.status}; no update or merge was forced`
                : 'Validation or GitHub request failed; no merge was attempted',
    }
}

async function maintainPullRequest(
    request: GitHubRequest,
    options: MaintenanceOptions,
    number: number,
    context: MaintenanceContext,
): Promise<MaintenanceResult | QueuedUpdate> {
    const prefix = `/repos/${options.repository}`
    const path = `${prefix}/pulls/${number}`
    const skipped = (reason: string): MaintenanceResult => ({ number, action: 'skipped', reason })
    const pull = record(await request('GET', path))
    const closed = await closeDigestOnlyDockerUpdate(request, options, number, path, pull)
    if (closed) return closed
    const base = record(pull.base)
    const head = record(pull.head)
    if (
        pull.state !== 'open' ||
        base.ref !== 'main' ||
        record(base.repo).full_name?.toString().toLowerCase() !== options.repository ||
        head.repo === null
    ) {
        return skipped('Pull request is no longer open against this repository’s main branch')
    }
    if (pull.mergeable === false) return skipped('Merge conflict requires manual resolution')

    const headSha = commitSha(head.sha)
    const main = record(await request('GET', `${prefix}/git/ref/heads/main`))
    const baseSha = commitSha(record(main.object).sha)
    const comparison = record(await request('GET', `${prefix}/compare/${headSha}...${baseSha}`))
    if (!Number.isSafeInteger(comparison.ahead_by) || Number(comparison.ahead_by) < 0) {
        throw new Error('Invalid branch comparison')
    }
    if (Number(comparison.ahead_by) > 0) {
        if (
            record(head.repo).full_name?.toString().toLowerCase() !== options.repository &&
            pull.maintainer_can_modify !== true
        ) {
            return skipped('Fork owner has not allowed maintainer branch updates')
        }
        if (pull.draft === false && record(pull.user).login === 'dependabot[bot]') {
            const [commits, files] = await Promise.all([
                arrayPages(request, `${path}/commits`),
                arrayPages(request, `${path}/files`),
            ])
            const queued = evaluateDependabotEligibility({
                repository: options.repository,
                trustedMergeBotLogin: options.trustedMergeBotLogin ?? '',
                pullRequest: pull,
                commits,
                files,
            })
            // Auto-mergeable updates wait for their turn; manual-review updates stay current.
            if (queued.eligible) return { number, action: 'queued', headSha }
        }
        if (!options.dryRun) {
            await request('PUT', `${path}/update-branch`, { expected_head_sha: headSha })
        }
        return {
            number,
            action: options.dryRun ? 'would-update' : 'update-requested',
            reason: 'Requested branch update; GitHub completes the merge asynchronously',
        }
    }

    if (pull.draft !== false || record(pull.user).login !== 'dependabot[bot]') {
        return skipped('Branch is current; automatic merging is limited to Dependabot updates')
    }
    const [commits, files] = await Promise.all([
        arrayPages(request, `${path}/commits`),
        arrayPages(request, `${path}/files`),
    ])
    const eligibility = evaluateDependabotEligibility({
        repository: options.repository,
        trustedMergeBotLogin: options.trustedMergeBotLogin ?? '',
        pullRequest: pull,
        commits,
        files,
    })
    if (!eligibility.eligible) return skipped(eligibility.reason)
    const markInFlight = () => {
        if (recentHead(commits, headSha, context.clock)) context.dependabotInFlight = true
    }
    if (pull.mergeable !== true) {
        markInFlight()
        return skipped('GitHub is still calculating mergeability')
    }
    const checks = await currentChecks(request, options.repository, number, headSha, baseSha)
    if (checks !== 'success') {
        if (checks === 'pending') markInFlight()
        return skipped('Waiting for current successful checks and resolution of review objections')
    }

    const latest = record(await request('GET', path))
    if (
        record(latest.head).sha !== headSha ||
        record(latest.base).sha !== baseSha ||
        latest.mergeable !== true
    ) {
        markInFlight()
        return skipped('Pull request changed during validation; retry on the next event')
    }
    const currentEligibility = evaluateDependabotEligibility({
        repository: options.repository,
        trustedMergeBotLogin: options.trustedMergeBotLogin ?? '',
        pullRequest: latest,
        commits,
        files,
    })
    if (!currentEligibility.eligible) return skipped(currentEligibility.reason)
    if (options.dryRun) {
        return { number, action: 'would-merge', reason: eligibility.reason }
    }

    // Only the review ruleset exempts this App; GitHub enforces strict CI and main protections.
    const merged = record(
        await request('PUT', `${path}/merge`, { sha: headSha, merge_method: 'squash' }),
    )
    return merged.merged === true
        ? { number, action: 'merged', reason: 'Verified Dependabot update passed current CI' }
        : skipped('GitHub declined the merge; required rules remain enforced')
}

export async function maintainPullRequests(
    request: GitHubRequest,
    options: MaintenanceOptions,
): Promise<MaintenanceResult[]> {
    const repository = repositoryName(options.repository)
    const pulls = await arrayPages(request, `/repos/${repository}/pulls?state=open&base=main`)
    const context: MaintenanceContext = {
        dependabotInFlight: false,
        clock: options.clock ?? (() => Date.now()),
    }
    const results: MaintenanceResult[] = []
    const queued: (QueuedUpdate & { index: number })[] = []
    for (const entry of pulls) {
        const number = record(entry).number
        if (!Number.isSafeInteger(number) || Number(number) <= 0) {
            throw new Error('Invalid pull request number')
        }
        try {
            // eslint-disable-next-line no-await-in-loop -- each merge changes main for subsequent PRs
            const result = await maintainPullRequest(
                request,
                { ...options, repository },
                Number(number),
                context,
            )
            if (result.action === 'queued') {
                queued.push({ ...result, index: results.length })
                results.push({ number: result.number, action: 'skipped', reason: '' })
            } else {
                results.push(result)
            }
        } catch (error) {
            results.push(failureResult(Number(number), error))
        }
    }

    // Start at most one auto-mergeable Dependabot update, oldest first, after every current
    // update was seen; the next one follows once it merged or stopped waiting for CI.
    let started = context.dependabotInFlight
    for (const update of queued.toSorted((left, right) => left.number - right.number)) {
        if (started) {
            results[update.index] = {
                number: update.number,
                action: 'skipped',
                reason: 'Waiting for the Dependabot update already in CI; updates run one at a time',
            }
            continue
        }
        try {
            if (!options.dryRun) {
                // eslint-disable-next-line no-await-in-loop -- only the first accepted update may start
                await request('PUT', `/repos/${repository}/pulls/${update.number}/update-branch`, {
                    expected_head_sha: update.headSha,
                })
            }
            results[update.index] = {
                number: update.number,
                action: options.dryRun ? 'would-update' : 'update-requested',
                reason: 'Requested branch update for the next Dependabot update in line',
            }
            started = true
        } catch (error) {
            results[update.index] = failureResult(update.number, error)
            // Only a definite refusal hands the turn on; any other failure may have been accepted.
            if (!definiteRefusal(error)) started = true
        }
    }
    return results
}

if (import.meta.main) {
    const repository = process.env.GITHUB_REPOSITORY ?? ''
    const dryRun = process.env.DRY_RUN !== 'false'
    const request = createGitHubRequest(repository, process.env.GH_TOKEN ?? '')
    const results = await maintainPullRequests(request, {
        repository,
        dryRun,
        trustedMergeBotLogin: process.env.TRUSTED_MERGE_BOT_LOGIN ?? '',
    })
    const summary = [
        `## PR maintenance${dryRun ? ' (dry run)' : ''}`,
        '',
        '| PR | Result | Reason |',
        '| --- | --- | --- |',
        ...results.map((result) => `| #${result.number} | ${result.action} | ${result.reason} |`),
        ...(results.length === 0 ? ['No open pull requests against main.'] : []),
        '',
    ].join('\n')
    console.log(summary)
    if (process.env.GITHUB_STEP_SUMMARY) {
        await appendFile(process.env.GITHUB_STEP_SUMMARY, summary)
    }
    if (results.some((result) => result.action === 'failed')) process.exitCode = 1
}
