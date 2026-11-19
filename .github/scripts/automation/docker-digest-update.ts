import { arrayPages, commitSha, record } from './github.ts'
import type {
    GitHubRequest,
    MaintenanceOptions,
    MaintenanceResult,
} from './Types/pr-maintenance.types.ts'

const dockerDigest =
    /^([ \t]*(?:FROM[ \t]+(?:--platform=\S+[ \t]+)?|#[ \t]*syntax=[ \t]*)\S+@sha256:)([a-f0-9]{64})([ \t]+.*)?$/iu
const composeDigest =
    /^([ \t]*image:[ \t]*["']?[^ \t"']+@sha256:)([a-f0-9]{64})(["']?(?:[ \t]+.*)?)$/u

function isRoutineDockerPull(pull: Record<string, unknown>, repository: string): boolean {
    if (pull.draft !== false) return false
    const head = record(pull.head)
    if (typeof head.ref !== 'string' || !/^dependabot\/docker(?:-compose)?\//u.test(head.ref))
        return false
    const base = record(pull.base)
    const author = record(pull.user)
    return (
        author.login === 'dependabot[bot]' &&
        author.id === 49699333 &&
        author.type === 'Bot' &&
        base.ref === 'main' &&
        base.repo !== null &&
        head.repo !== null &&
        String(record(base.repo).full_name).toLowerCase() === repository &&
        String(record(head.repo).full_name).toLowerCase() === repository &&
        Array.isArray(pull.labels) &&
        pull.labels.every((label) => !/security|vulnerabilit/iu.test(String(record(label).name)))
    )
}

function changesOnlyDigests(value: unknown): boolean {
    const file = record(value)
    if (
        file.status !== 'modified' ||
        typeof file.filename !== 'string' ||
        typeof file.patch !== 'string'
    )
        return false

    const name = file.filename.split('/').at(-1) ?? ''
    const isDockerfile =
        /^(?:(?:dockerfile|containerfile)(?:\.[^.]+)?|.+\.(?:dockerfile|containerfile))$/iu.test(
            name,
        )
    const isCompose = /^(?:docker-)?compose(?:[.-][^.]+)?\.ya?ml$/iu.test(name)
    if (!isDockerfile && !isCompose) return false

    const pattern = isCompose ? composeDigest : dockerDigest
    const before: RegExpExecArray[] = []
    const after: RegExpExecArray[] = []
    for (const line of file.patch.split('\n')) {
        if (!line.startsWith('-') && !line.startsWith('+')) continue
        const reference = pattern.exec(line.slice(1))
        if (!reference) return false
        const rows = line.startsWith('-') ? before : after
        rows.push(reference)
    }
    return (
        before.length > 0 &&
        before.length === file.deletions &&
        after.length === file.additions &&
        before.length === after.length &&
        before.every((entry, index) => {
            const next = after[index]!
            return entry[1] === next[1] && entry[2] !== next[2] && entry[3] === next[3]
        })
    )
}

export async function closeDigestOnlyDockerUpdate(
    request: GitHubRequest,
    options: MaintenanceOptions,
    number: number,
    path: string,
    pull: Record<string, unknown>,
): Promise<MaintenanceResult | undefined> {
    if (pull.state !== 'open' || !isRoutineDockerPull(pull, options.repository)) return undefined
    const headSha = commitSha(record(pull.head).sha)
    const baseSha = commitSha(record(pull.base).sha)
    const files = await arrayPages(request, path + '/files')
    if (
        files.length === 0 ||
        files.length !== pull.changed_files ||
        !files.every(changesOnlyDigests)
    )
        return undefined

    const reason = 'Docker image digests changed while the tags stayed the same'
    if (options.dryRun) return { number, action: 'would-close', reason }

    const matchesCheckedUpdate = (current: Record<string, unknown>) =>
        isRoutineDockerPull(current, options.repository) &&
        record(current.head).sha === headSha &&
        record(current.base).sha === baseSha &&
        current.changed_files === files.length

    const latest = record(await request('GET', path))
    if (latest.state !== 'open' || !matchesCheckedUpdate(latest)) {
        return {
            number,
            action: 'skipped',
            reason: 'Pull request changed during digest validation',
        }
    }

    const closed = record(await request('PATCH', path, { state: 'closed' }))
    if (closed.state !== 'closed')
        throw new Error('GitHub did not close the digest-only pull request')
    if (closed.merged === true)
        return {
            number,
            action: 'skipped',
            reason: 'Pull request was merged during digest validation',
        }
    // GitHub does not accept an expected head SHA when changing the PR state.
    if (!matchesCheckedUpdate(closed)) {
        const reopened = record(await request('PATCH', path, { state: 'open' }))
        if (reopened.state !== 'open')
            throw new Error('GitHub did not reopen the changed pull request')
        return { number, action: 'skipped', reason: 'Reopened after the pull request changed' }
    }
    return { number, action: 'closed', reason }
}
