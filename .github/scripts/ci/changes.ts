import { appendFile } from 'node:fs/promises'

const checkNames = [
    'web',
    'scripts',
    'rust',
    'go',
    'caddy',
    'build_web',
    'build_core',
    'runtime',
    'dependencies',
    'actions',
    'app_runtime',
    'full',
] as const
type CheckSelection = Record<(typeof checkNames)[number], boolean>

// Inputs of the native app runtime reference: the app boundary in the core and its fixtures, the
// production appliance it builds, and the backup tooling that its offline restore uses.
const appRuntimeInputs =
    /^(?:core\/src\/app_|core\/tests\/(?:private\/app_|fixtures\/app-)|core\/(?:Cargo\.(?:toml|lock)|rust-toolchain\.toml)$|docker\/production\/|docker-compose\.yml$|scripts\/(?:production-(?:backup|restore)\.ts$|backup\/|smoke\/wait\.ts$)|web\/src\/(?:lib\/App(?:Catalog|Ui)\/|server\/security-headers\.ts$|tests\/fixtures\/app-)|\.github\/(?:workflows\/app-runtime-reference\.yml$|scripts\/ci\/fixtures\/app-))/u

function selection(value: boolean): CheckSelection {
    return Object.fromEntries(checkNames.map((name) => [name, value])) as CheckSelection
}

export function selectChecks(paths: readonly string[]): CheckSelection {
    const selected = selection(false)
    const enable = (...names: (keyof CheckSelection)[]) => {
        for (const name of names) selected[name] = true
    }
    for (const path of paths) {
        if (/^(?:docs\/|README\.md$|SECURITY\.md$|LICENSE$|AGENTS\.md$)/u.test(path)) continue
        if (/^\.github\/.*\.md$/u.test(path)) continue
        if (/^\.github\/(?:ISSUE_TEMPLATE\/|assets\/|CODEOWNERS$|release-notes\.json$)/u.test(path))
            continue
        if (appRuntimeInputs.test(path)) enable('app_runtime')
        if (/^\.github\/(?:workflows\/|actions\/)/u.test(path)) {
            enable('actions', 'web', 'scripts')
            if (
                /^\.github\/(?:actions\/(?:runtime-images|load-runtime-images)\/|workflows\/(?:production-smokes|arm64-appliance|beta2-integration|release-compatibility|runtime-reliability)\.yml$)/u.test(
                    path,
                )
            )
                enable('runtime')
            if (path === '.github/workflows/dependency-security.yml')
                enable('dependencies', 'runtime')
            if (path === '.github/workflows/codeql.yml') enable('rust')
            if (
                path === '.github/workflows/detect-changes.yml' ||
                path === '.github/workflows/ci.yml'
            )
                return selection(true)
            continue
        }
        if (path.startsWith('.github/scripts/')) {
            enable('web', 'scripts', 'actions')
            if (path.includes('/security/')) enable('dependencies', 'runtime')
            if (path.includes('/ci/') || path.includes('/lib/')) enable('runtime')
            if (path.endsWith('/rust-coverage.sh')) enable('rust')
            if (path.includes('/caddy-')) enable('go', 'caddy', 'runtime')
            if (path.endsWith('.go') || path.endsWith('/go-coverage.sh')) enable('go')
            if (path.endsWith('/changes.ts') || path.includes('/Types/changes'))
                return selection(true)
            continue
        }
        if (path.startsWith('core/caddy-modules/')) {
            enable('go', 'caddy', 'runtime')
            continue
        }
        if (/^core\/(?:src\/|tests\/|build\.rs$)/u.test(path)) {
            enable('rust', 'build_core', 'runtime')
            continue
        }
        if (
            /^core\/(?:Cargo\.(?:toml|lock)$|\.cargo\/)/u.test(path) ||
            /^(?:rust-toolchain|\.cargo\/)/u.test(path)
        ) {
            enable('rust', 'build_core', 'runtime', 'dependencies')
            continue
        }
        if (path.startsWith('web/src/tests/')) {
            enable('web')
            if (path.startsWith('web/src/tests/tooling/github/caddy-'))
                enable('go', 'caddy', 'runtime')
            if (path.startsWith('web/src/tests/tooling/docker/')) enable('runtime')
            continue
        }
        if (
            path.startsWith('web/src/features/') &&
            (path.endsWith('/middleware.ts') ||
                path.includes('.server.') ||
                (!path.endsWith('.tsx') && !/\/(?:Components|Hooks|Types)\//u.test(path)))
        ) {
            enable('web', 'scripts', 'build_web', 'runtime')
            continue
        }
        if (
            /^web\/(?:public\/|src\/(?:features|layouts|styles)\/)/u.test(path) ||
            /^web\/src\/.*\.css$/u.test(path)
        ) {
            enable('web', 'build_web')
            continue
        }
        if (path.startsWith('web/')) {
            enable('web', 'scripts', 'build_web', 'runtime')
            continue
        }
        if (path.startsWith('scripts/')) {
            enable('web', 'scripts')
            if (
                /^scripts\/coverage\/(?:coverage\.config\.ts|report\.ts|summary\.ts|Types\/report\.types\.ts)$/u.test(
                    path,
                )
            )
                enable('go', 'rust')
            if (!/^scripts\/(?:coverage\/|test-web\.ts$)/u.test(path))
                enable('build_web', 'build_core', 'runtime')
            continue
        }
        if (
            path.startsWith('docker/') ||
            path.startsWith('packaging/') ||
            path === 'docker-compose.yml' ||
            path === '.dockerignore'
        ) {
            enable('web', 'scripts', 'runtime', 'build_web', 'build_core')
            if (path.startsWith('docker/tooling/buildinfo/')) enable('go')
            if (path.startsWith('docker/proxy-runtime/') || path.startsWith('docker/caddy/'))
                enable('caddy', 'go')
            continue
        }
        if (
            /^(?:package\.json|bun\.lock|bunfig\.toml|tsconfig.*\.json|vite\.config\.ts|drizzle\.config\.ts|knip\.json|\.oxlintrc.*\.json)$/u.test(
                path,
            )
        )
            return selection(true)
        return selection(true)
    }
    selected.full = checkNames.filter((name) => name !== 'full').every((name) => selected[name])
    return selected
}

export function detectChanges(
    event: string,
    base: string,
    head: string,
    cwd = process.cwd(),
): CheckSelection {
    if (!['pull_request', 'merge_group', 'push'].includes(event)) return selection(true)
    for (const revision of [base, head]) {
        if (!/^[a-f0-9]{40,64}$/u.test(revision) || /^0+$/u.test(revision)) return selection(true)
    }
    // Pull requests and merge queue entries compare against their merge base; pushes include
    // every commit since the previous tip.
    const comparison = event === 'push' ? `${base}..${head}` : `${base}...${head}`
    const result = Bun.spawnSync(
        ['git', 'diff', '--no-renames', '--name-only', '-z', comparison, '--'],
        {
            cwd,
            stdout: 'pipe',
            stderr: 'pipe',
        },
    )
    if (result.exitCode !== 0) throw new Error('Cannot resolve the CI change comparison')
    return selectChecks(result.stdout.toString().split('\0').filter(Boolean))
}

/**
 * A pull request may hand its affected runtime verification to the merge queue, which then runs
 * it once on the exact merge result. Every other event keeps its selection unchanged.
 */
export function deferRuntime(
    event: string,
    requested: string | undefined,
    selected: CheckSelection,
): { selected: CheckSelection; deferred: boolean } {
    if (event !== 'pull_request' || requested !== 'true' || !selected.runtime)
        return { selected, deferred: false }
    return { selected: { ...selected, runtime: false, full: false }, deferred: true }
}

if (import.meta.main) {
    const event = process.env.GITHUB_EVENT_NAME ?? ''
    const { selected, deferred } = deferRuntime(
        event,
        process.env.CI_DEFER_RUNTIME,
        detectChanges(event, process.env.CI_BASE_SHA ?? '', process.env.CI_HEAD_SHA ?? ''),
    )
    if (!process.env.GITHUB_OUTPUT) throw new Error('GITHUB_OUTPUT is required')
    await appendFile(
        process.env.GITHUB_OUTPUT,
        checkNames.map((name) => `${name}=${String(selected[name])}\n`).join('') +
            `runtime_deferred=${String(deferred)}\n`,
    )
    console.log(JSON.stringify({ ...selected, runtime_deferred: deferred }, null, 2))
}
