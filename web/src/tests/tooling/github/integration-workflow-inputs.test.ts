import { readFile } from 'node:fs/promises'
import { describe, expect, test } from 'bun:test'

type Trigger = { paths?: string[]; 'paths-ignore'?: string[] } | null
type Workflow = { on: Record<string, Trigger> }

async function workflow(name: string): Promise<Workflow> {
    return Bun.YAML.parse(
        await readFile(
            new URL(`../../../../../.github/workflows/${name}.yml`, import.meta.url),
            'utf8',
        ),
    ) as Workflow
}

test.each(['release-compatibility', 'runtime-reliability'])(
    '%s retains manual diagnostics while central main and PR checks cover runtime inputs',
    async (name) => {
        const triggers = (await workflow(name)).on
        expect(triggers).not.toHaveProperty('pull_request')
        expect(triggers).not.toHaveProperty('push')
        expect(triggers).toHaveProperty('workflow_dispatch')
        const central = (await workflow('production-smokes')).on
        for (const event of ['pull_request', 'push']) {
            expect(central).toHaveProperty(event)
            expect(central[event]?.paths).toBeUndefined()
            expect(central[event]?.['paths-ignore']).toBeUndefined()
        }
    },
)

async function armPaths(): Promise<string[]> {
    const triggers = (await workflow('arm64-appliance')).on
    return triggers.pull_request?.paths ?? []
}

function matches(patterns: string[], path: string): boolean {
    return patterns.some((pattern) => new Bun.Glob(pattern).match(path))
}

describe('ARM64 Appliance pull request scope', () => {
    test('main pushes and manual runs always verify ARM64; pull requests only for native inputs', async () => {
        const triggers = (await workflow('arm64-appliance')).on
        expect(triggers.push).toEqual({ branches: ['main'] } as unknown as Trigger)
        expect(triggers).toHaveProperty('workflow_dispatch')
        expect(triggers.pull_request?.['paths-ignore']).toBeUndefined()
        const paths = await armPaths()
        for (const path of [
            'docker/production/Dockerfile',
            'docker/production/entrypoint.sh',
            'packaging/debian/control',
            'scripts/smoke/http3/Dockerfile',
            'bun.lock',
            'core/Cargo.lock',
            'core/caddy-modules/go.mod',
            'core/caddy-modules/go.sum',
            'rust-toolchain.toml',
            '.github/actions/runtime-images/action.yml',
            '.github/workflows/arm64-appliance.yml',
            '.github/scripts/security/scan-image.sh',
        ])
            expect(matches(paths, path), path).toBeTrue()
        for (const path of [
            'web/src/features/Hosts/Components/HostList.tsx',
            'web/src/tests/features/Hosts/host.test.tsx',
            'core/src/main.rs',
            'core/caddy-modules/modules.go',
            'core/caddy-modules/responsecache/handler.go',
            'core/caddy-modules/upstreamobserver/observer.go',
            'scripts/test-web.ts',
            '.github/workflows/ci.yml',
            'README.md',
        ])
            expect(matches(paths, path), path).toBeFalse()
    })

    test('every Dependabot update that reaches the appliance still runs native ARM64', async () => {
        const dependabot = Bun.YAML.parse(
            await readFile(
                new URL('../../../../../.github/dependabot.yml', import.meta.url),
                'utf8',
            ),
        ) as {
            updates: {
                'package-ecosystem': string
                directory?: string
                directories?: string[]
            }[]
        }
        const manifests: Record<string, string[]> = {
            bun: ['package.json', 'bun.lock'],
            cargo: ['Cargo.toml', 'Cargo.lock'],
            gomod: ['go.mod', 'go.sum'],
            docker: ['Dockerfile'],
            'docker-compose': ['docker-compose.yml'],
        }
        const paths = await armPaths()
        let checked = 0
        for (const update of dependabot.updates) {
            const ecosystem = update['package-ecosystem']
            for (const directory of update.directories ?? [update.directory!]) {
                const relative = directory.replace(/^\//u, '')
                // Test fixtures are verified by their own workflows and never enter the appliance.
                if (/^(?:web\/src\/tests|core\/tests)\/fixtures\//u.test(relative)) continue
                const files =
                    ecosystem === 'github-actions'
                        ? relative === ''
                            ? ['.github/workflows/arm64-appliance.yml']
                            : ['.github/actions/runtime-images/action.yml']
                        : manifests[ecosystem]!.map(
                              (name) => (relative ? relative + '/' : '') + name,
                          )
                for (const file of files) {
                    expect(matches(paths, file), `${ecosystem} ${file}`).toBeTrue()
                    checked++
                }
            }
        }
        expect(checked).toBeGreaterThan(10)
    })
})

test.each([
    'ci',
    'workflow-lint',
    'gitleaks',
    'codeql',
    'dependency-review',
    'dependency-security',
    'production-smokes',
    'pr-preview-source',
])('%s keeps required PR checks independent of path filters', async (name) => {
    const triggers = (await workflow(name)).on
    expect(triggers).toHaveProperty('pull_request')
    expect(triggers.pull_request?.paths).toBeUndefined()
    expect(triggers.pull_request?.['paths-ignore']).toBeUndefined()
})
