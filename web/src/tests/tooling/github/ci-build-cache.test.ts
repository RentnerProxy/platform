import { readFile } from 'node:fs/promises'
import { join, resolve } from 'node:path'
import { expect, test } from 'bun:test'

const root = resolve(import.meta.dir, '../../../../..')

async function repositoryFile(path: string): Promise<string> {
    return readFile(join(root, path), 'utf8')
}

/** Dockerfile instructions per stage, with continuations joined and comments removed. */
function stages(dockerfile: string): Map<string, string[]> {
    const instructions = dockerfile
        .replace(/\\\r?\n[ \t]*/gu, ' ')
        .split(/\r?\n/u)
        .map((line) => line.trim())
        .filter((line) => line !== '' && !line.startsWith('#'))
    const result = new Map<string, string[]>()
    let current: string[] | undefined
    for (const instruction of instructions) {
        const stage = /^FROM \S+ AS (\S+)$/u.exec(instruction)?.[1]
        if (instruction.startsWith('FROM ')) {
            current = [instruction]
            if (stage) result.set(stage, current)
            continue
        }
        current?.push(instruction)
    }
    return result
}

test('proxy-runtime reuses the production controller and Caddy stages instruction for instruction', async () => {
    const [production, proxy] = await Promise.all([
        repositoryFile('docker/production/Dockerfile'),
        repositoryFile('docker/proxy-runtime/Dockerfile'),
    ])
    // One BuildKit builder builds both images in CI; identical stages compile only once.
    expect(proxy.split(/\r?\n/u)[0]).toBe(production.split(/\r?\n/u)[0])
    expect(proxy.split(/\r?\n/u)[0]).toMatch(
        /^# syntax=mirror\.gcr\.io\/docker\/dockerfile:\d+\.\d+\.\d+$/u,
    )
    for (const stage of ['controller-dependencies', 'controller-build', 'caddy-build']) {
        const expected = stages(production).get(stage)
        expect(expected, stage).toBeDefined()
        expect(stages(proxy).get(stage), stage).toEqual(expected!)
    }
})

test.each([
    ['docker/production/Dockerfile', 'controller-build', 'release'],
    ['docker/proxy-runtime/Dockerfile', 'controller-build', 'release'],
    ['docker/tooling/coverage/Dockerfile', 'controller', 'debug'],
])(
    '%s caches only manifest-keyed dependencies and keeps controller output out of cacheable layers',
    async (path, stage, profile) => {
        const dockerfile = await repositoryFile(path)
        const build = stages(dockerfile)
            .get(stage)!
            .find((instruction) => instruction.includes('cargo build --locked'))
        expect(build).toStartWith(
            'RUN --mount=type=cache,id=rentnerproxy-cargo-registry,target=/usr/local/cargo/registry ',
        )
        expect(build).toContain(
            `install -D -m 0755 target/${profile}/rentnerproxy-controller /out/rentnerproxy-controller`,
        )
        expect(build).toMatch(/rm -rf target$/u)
        expect(dockerfile).toContain(`COPY --from=${stage} /out/rentnerproxy-controller `)
        expect(dockerfile).not.toContain('/build/target/')

        // The dependency layer depends on the manifests alone: no controller source reaches it,
        // and the placeholder crate is removed so the real controller is always rebuilt.
        const dependencies = stages(dockerfile).get('controller-dependencies')!
        expect(stages(dockerfile).get(stage)![0]).toBe(`FROM controller-dependencies AS ${stage}`)
        expect(dependencies.filter((instruction) => instruction.startsWith('COPY '))).toEqual([
            'COPY core/Cargo.toml core/Cargo.lock ./',
        ])
        const prebuild = dependencies.find((instruction) =>
            instruction.includes('cargo build --locked'),
        )
        expect(prebuild).toStartWith(
            'RUN --mount=type=cache,id=rentnerproxy-cargo-registry,target=/usr/local/cargo/registry ',
        )
        expect(prebuild).toContain(
            profile === 'release'
                ? 'cargo clean --release --package rentnerproxy-controller'
                : 'cargo clean --package rentnerproxy-controller',
        )
        expect(prebuild).toMatch(/rm -rf src$/u)
        expect(stages(dockerfile).get(stage)).toContain('COPY core/src ./src')
    },
)

test('Web Tests restores the coverage image from a cache that pull requests cannot write', async () => {
    const workflow = Bun.YAML.parse(await repositoryFile('.github/workflows/ci.yml')) as {
        jobs: Record<
            string,
            {
                steps: {
                    name: string
                    uses?: string
                    run?: string
                    with?: Record<string, unknown>
                }[]
            }
        >
    }
    const steps = workflow.jobs['web-tests']!.steps
    const builder = steps.findIndex((step) => step.uses?.startsWith('docker/setup-buildx-action@'))
    const build = steps.findIndex(
        (step) => step.with?.file === 'docker/tooling/coverage/Dockerfile',
    )
    expect(builder).toBeGreaterThan(-1)
    expect(build).toBeGreaterThan(builder)
    const image = steps[build]!
    expect(image.uses).toMatch(/^docker\/build-push-action@[a-f0-9]{40}$/u)
    expect(image.with).toMatchObject({
        context: '.',
        load: true,
        push: false,
        tags: 'rentnerproxy-ts-coverage:test',
        'cache-from': 'type=registry,ref=ghcr.io/rentnerproxy/platform-build-cache:coverage-amd64',
    })
    expect(image.with?.['cache-to']).toBeUndefined()
    const run = steps.findIndex((step) => step.run?.includes('rentnerproxy-ts-coverage:test run'))
    expect(run).toBeGreaterThan(build)
})

test('only the main-only Build Cache workflow writes the registry build cache', async () => {
    const source = await repositoryFile('.github/workflows/build-cache.yml')
    const workflow = Bun.YAML.parse(source) as {
        on: Record<string, unknown>
        permissions: Record<string, string>
        jobs: Record<
            string,
            {
                permissions?: Record<string, string>
                strategy: { matrix: { include: { image: string; file: string; architecture: string }[] } }
                steps: { uses?: string; run?: string; if?: string; with?: Record<string, unknown> }[]
            }
        >
    }
    expect(Object.keys(workflow.on).toSorted()).toEqual(['push', 'schedule', 'workflow_dispatch'])
    expect(workflow.on.push).toMatchObject({ branches: ['main'] })
    expect(workflow.permissions).toEqual({ contents: 'read' })
    const refresh = workflow.jobs.refresh!
    expect(refresh.permissions).toEqual({ contents: 'read', packages: 'write' })
    expect(
        refresh.strategy.matrix.include.map(
            (entry) => `${entry.image}-${entry.architecture}:${entry.file}`,
        ),
    ).toEqual([
        'production-amd64:docker/production/Dockerfile',
        'production-arm64:docker/production/Dockerfile',
        'coverage-amd64:docker/tooling/coverage/Dockerfile',
    ])
    expect(source).toContain('persist-credentials: false')
    expect(source).not.toContain('secrets.')
    for (const step of refresh.steps.filter((candidate) => candidate.uses))
        expect(step.uses).toMatch(/^[^@]+@[0-9a-f]{40}$/u)
    const build = refresh.steps.find((step) => step.uses?.startsWith('docker/build-push-action@'))!
    expect(build.with).toMatchObject({ push: false, outputs: 'type=cacheonly' })
    expect(build.with?.['cache-to']).toContain('mode=max')
    expect(refresh.steps.at(-1)).toMatchObject({ if: 'always()', run: 'docker logout ghcr.io' })

    // Every consumer reads the cache anonymously and never writes or signs in to the registry.
    for (const path of [
        '.github/workflows/ci.yml',
        '.github/workflows/beta2-integration.yml',
        '.github/workflows/app-runtime-reference.yml',
        '.github/actions/runtime-images/action.yml',
        '.github/scripts/deploy/build-preview-image.sh',
    ]) {
        // oxlint-disable-next-line no-await-in-loop -- each consumer is checked independently.
        const consumer = await repositoryFile(path)
        expect(consumer, path).toContain(
            'type=registry,ref=ghcr.io/rentnerproxy/platform-build-cache:',
        )
        expect(consumer, path).not.toMatch(/cache-to:[^\n]*type=registry|docker login|packages: write/u)
    }
})
