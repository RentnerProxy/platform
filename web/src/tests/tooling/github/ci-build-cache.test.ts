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
    expect(proxy.split(/\r?\n/u)[0]).toMatch(/^# syntax=mirror\.gcr\.io\/docker\/dockerfile:\d+\.\d+\.\d+$/u)
    for (const stage of ['controller-build', 'caddy-build']) {
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
    '%s keeps the Cargo target and registry out of cacheable layers',
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
        'cache-from': 'type=gha,version=2,scope=ci-ts-coverage-v1,timeout=2m',
    })
    expect(image.with?.['cache-to']).toBe(
        "${{ github.event_name != 'pull_request' && 'type=gha,version=2,scope=ci-ts-coverage-v1,mode=max,timeout=2m,ignore-error=true' || '' }}",
    )
    const run = steps.findIndex((step) => step.run?.includes('rentnerproxy-ts-coverage:test run'))
    expect(run).toBeGreaterThan(build)
})
