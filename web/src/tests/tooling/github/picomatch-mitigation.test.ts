import { expect, test } from 'bun:test'
import {
    copyFile,
    mkdir,
    mkdtemp,
    readFile,
    rename,
    rm,
    symlink,
    writeFile,
} from 'node:fs/promises'
import { createRequire } from 'node:module'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'
import {
    AdvisoryPolicyError,
    evaluateBunAudit,
} from '../../../../../.github/scripts/security/dependency-policy.ts'
import {
    isMitigatedPicomatchAdvisory,
    verifyPicomatchMitigation,
} from '../../../../../.github/scripts/security/picomatch-mitigation.ts'

const root = resolve(import.meta.dir, '../../../../..')
const trustedResolution = 'picomatch@4.0.7'
const patch = 'patches/picomatch@4.0.7.patch'
const patchDeclaration = { patchedDependencies: { [trustedResolution]: patch } }
const resolution = [
    trustedResolution,
    '',
    {},
    'sha512-qcJu88Q2IWqJsDD529JKMdwGm/dvInW4HvQnRwiH9JtihJvzGOscDtHE3x1pBKeUOTysQ8kVmLnJ2kJu7yhcGA==',
]
const packages = { picomatch: resolution }
const sourceProof = {
    package: trustedResolution,
    advisory: 'GHSA-fc5q-39xc-vjpf',
    patchSha256: '550d716012d83ec38cb7c7001e2421a7bcbd4b4a61c34f12a0e936945808d15d',
} as const
const advisory = {
    id: 1247710,
    url: 'https://github.com/advisories/GHSA-fc5q-39xc-vjpf',
    title: 'Picomatch advisory fixture',
    severity: 'high',
    vulnerable_versions: '<=4.0.7',
}

async function withSourceFixture(run: (directory: string) => Promise<void>): Promise<void> {
    const directory = await mkdtemp(join(tmpdir(), 'rentnerproxy-picomatch-proof-'))
    try {
        await mkdir(join(directory, 'patches'))
        await Promise.all([
            copyFile(join(root, patch), join(directory, patch)),
            writeFile(join(directory, 'package.json'), JSON.stringify(patchDeclaration)),
            writeFile(
                join(directory, 'bun.lock'),
                `{
                    // Bun lockfiles support JSONC comments and trailing commas.
                    "patchedDependencies": ${JSON.stringify(patchDeclaration.patchedDependencies)},
                    "packages": { "picomatch": ${JSON.stringify(resolution)}, },
                }`,
            ),
        ])
        await run(directory)
    } finally {
        await rm(directory, { recursive: true, force: true })
    }
}

test('verifies the native Bun lock and exact repository patch', async () => {
    expect(await verifyPicomatchMitigation(root)).toEqual(sourceProof)
    await withSourceFixture(async (directory) => {
        expect(await verifyPicomatchMitigation(directory)).toEqual(sourceProof)
    })
})

test('verifies the installed parser bytes and rejects missing or changed parser evidence', async () => {
    const requireFromRoot = createRequire(join(root, 'package.json'))
    const requireFromVite = createRequire(requireFromRoot.resolve('vite/package.json'))
    const installed = requireFromVite.resolve('picomatch/lib/parse.js')
    await withSourceFixture(async (directory) => {
        const parser = join(directory, 'parse.js')
        expect(await verifyPicomatchMitigation(directory, parser)).toBeNull()

        await copyFile(installed, parser)
        expect(await verifyPicomatchMitigation(directory, parser)).toEqual({
            ...sourceProof,
            parserSha256: '46c326dda81c8afdb936e69773d03a5233534ddfec054d74ce5bdb68ab8cc337',
        })

        await writeFile(parser, 'changed parser')
        expect(await verifyPicomatchMitigation(directory, parser)).toBeNull()
    })
})

test.each([
    ['alternate version', { picomatch: ['picomatch@4.0.8', ...resolution.slice(1)] }],
    ['second copy', { ...packages, 'other/picomatch': resolution }],
    ['aliased copy', { ...packages, alias: resolution }],
    ['changed integrity', { picomatch: [...resolution.slice(0, 3), 'sha512-other'] }],
    [
        'changed tarball source',
        {
            picomatch: [
                trustedResolution,
                'https://example.invalid/package.tgz',
                ...resolution.slice(2),
            ],
        },
    ],
    ['malformed resolution', { ...packages, other: null }],
])('rejects a lock with %s', async (_description, graph) => {
    await withSourceFixture(async (directory) => {
        await writeFile(
            join(directory, 'bun.lock'),
            JSON.stringify({ ...patchDeclaration, packages: graph }),
        )
        expect(await verifyPicomatchMitigation(directory)).toBeNull()
    })
})

test.each(['\n', '\u2028', '\u2029'])(
    'rejects a duplicate resolution even after a JSONC comment with separator %j',
    async (separator) => {
        await withSourceFixture(async (directory) => {
            await writeFile(
                join(directory, 'bun.lock'),
                `{
                "patchedDependencies": ${JSON.stringify(patchDeclaration.patchedDependencies)},
                "packages": {
                    // Bun accepts Unicode line separators in comments.${separator}"\\u0070icomatch": ["picomatch@4.0.6"],
                    "picomatch": ${JSON.stringify(resolution)},
                },
            }`,
            )
            expect(await verifyPicomatchMitigation(directory)).toBeNull()
        })
    },
)

test('rejects missing or tampered patch inputs and a traversing manifest declaration', async () => {
    await withSourceFixture(async (directory) => {
        const manifest = join(directory, 'package.json')
        const patchFile = join(directory, patch)
        await writeFile(
            manifest,
            JSON.stringify({ patchedDependencies: { [trustedResolution]: `../${patch}` } }),
        )
        expect(await verifyPicomatchMitigation(directory)).toBeNull()

        await writeFile(manifest, JSON.stringify(patchDeclaration))
        await rm(patchFile)
        expect(await verifyPicomatchMitigation(directory)).toBeNull()

        await writeFile(patchFile, 'changed patch')
        expect(await verifyPicomatchMitigation(directory)).toBeNull()

        await writeFile(patchFile, Buffer.alloc(64 * 1024 + 1))
        expect(await verifyPicomatchMitigation(directory)).toBeNull()
    })
})

test.skipIf(process.platform === 'win32')(
    'rejects the exact patch bytes reached through a linked directory',
    async () => {
        await withSourceFixture(async (directory) => {
            const patches = join(directory, 'patches')
            const actual = join(directory, 'linked-target')
            await rename(patches, actual)
            await symlink(actual, patches, 'dir')
            expect(await verifyPicomatchMitigation(directory)).toBeNull()
        })
    },
)

test('matches only the exact registry advisory for picomatch', () => {
    expect(isMitigatedPicomatchAdvisory('picomatch', advisory)).toBe(true)
    expect(
        isMitigatedPicomatchAdvisory('picomatch', {
            ...advisory,
            vulnerable_versions: ' <=\t4.0.7',
        }),
    ).toBe(true)
    expect(isMitigatedPicomatchAdvisory('another-package', advisory)).toBe(false)
    for (const changed of [
        { id: 1247711 },
        { id: '1247710' },
        { url: advisory.url + '?alternate=1' },
        { severity: 'critical' },
        { vulnerable_versions: '<4.0.8' },
        { vulnerable_versions: '<=4.0.7 || 5.0.0' },
    ]) {
        expect(isMitigatedPicomatchAdvisory('picomatch', { ...advisory, ...changed })).toBe(false)
    }
})

test('preserves all other blocking findings and rejects incomplete audit coverage', () => {
    const report = { picomatch: [advisory] }
    expect(evaluateBunAudit(report, 1, '', sourceProof)).toBe(true)
    expect(() => evaluateBunAudit(report, 1, '')).toThrow(AdvisoryPolicyError)
    expect(() =>
        evaluateBunAudit({ ...report, other: [{ ...advisory, id: 12 }] }, 1, '', sourceProof),
    ).toThrow(AdvisoryPolicyError)
    expect(() =>
        evaluateBunAudit({ picomatch: [advisory, { ...advisory, id: 12 }] }, 1, '', sourceProof),
    ).toThrow(AdvisoryPolicyError)
    expect(() => evaluateBunAudit(report, 0, '', sourceProof)).toThrow('inconsistent')
    expect(() => evaluateBunAudit(report, 1, 'Registry warnings', sourceProof)).toThrow(
        'incomplete',
    )
})

test('the policy CLI writes proof only when the requested evidence is present', async () => {
    await withSourceFixture(async (directory) => {
        const report = join(directory, 'audit.json')
        const diagnostics = join(directory, 'diagnostics.txt')
        const proof = join(directory, 'picomatch-mitigation.json')
        await writeFile(report, JSON.stringify({ picomatch: [advisory] }))
        await writeFile(diagnostics, '')
        const command = [
            process.execPath,
            '--no-env-file',
            join(root, '.github/scripts/security/dependency-policy.ts'),
            'bun-audit',
            report,
            '1',
            diagnostics,
            directory,
        ]
        const missingParser = Bun.spawnSync([...command, join(directory, 'missing-parser'), proof])
        expect(missingParser.exitCode).toBe(3)
        expect(await Bun.file(proof).exists()).toBe(false)
        expect(Bun.spawnSync([...command, '']).exitCode).toBe(3)
        expect(Bun.spawnSync([...command, '', proof]).exitCode).toBe(0)
        expect(JSON.parse(await readFile(proof, 'utf8')) as unknown).toEqual(sourceProof)
    })
})
