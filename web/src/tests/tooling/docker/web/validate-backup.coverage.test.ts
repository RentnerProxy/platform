import { afterEach, describe, expect, mock, test } from 'bun:test'
import { Database } from 'bun:sqlite'
import { createCipheriv, createHash } from 'node:crypto'
import { mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'
import { coverageFixtureSource } from '@/tests/Helpers/coverageFixture.ts'

const prefix = join(tmpdir(), 'rentnerproxy-validate-backup-coverage-')
const directories: string[] = []
const rows = new Map<string, unknown[]>()
let closed = 0
function fixtureRows(query: string) {
    const entry = [...rows.entries()].find(([table]) => query.includes(table))
    if (!entry) throw new Error('Unexpected fixture SQL query.')
    return entry[1]
}
await mock.module('rentnerproxy-coverage-sql-fixture', () => ({
    SQL: function () {
        return Object.assign(async (query: TemplateStringsArray) => fixtureRows(query.join('')), {
            unsafe: async (query: string) => fixtureRows(query),
            close: async () => {
                closed += 1
            },
        })
    },
}))
afterEach(async () => {
    await Promise.all(
        directories.splice(0).map(async (directory) => {
            if (!resolve(directory).startsWith(resolve(prefix)))
                throw new Error('Unsafe fixture cleanup.')
            await rm(directory, { recursive: true, force: true })
        }),
    )
})

const id = '0198d98a-0000-7000-8000-000000000881'
const key = Buffer.alloc(32, 6)
function encrypted(context: string, plaintext = 'synthetic fixture secret') {
    const iv = Buffer.alloc(12, 7)
    const cipher = createCipheriv('aes-256-gcm', key, iv)
    cipher.setAAD(Buffer.from(context))
    const ciphertext = Buffer.concat([
        cipher.update(plaintext),
        cipher.final(),
        cipher.getAuthTag(),
    ])
    return { iv, ciphertext }
}

function handoffPart(domain: string, installation: string, sequence: number) {
    const plaintext = JSON.stringify({ synthetic: domain, sequence })
    const sha256 = createHash('sha256').update(plaintext).digest('hex')
    const context = `legacy-feature-handoff:v1:${domain}:${installation}:${sequence}:${sha256}`
    return {
        domain,
        sequence,
        sha256,
        installation_id: installation,
        ...encrypted(context, plaintext),
    }
}

const app = { id: 'app-greeting', appId: 'rentnerproxy.greeting', uid: 20000 }

function handoffParts(count: number, first = 0) {
    return [{ domain: 'dns', count, distinct: count, first, last: first + count - 1 }]
}

function appEvidence(
    installations: readonly { id: string; appId: string; uid: number }[],
    generation = 1,
) {
    return [
        {
            evidence: JSON.stringify({
                installations,
                references: installations.map((installation) => installation.id),
                generations: installations.map((installation) => ({
                    installationId: installation.id,
                    generation,
                })),
            }),
        },
    ]
}

async function fixture(database = true) {
    rows.clear()
    closed = 0
    const directory = await mkdtemp(prefix)
    directories.push(directory)
    const backup = join(directory, 'backup')
    const archive = join(directory, 'archive')
    const migrations = join(directory, 'migrations')
    const controller = join(directory, 'controller')
    await Promise.all([
        mkdir(backup),
        mkdir(join(archive, 'data'), { recursive: true }),
        mkdir(join(archive, 'credentials'), { recursive: true }),
        mkdir(join(archive, 'bouncer'), { recursive: true }),
        mkdir(join(migrations, 'meta'), { recursive: true }),
    ])
    const migration = Buffer.from('synthetic migration fixture')
    await Promise.all([
        writeFile(join(migrations, 'fixture.sql'), migration),
        writeFile(
            join(migrations, 'meta/_journal.json'),
            JSON.stringify({ entries: [{ tag: 'fixture', when: 1 }] }),
        ),
        writeFile(join(backup, 'metadata.json'), JSON.stringify({ version: 4 })),
        writeFile(join(backup, 'app-encryption-key'), key.toString('base64')),
        writeFile(
            join(archive, 'credentials/local_api_credentials.yaml'),
            'url: http://127.0.0.1:18080\nlogin: synthetic\npassword: synthetic-fixture\n',
        ),
        writeFile(join(archive, 'bouncer/caddy-bouncer-key'), 'a'.repeat(64)),
    ])
    if (database) {
        const sqlite = new Database(join(archive, 'data/crowdsec.db'))
        try {
            sqlite.run('CREATE TABLE fixture (id INTEGER PRIMARY KEY)')
        } finally {
            sqlite.close()
        }
    }
    const pack = async () => {
        const child = Bun.spawn(
            ['tar', '-cf', join(backup, 'crowdsec-state.tar'), '-C', archive, '.'],
            { stdout: 'ignore', stderr: 'pipe' },
        )
        const [status, stderr] = await Promise.all([
            child.exited,
            new Response(child.stderr).text(),
        ])
        expect(status, stderr).toBe(0)
    }
    await pack()
    const totp = encrypted('rentnerproxy:totp:' + id)
    const certificate = encrypted('certificate-binding-job:' + id)
    const notification = encrypted('rentnerproxy:notifications:v1:' + id)
    const crowdsec = encrypted('crowdsec_configuration_v1:external_api_key')
    rows.set('drizzle.__drizzle_migrations', [
        { hash: createHash('sha256').update(migration).digest('hex'), created_at: 1 },
    ])
    rows.set("to_regclass('rentnerproxy.app_runtime_installations')", [
        { present: false, handoffs: false, parts: false },
    ])
    rows.set('rentnerproxy.user_totp_factors', [
        { user_id: id, secret_ciphertext: totp.ciphertext, secret_iv: totp.iv },
    ])
    rows.set('rentnerproxy.certificate_binding_jobs', [
        { id, request_ciphertext: certificate.ciphertext, request_iv: certificate.iv },
    ])
    rows.set("key = 'notification_configuration_v1'", [
        {
            value: {
                version: 1,
                revision: 1,
                enabled: false,
                pausedAfterRestore: true,
                channels: [
                    {
                        id,
                        destination: {
                            ciphertext: notification.ciphertext.toString('base64url'),
                            iv: notification.iv.toString('base64url'),
                        },
                    },
                ],
            },
        },
    ])
    rows.set("key = 'crowdsec_configuration_v1'", [
        {
            value: JSON.stringify({
                mode: database ? 'managed' : 'external',
                external: {
                    apiKey: {
                        ciphertext: crowdsec.ciphertext.toString('base64url'),
                        iv: crowdsec.iv.toString('base64url'),
                    },
                },
            }),
        },
    ])
    const root = fileURLToPath(new URL('../../../../../../', import.meta.url))
    const original = await coverageFixtureSource('docker/web/validate-backup.ts')
    const source = original
        .replace(/from\s*(['"])bun\1/gu, "from 'rentnerproxy-coverage-sql-fixture'")
        .replaceAll('/usr/local/bin/rentnerproxy-controller', controller.replaceAll('\\', '/'))
        .replaceAll('/opt/rentnerproxy/web/web/drizzle', migrations.replaceAll('\\', '/'))
        .replaceAll(
            '../../web/src/lib/ApplicationVersion/backupCompatibility.ts',
            pathToFileURL(join(root, 'web/src/lib/ApplicationVersion/backupCompatibility.ts')).href,
        )
    const modulePath = join(directory, 'validate.ts')
    await writeFile(modulePath, source)
    const module = (await import(
        pathToFileURL(modulePath).href
    )) as typeof import('../../../../../../docker/web/validate-backup.ts')
    return {
        directory,
        backup,
        archive,
        migrations,
        controller,
        pack,
        validate: () =>
            module.validateDatabase(
                backup,
                1,
                join(directory, 'extracted'),
                join(directory, 'no-live-postgres-socket'),
            ),
    }
}

async function writeAppBackup(
    context: Awaited<ReturnType<typeof fixture>>,
    version: 5 | 6,
    decodable = true,
) {
    const name = version === 6 ? '.rentnerproxy-app-state-v2' : '.rentnerproxy-app-state-v1'
    const action = version === 6 ? 'inspect-portable' : 'inspect'
    const path = join(context.backup, name)
    const expected = ['--app-backup', action, path]
    await Promise.all([
        writeFile(
            join(context.backup, 'metadata.json'),
            JSON.stringify({
                version,
                applications: { installations: [{ ...app, generation: 1 }] },
            }),
        ),
        writeFile(path, decodable ? 'valid fixture member' : 'damaged fixture member'),
        writeFile(
            context.controller,
            [
                '#!/usr/bin/env -S bun --no-env-file',
                'const actual = process.argv.slice(2)',
                'if (JSON.stringify(actual) !== ' +
                    JSON.stringify(JSON.stringify(expected)) +
                    ') process.exit(2)',
                "if ((await Bun.file(actual[2]).text()) !== 'valid fixture member') process.exit(1)",
            ].join('\n'),
            { mode: 0o700 },
        ),
    ])
    rows.set("to_regclass('rentnerproxy.app_runtime_installations')", [
        { present: true, handoffs: true, parts: true },
    ])
    rows.set('json_build_object', appEvidence([app]))
    rows.set('FROM rentnerproxy.app_runtime_generations', [{ quiet: true }])
    const credential = encrypted('app-runtime-secret:v1:' + app.id + ':' + id)
    rows.set('FROM rentnerproxy.app_runtime_secrets', [
        { installation_id: app.id, id, ciphertext: credential.ciphertext, iv: credential.iv },
    ])
    rows.set('FROM rentnerproxy.legacy_feature_handoffs ORDER BY', [
        { domain: 'dns', installation_id: app.id, state: 'exported', part_count: 1 },
        { domain: 'oidc', installation_id: app.id, state: 'committed', part_count: 2 },
    ])
    rows.set('GROUP BY domain', [{ domain: 'dns', count: 1, distinct: 1, first: 0, last: 0 }])
    rows.set('legacy_feature_handoff_parts stored', [handoffPart('dns', app.id, 0)])
    return app
}

describe('backup database validation with isolated storage and injected SQL rows', () => {
    test('authenticates stored secrets and verifies a real extracted SQLite database before closing SQL', async () => {
        const context = await fixture()
        await context.validate()
        expect(closed).toBe(1)
        expect(
            await readFile(join(context.directory, 'extracted/bouncer/caddy-bouncer-key'), 'utf8'),
        ).toBe('a'.repeat(64))
    })

    test('rejects a legacy snapshot whose database contains a native installation', async () => {
        const context = await fixture(false)
        rows.set("to_regclass('rentnerproxy.app_runtime_installations')", [
            { present: true, handoffs: false, parts: false },
        ])
        rows.set('json_build_object', appEvidence([{ id: 'kiri', appId: 'dev.kiri', uid: 20000 }]))
        await expect(context.validate()).rejects.toThrow('App database identities differ')
        expect(closed).toBe(1)
    })

    test('accepts a legacy snapshot whose app tables, handoff journal included, are empty', async () => {
        const context = await fixture(false)
        rows.set("to_regclass('rentnerproxy.app_runtime_installations')", [
            { present: true, handoffs: true, parts: true },
        ])
        rows.set('json_build_object', appEvidence([]))
        rows.set('FROM rentnerproxy.legacy_feature_handoffs ORDER BY', [])
        rows.set('GROUP BY domain', [])
        rows.set('legacy_feature_handoff_parts stored', [])
        await context.validate()
        expect(closed).toBe(1)
    })

    test.each([
        { present: false, handoffs: true, parts: true },
        { present: true, handoffs: true, parts: false },
        { present: true, handoffs: null, parts: null },
    ])('rejects inconsistent app schema evidence %#', async (schema) => {
        const context = await fixture(false)
        rows.set("to_regclass('rentnerproxy.app_runtime_installations')", [schema])
        await expect(context.validate()).rejects.toThrow('Invalid application schema evidence')
        expect(closed).toBe(1)
    })

    test('rejects a legacy snapshot with app rows outside any installation', async () => {
        const context = await fixture(false)
        rows.set("to_regclass('rentnerproxy.app_runtime_installations')", [
            { present: true, handoffs: false, parts: false },
        ])
        rows.set('json_build_object', [
            {
                evidence: JSON.stringify({
                    installations: [],
                    references: ['kiri'],
                    generations: [],
                }),
            },
        ])
        await expect(context.validate()).rejects.toThrow(
            'App database rows reference installations outside the backup inventory',
        )
        expect(closed).toBe(1)
    })

    test.skipIf(process.platform === 'win32').each([5, 6] as const)(
        'validates the v%s app snapshot with its decoder and authenticates app database secrets',
        async (version) => {
            const context = await fixture(false)
            await writeAppBackup(context, version)
            await context.validate()
            expect(closed).toBe(1)
        },
    )

    test.skipIf(process.platform === 'win32')(
        'rejects a corrupt portable app snapshot before opening the database',
        async () => {
            const context = await fixture(false)
            await writeAppBackup(context, 6, false)
            await expect(context.validate()).rejects.toThrow('Invalid application file snapshot')
            expect(closed).toBe(0)
        },
    )

    test.skipIf(process.platform === 'win32').each([
        [
            'live-generation',
            () => rows.set('FROM rentnerproxy.app_runtime_generations', [{ quiet: false }]),
            'App generation has not retired',
        ],
        [
            'invalid-secret',
            () =>
                rows.set('FROM rentnerproxy.app_runtime_secrets', [
                    { installation_id: app.id, id, ciphertext: null, iv: Buffer.alloc(12) },
                ]),
            'Invalid application backup secret',
        ],
        [
            'foreign-grant',
            () =>
                rows.set('json_build_object', [
                    {
                        evidence: JSON.stringify({
                            installations: [app],
                            references: [app.id, 'removed-app'],
                            generations: [{ installationId: app.id, generation: 1 }],
                        }),
                    },
                ]),
            'App database rows reference installations outside the backup inventory',
        ],
        [
            'generation-ahead',
            () => rows.set('json_build_object', appEvidence([app], 2)),
            'App database generation is ahead of the native installation journal',
        ],
        [
            'malformed-evidence',
            () => rows.set('json_build_object', [{ evidence: '{' }]),
            'Invalid application schema evidence',
        ],
        [
            'missing-handoff-part',
            () => rows.set('GROUP BY domain', []),
            'Invalid legacy feature handoff parts',
        ],
        [
            'handoff-sequence-gap',
            () => rows.set('GROUP BY domain', handoffParts(1, 1)),
            'Invalid legacy feature handoff parts',
        ],
        [
            'committed-handoff-parts',
            () =>
                rows.set('GROUP BY domain', [
                    ...handoffParts(1),
                    { domain: 'oidc', count: 2, distinct: 2, first: 0, last: 1 },
                ]),
            'Invalid legacy feature handoff parts',
        ],
        [
            'oversized-handoff-part',
            () =>
                rows.set('legacy_feature_handoff_parts stored', [
                    { ...handoffPart('dns', app.id, 0), ciphertext: null },
                ]),
            'Invalid legacy feature handoff parts',
        ],
        [
            'foreign-handoff-part',
            () =>
                rows.set('legacy_feature_handoff_parts stored', [
                    { ...handoffPart('dns', 'other-app', 0), installation_id: app.id },
                ]),
            'backup application key cannot decrypt persisted secrets',
        ],
        [
            'changed-handoff-content',
            () =>
                rows.set('legacy_feature_handoff_parts stored', [
                    { ...handoffPart('dns', app.id, 0), sha256: 'f'.repeat(64) },
                ]),
            'backup application key cannot decrypt persisted secrets',
        ],
    ] as const)(
        'fails closed while validating a portable backup with %s evidence',
        async (_scenario, mutate, message) => {
            const context = await fixture(false)
            await writeAppBackup(context, 6)
            mutate()
            await expect(context.validate()).rejects.toThrow(message)
            expect(closed).toBe(1)
        },
    )

    test.skipIf(process.platform === 'win32')(
        'rejects a handoff part whose authenticated content differs from its recorded digest',
        async () => {
            const context = await fixture(false)
            await writeAppBackup(context, 6)
            const sha256 = 'e'.repeat(64)
            const additionalData = `legacy-feature-handoff:v1:dns:${app.id}:0:${sha256}`
            rows.set('legacy_feature_handoff_parts stored', [
                {
                    domain: 'dns',
                    sequence: 0,
                    sha256,
                    installation_id: app.id,
                    ...encrypted(additionalData, '{"synthetic":"tampered"}'),
                },
            ])
            await expect(context.validate()).rejects.toThrow('Invalid legacy feature handoff parts')
            expect(closed).toBe(1)
        },
    )

    test('accepts an external-only backup without a managed CrowdSec database', async () => {
        const context = await fixture(false)
        await context.validate()
        expect(closed).toBe(1)
    })

    test.each([true, false])(
        'validates canonical raw CrowdSec credentials (canonical: %s)',
        async (canonical) => {
            const context = await fixture()
            const rawCredential = Buffer.alloc(32, 255).toString('base64').slice(0, -1)
            await writeFile(
                join(context.archive, 'bouncer/caddy-bouncer-key'),
                canonical ? rawCredential : rawCredential.slice(0, -1) + 'B',
            )
            await context.pack()
            if (canonical) await context.validate()
            else await expect(context.validate()).rejects.toThrow('invalid CrowdSec bouncer key')
            expect(closed).toBe(1)
        },
    )

    test.each([
        'journal',
        'migration',
        'totp',
        'certificate',
        'notification',
        'crowdsec',
        'archive',
        'credentials',
        'bouncer',
    ])('fails closed for invalid %s evidence and still closes SQL', async (kind) => {
        const context = await fixture()
        if (kind === 'journal')
            await writeFile(join(context.migrations, 'meta/_journal.json'), '{}')
        if (kind === 'migration')
            rows.set('drizzle.__drizzle_migrations', [{ hash: 'wrong', created_at: 1 }])
        if (kind === 'totp')
            rows.set('rentnerproxy.user_totp_factors', [
                { user_id: id, secret_ciphertext: Buffer.alloc(17), secret_iv: Buffer.alloc(12) },
            ])
        if (kind === 'certificate')
            rows.set('rentnerproxy.certificate_binding_jobs', [
                { id, request_ciphertext: Buffer.alloc(17), request_iv: Buffer.alloc(12) },
            ])
        if (kind === 'notification')
            rows.set("key = 'notification_configuration_v1'", [{ value: '{}' }])
        if (kind === 'crowdsec')
            rows.set("key = 'crowdsec_configuration_v1'", [
                { value: { mode: 'external', external: { apiKey: { ciphertext: 1 } } } },
            ])
        if (kind === 'archive')
            await writeFile(join(context.backup, 'crowdsec-state.tar'), 'invalid archive')
        if (kind === 'credentials') {
            await writeFile(
                join(context.archive, 'credentials/local_api_credentials.yaml'),
                'url: https://outside.example.test\nlogin: synthetic\npassword: synthetic\n',
            )
            await context.pack()
        }
        if (kind === 'bouncer') {
            await writeFile(join(context.archive, 'bouncer/caddy-bouncer-key'), 'invalid')
            await context.pack()
        }
        await expect(context.validate()).rejects.toThrow()
        expect(closed).toBe(1)
    })

    test('requires the managed database even when all encrypted configuration secrets authenticate', async () => {
        const context = await fixture(false)
        rows.set("key = 'crowdsec_configuration_v1'", [{ value: { mode: 'managed' } }])
        await expect(context.validate()).rejects.toThrow('managed CrowdSec database is missing')
        expect(closed).toBe(1)
    })
})
