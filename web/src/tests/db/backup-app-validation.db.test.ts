import { describe, expect, test } from 'bun:test'
import { SQL } from 'bun'
import { drizzle } from 'drizzle-orm/bun-sql'
import { migrate } from 'drizzle-orm/bun-sql/migrator'
import { createCipheriv, createHash, randomBytes } from 'node:crypto'
import { fileURLToPath } from 'node:url'

import {
    appDatabaseEvidenceSql,
    assertBackupAppState,
    parseAppDatabaseEvidence,
    validateLegacyHandoffParts,
} from '../../../../docker/web/validate-backup.ts'

const migrationsFolder = fileURLToPath(new URL('../../../drizzle', import.meta.url))
const configuredDatabaseUrl =
    process.env.RENTNERPROXY_MIGRATION_DATABASE_URL ?? process.env.DATABASE_URL
const isolatedDatabaseUrl =
    process.env.RENTNERPROXY_DATABASE_INTEGRATION === '1' &&
    configuredDatabaseUrl !== undefined &&
    new URL(configuredDatabaseUrl).pathname === '/rentnerproxy_upstream_test'
        ? configuredDatabaseUrl
        : null
const integrationTest = isolatedDatabaseUrl === null ? test.skip : test

const key = Buffer.alloc(32, 41)
const installation = 'backup-greeting'
const handoffParts = 20

function seal(context: string, plaintext: string) {
    const iv = randomBytes(12)
    const cipher = createCipheriv('aes-256-gcm', key, iv)
    cipher.setAAD(Buffer.from(context))
    return {
        iv,
        ciphertext: Buffer.concat([cipher.update(plaintext), cipher.final(), cipher.getAuthTag()]),
    }
}

/** Run each case against its own fully migrated database, never the shared test database. */
async function withMigratedDatabase(check: (client: SQL) => Promise<void>) {
    if (isolatedDatabaseUrl === null) throw new Error('isolated database integration is disabled')
    const databaseName = `rentnerproxy_backup_apps_${randomBytes(12).toString('hex')}`
    if (!/^rentnerproxy_backup_apps_[a-f0-9]{24}$/u.test(databaseName))
        throw new Error('unexpected backup fixture database name')
    const admin = new SQL(isolatedDatabaseUrl)
    let created = false
    let client: SQL | undefined
    try {
        await admin.unsafe(`CREATE DATABASE "${databaseName}"`)
        created = true
        const databaseUrl = new URL(isolatedDatabaseUrl)
        databaseUrl.pathname = `/${databaseName}`
        client = new SQL(databaseUrl.toString())
        await client`CREATE SCHEMA IF NOT EXISTS rentnerproxy`
        await migrate(drizzle(client), { migrationsFolder })
        await check(client)
    } finally {
        try {
            await client?.close()
        } finally {
            try {
                if (created) await admin.unsafe(`DROP DATABASE "${databaseName}"`)
            } finally {
                await admin.close()
            }
        }
    }
}

/** One retired installation with a grant, a secret, an exported and a committed handoff. */
async function seedApp(client: SQL) {
    await client`INSERT INTO rentnerproxy.app_runtime_installations (id, app_id, uid)
        VALUES (${installation}, 'fixture.greeting', 20000)`
    await client`INSERT INTO rentnerproxy.app_runtime_generations
            (installation_id, generation, state, lease_expires_at, capabilities, permission_keys)
        VALUES (${installation}, 1, 'revoked', now(), '[]'::jsonb, '[]'::jsonb),
            (${installation}, 2, 'revoked', now(), '[]'::jsonb, '[]'::jsonb)`
    await client`INSERT INTO rentnerproxy.app_runtime_grants
            (installation_id, capability_id, scope, resource_id)
        VALUES (${installation}, 'fixture.capability', 'fixture', 'resource')`
    const secret = seal(`app-runtime-secret:v1:${installation}:token`, 'synthetic token')
    await client`INSERT INTO rentnerproxy.app_runtime_secrets (installation_id, id, ciphertext, iv)
        VALUES (${installation}, 'token', ${secret.ciphertext}, ${secret.iv})`
    const hashes: string[] = []
    for (let sequence = 0; sequence < handoffParts; sequence++) {
        const plaintext = JSON.stringify({ synthetic: 'dns', sequence })
        const sha256 = createHash('sha256').update(plaintext).digest('hex')
        hashes.push(sha256)
        const part = seal(
            `legacy-feature-handoff:v1:dns:${installation}:${sequence}:${sha256}`,
            plaintext,
        )
        // oxlint-disable-next-line no-await-in-loop -- Parts are inserted in sequence order.
        await client`INSERT INTO rentnerproxy.legacy_feature_handoff_parts
                (domain, sequence, sha256, ciphertext, iv)
            VALUES ('dns', ${sequence}, ${sha256}, ${part.ciphertext}, ${part.iv})`
    }
    await client`INSERT INTO rentnerproxy.legacy_feature_handoffs
            (domain, installation_id, state, digest, part_count, committed_at)
        VALUES ('dns', ${installation}, 'exported', ${'a'.repeat(64)}, ${handoffParts}, NULL),
            ('oidc', ${installation}, 'committed', ${'b'.repeat(64)}, 3, now())`
}

async function readEvidence(client: SQL, handoffs = true) {
    const [row] = await client.unsafe<{ evidence: unknown }[]>(appDatabaseEvidenceSql(handoffs))
    return parseAppDatabaseEvidence(row?.evidence)
}

const journal = (generation: number) => [
    { id: installation, appId: 'fixture.greeting', uid: 20000, generation },
]

describe('backup app state validation against a migrated database', () => {
    integrationTest(
        'reads app rows, references and generations and accepts a matching journal',
        async () => {
            await withMigratedDatabase(async (client) => {
                expect(await readEvidence(client)).toEqual({
                    installations: [],
                    references: [],
                    generations: [],
                })
                await seedApp(client)
                for (const handoffs of [true, false]) {
                    // oxlint-disable-next-line no-await-in-loop -- Both schema shapes in turn.
                    const evidence = await readEvidence(client, handoffs)
                    expect(evidence).toEqual({
                        installations: [
                            { id: installation, appId: 'fixture.greeting', uid: 20000 },
                        ],
                        references: [installation],
                        generations: [{ installationId: installation, generation: 2 }],
                    })
                    expect(() => assertBackupAppState(journal(2), evidence)).not.toThrow()
                    expect(() => assertBackupAppState(journal(5), evidence)).not.toThrow()
                }
                await validateLegacyHandoffParts(client, key)
            })
        },
        60_000,
    )

    integrationTest(
        'rejects a journal behind the database and rows outside the inventory',
        async () => {
            await withMigratedDatabase(async (client) => {
                await seedApp(client)
                const seeded = await readEvidence(client)
                expect(() => assertBackupAppState(journal(1), seeded)).toThrow(
                    'App database generation is ahead of the native installation journal',
                )
                // A dump without its foreign keys can carry rows of an installation it lacks.
                await client`ALTER TABLE rentnerproxy.app_runtime_grants
                    DROP CONSTRAINT app_runtime_grants_installation_id_app_runtime_installations_id_fk`
                await client`INSERT INTO rentnerproxy.app_runtime_grants
                        (installation_id, capability_id, scope, resource_id)
                    VALUES ('removed-app', 'fixture.capability', 'fixture', 'resource')`
                const orphaned = await readEvidence(client)
                expect(orphaned.references).toEqual([installation, 'removed-app'])
                expect(() => assertBackupAppState(journal(2), orphaned)).toThrow(
                    'App database rows reference installations outside the backup inventory',
                )
            })
        },
        60_000,
    )

    integrationTest(
        'rejects incomplete, committed and foreign handoff parts',
        async () => {
            await withMigratedDatabase(async (client) => {
                await seedApp(client)
                await expect(
                    validateLegacyHandoffParts(client, Buffer.alloc(32, 42)),
                ).rejects.toThrow('backup application key cannot decrypt persisted secrets')
                await client`DELETE FROM rentnerproxy.legacy_feature_handoff_parts
                    WHERE domain = 'dns' AND sequence = 7`
                await expect(validateLegacyHandoffParts(client, key)).rejects.toThrow(
                    'Invalid legacy feature handoff parts',
                )
                await client`UPDATE rentnerproxy.legacy_feature_handoffs
                    SET part_count = ${handoffParts - 1} WHERE domain = 'dns'`
                await expect(validateLegacyHandoffParts(client, key)).rejects.toThrow(
                    'Invalid legacy feature handoff parts',
                )
                await client`DELETE FROM rentnerproxy.legacy_feature_handoff_parts`
                await client`UPDATE rentnerproxy.legacy_feature_handoffs SET part_count = 0`
                await validateLegacyHandoffParts(client, key)
                const stray = seal('legacy-feature-handoff:v1:oidc:x:0:' + 'c'.repeat(64), 'x')
                await client`INSERT INTO rentnerproxy.legacy_feature_handoff_parts
                        (domain, sequence, sha256, ciphertext, iv)
                    VALUES ('oidc', 0, ${'c'.repeat(64)}, ${stray.ciphertext}, ${stray.iv})`
                await expect(validateLegacyHandoffParts(client, key)).rejects.toThrow(
                    'Invalid legacy feature handoff parts',
                )
            })
        },
        60_000,
    )
})
