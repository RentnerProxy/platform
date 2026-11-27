import { expect, test } from 'bun:test'

import {
    activateAppRuntimeGenerationInTransaction,
    readAppIncidentCategoriesInTransaction,
    registerAppRuntimeGenerationInTransaction,
} from '@/server/AppRuntime/lifecycle.server.ts'
import { manageAppRuntime } from '@/server/AppRuntime/management.server.ts'
import type { AuthTransaction } from '@/server/Auth/Core/Types/database.types.ts'

const integrationEnabled =
    process.env.RENTNERPROXY_DATABASE_INTEGRATION === '1' && Boolean(process.env.DATABASE_URL)
const integrationTest = integrationEnabled ? test : test.skip

const rolledBack = new Error('incident category test rollback')
const categories = [
    { id: 'disk-full', name: 'Disk full', resource: 'none' },
    { id: 'upstream-down', name: 'Upstream down', resource: 'proxyHost' },
] as const

function identityOf(uid: number) {
    return { installationId: crypto.randomUUID(), appId: 'fixture.incidents', uid, generation: 1 }
}

/** Run a scenario in a transaction that is always rolled back. */
async function scenario(body: (transaction: AuthTransaction) => Promise<void>): Promise<void> {
    const { db } = await import('@/db/index.ts')
    await expect(
        db.transaction(async (transaction) => {
            await body(transaction)
            throw rolledBack
        }),
    ).rejects.toBe(rolledBack)
}

integrationTest('registered incident categories are read back from the active generation', () =>
    scenario(async (transaction) => {
        const identity = identityOf(40_601)
        const leaseExpiresAt = new Date(Date.now() + 60_000)
        await registerAppRuntimeGenerationInTransaction(transaction, {
            identity,
            leaseExpiresAt,
            capabilities: [],
            incidentCategories: categories,
        })
        // A preparing generation does not yet declare anything for the installation.
        expect(
            await readAppIncidentCategoriesInTransaction(transaction, identity.installationId),
        ).toEqual([])
        await activateAppRuntimeGenerationInTransaction(transaction, identity, leaseExpiresAt)
        expect(
            await readAppIncidentCategoriesInTransaction(transaction, identity.installationId),
        ).toEqual(categories)
        expect(await readAppIncidentCategoriesInTransaction(transaction, 'unknown')).toEqual([])
    }),
)

integrationTest('a registration without categories declares none', () =>
    scenario(async (transaction) => {
        const identity = identityOf(40_602)
        const leaseExpiresAt = new Date(Date.now() + 60_000)
        await registerAppRuntimeGenerationInTransaction(transaction, {
            identity,
            leaseExpiresAt,
            capabilities: [],
        })
        await activateAppRuntimeGenerationInTransaction(transaction, identity, leaseExpiresAt)
        expect(
            await readAppIncidentCategoriesInTransaction(transaction, identity.installationId),
        ).toEqual([])
    }),
)

const invalid = [
    [categories[0], categories[0]],
    [{ id: 'bad id', name: 'Name', resource: 'none' }],
    [{ id: 'ok', name: '', resource: 'none' }],
    [{ id: 'ok', name: 'x'.repeat(81), resource: 'none' }],
    [{ id: 'ok', name: 'Line\nbreak', resource: 'none' }],
    [{ id: 'ok', name: 'Line separator', resource: 'none' }],
    [{ id: 'ok', name: 'Bidi‮flip', resource: 'none' }],
    [{ id: 'ok', name: 'Name', resource: 'dockerHost' }],
    Array.from({ length: 17 }, (_, index) => ({
        id: `category-${index}`,
        name: 'Name',
        resource: 'none',
    })),
]
for (const [index, incidentCategories] of invalid.entries())
    integrationTest(`invalid incident categories are refused (${index})`, () =>
        scenario(async (transaction) => {
            await expect(
                registerAppRuntimeGenerationInTransaction(transaction, {
                    identity: identityOf(40_603),
                    leaseExpiresAt: new Date(Date.now() + 60_000),
                    capabilities: [],
                    incidentCategories: incidentCategories as never,
                }),
            ).rejects.toThrow()
        }),
    )

integrationTest('registering the same generation again must declare the same categories', () =>
    scenario(async (transaction) => {
        const identity = identityOf(40_604)
        const leaseExpiresAt = new Date(Date.now() + 60_000)
        const register = (incidentCategories: readonly (typeof categories)[number][]) =>
            registerAppRuntimeGenerationInTransaction(transaction, {
                identity,
                leaseExpiresAt,
                capabilities: [],
                incidentCategories,
            })
        await register(categories)
        await register(categories)
        await expect(register([categories[0]])).rejects.toThrow()
    }),
)

integrationTest('the management registration validates the declared categories', async () => {
    const identity = identityOf(40_605)
    const register = (incidentCategories: unknown) =>
        manageAppRuntime(
            'register',
            {
                identity,
                leaseExpiresAt: new Date(Date.now() + 60_000).toISOString(),
                capabilities: [],
                incidentCategories,
            },
            new AbortController().signal,
        )
    await expect(register([{ id: 'a', name: 'A', resource: 'bogus' }])).rejects.toMatchObject({
        status: 400,
    })
    await expect(register([categories[0], categories[0]])).rejects.toMatchObject({ status: 400 })
})
