import { randomUUID } from 'node:crypto'
import { afterEach, beforeAll, beforeEach, describe, expect, test } from 'bun:test'
import { eq, inArray, sql } from 'drizzle-orm'
import { PERMISSIONS } from '@/config/permissions.config.ts'
import {
    appRuntimeGenerations,
    appRuntimeOwnedProxyHosts,
    legacyFeatureHandoffs,
    permissions,
    proxyHosts,
    rolePermissions,
    roles,
    userRoles,
    users,
} from '@/db/schema.ts'
import { APP_RUNTIME_SUPPORT_CAPABILITIES } from '@/server/AppRuntime/authority-policy.server.ts'
import {
    activateAppRuntimeGenerationInTransaction,
    recordAppRuntimeProvidersInTransaction,
    registerAppRuntimeGenerationInTransaction,
    replaceAppRuntimeGrantsInTransaction,
} from '@/server/AppRuntime/lifecycle.server.ts'
import type { AppRuntimeGrant } from '@/server/AppRuntime/Types/authority.types.ts'
import { ensureAuthorizationRegistryInTransaction } from '@/server/Auth/Access/registry.service.ts'
import { getAuthDatabase } from '@/server/Auth/Core/database.server.ts'
import { getDatabaseUrl } from '@/server/env.server.ts'
import { removeEventApps } from '@/tests/Helpers/appHostEvents.ts'

const enabled = process.env.RENTNERPROXY_DATABASE_INTEGRATION === '1' && getDatabaseUrl() !== null
const integrationTest = enabled ? test : test.skip
const marker = 'monitoring-app-context.invalid'
const readHosts = { id: 'proxy.hosts.read.v1', scope: 'proxyHosts' } as const
const allHosts = { id: readHosts.id, scope: 'allProxyHosts' } as const
const provider = { id: 'monitor-main', profile: 'monitoring', version: '1.0.0' }
const installed: { appId: string; installationId: string; generation: number; uid: number }[] = []
const userIds: string[] = []
const roleIds: string[] = []
const appRuntime = process.env.RENTNERPROXY_APP_RUNTIME
let nextUid = 41_800

const hostGrant = (resourceId: string, allowService = true): AppRuntimeGrant => ({
    capability: readHosts,
    resourceId,
    allowService,
})
const everyHostGrant: AppRuntimeGrant = {
    capability: allHosts,
    resourceId: 'all',
    allowService: true,
}

interface InstallOptions {
    readonly grants?: readonly AppRuntimeGrant[]
    readonly providers?: readonly (typeof provider)[]
    readonly providerGrant?: boolean | 'client-only'
    readonly activate?: boolean
    readonly expired?: boolean
    readonly handoff?: 'committed' | 'exported' | null
}

/** An app with a monitoring provider; options break one precondition at a time. */
async function installApp({
    grants = [],
    providers = [provider],
    providerGrant = true,
    activate = true,
    expired = false,
    handoff = 'committed',
}: InstallOptions = {}) {
    const { db } = await import('@/db/index.ts')
    const identity = {
        appId: 'test.monitoring-context',
        installationId: randomUUID(),
        generation: 1,
        uid: nextUid++,
    }
    installed.push(identity)
    const leaseExpiresAt = new Date(Date.now() + 120_000)
    const registersMonitoring = providers.some(({ profile }) => profile === 'monitoring')
    await getAuthDatabase().transaction(async (transaction) => {
        await registerAppRuntimeGenerationInTransaction(transaction, {
            identity,
            leaseExpiresAt,
            capabilities: [readHosts],
            providerProfiles: [...new Set(providers.map(({ profile }) => profile))],
        })
        if (providers.length > 0)
            await recordAppRuntimeProvidersInTransaction(transaction, identity, providers)
        await replaceAppRuntimeGrantsInTransaction(transaction, identity, [
            ...(registersMonitoring && providerGrant === true
                ? [
                      {
                          capability: APP_RUNTIME_SUPPORT_CAPABILITIES.provider,
                          resourceId: 'monitoring',
                          allowService: true,
                      },
                  ]
                : registersMonitoring && providerGrant === 'client-only'
                  ? [
                        {
                            capability: APP_RUNTIME_SUPPORT_CAPABILITIES.provider,
                            resourceId: 'monitoring',
                            allowService: false,
                        },
                    ]
                  : []),
            ...grants,
        ])
        if (activate)
            await activateAppRuntimeGenerationInTransaction(transaction, identity, leaseExpiresAt)
    })
    if (expired)
        await db
            .update(appRuntimeGenerations)
            .set({ leaseExpiresAt: new Date(Date.now() - 1_000) })
            .where(eq(appRuntimeGenerations.installationId, identity.installationId))
    if (handoff !== null)
        await db.insert(legacyFeatureHandoffs).values({
            domain: 'monitoring',
            installationId: identity.installationId,
            state: handoff,
            digest: 'a'.repeat(64),
            partCount: 0,
            ...(handoff === 'committed' && { committedAt: new Date() }),
        })
    return identity
}

async function seedHosts(count: number): Promise<string[]> {
    const { db } = await import('@/db/index.ts')
    if (count === 0) return []
    await db.execute(sql`
        insert into ${proxyHosts} (id, forward_scheme, forward_host, forward_port)
        select uuidv7(), 'http', ${marker}, 8080 from generate_series(1, ${count})`)
    await db.execute(sql`
        insert into rentnerproxy.host_domains (proxy_host_id, domain)
        select id, 'ctx-' || replace(id::text, '-', '') || '.example.test'
        from ${proxyHosts} where forward_host = ${marker}`)
    const rows = await db
        .select({ id: proxyHosts.id })
        .from(proxyHosts)
        .where(eq(proxyHosts.forwardHost, marker))
        .orderBy(proxyHosts.id)
    return rows.map(({ id }) => id)
}

async function createUser(permissionKeys: readonly string[]) {
    const { db } = await import('@/db/index.ts')
    const id = randomUUID()
    userIds.push(id)
    await db.insert(users).values({
        id,
        displayName: 'Monitoring context fixture',
        email: `${id}@monitoring-app-context.invalid`,
        status: 'active',
    })
    const roleId = randomUUID()
    roleIds.push(roleId)
    await db.insert(roles).values({ id: roleId, key: `ctx-${roleId}`, name: 'Context fixture' })
    const selected = await db
        .select({ id: permissions.id })
        .from(permissions)
        .where(inArray(permissions.key, [...permissionKeys]))
    if (selected.length > 0)
        await db
            .insert(rolePermissions)
            .values(selected.map((permission) => ({ roleId, permissionId: permission.id })))
    await db.insert(userRoles).values({ userId: id, roleId })
    return id
}

async function own(installationId: string, hostId: string, proxyHostId: string) {
    const { db } = await import('@/db/index.ts')
    await db.insert(appRuntimeOwnedProxyHosts).values({ installationId, hostId, proxyHostId })
}

async function resetHandoff(installationId: string) {
    const { db } = await import('@/db/index.ts')
    await db
        .delete(legacyFeatureHandoffs)
        .where(eq(legacyFeatureHandoffs.installationId, installationId))
}

async function context(actor: string, ids: readonly string[]) {
    const { readContext } =
        await import('@/server/HostMonitoring/host-monitoring-app.context.server.ts')
    return readContext(actor, ids)
}

describe('monitoring app context (PostgreSQL)', () => {
    beforeAll(async () => {
        if (!enabled) return
        const { db } = await import('@/db/index.ts')
        const [held] = await db.select().from(legacyFeatureHandoffs)
        if (held) throw new Error('A legacy handoff exists; use an isolated database.')
        const [existing] = await db.select({ id: proxyHosts.id }).from(proxyHosts).limit(1)
        // The limit follows the number of all hosts, so the database must hold no others.
        if (existing) throw new Error('Proxy hosts exist; use an isolated database.')
        await db.transaction(ensureAuthorizationRegistryInTransaction)
    })

    beforeEach(() => {
        process.env.RENTNERPROXY_APP_RUNTIME = '1'
    })

    afterEach(async () => {
        if (!enabled) return
        const { db } = await import('@/db/index.ts')
        const ids = installed.splice(0)
        if (ids.length > 0)
            await db.delete(legacyFeatureHandoffs).where(
                inArray(
                    legacyFeatureHandoffs.installationId,
                    ids.map(({ installationId }) => installationId),
                ),
            )
        await db.delete(proxyHosts).where(eq(proxyHosts.forwardHost, marker))
        await removeEventApps(ids)
        if (userIds.length > 0) await db.delete(users).where(inArray(users.id, userIds.splice(0)))
        if (roleIds.length > 0) await db.delete(roles).where(inArray(roles.id, roleIds.splice(0)))
        if (appRuntime === undefined) delete process.env.RENTNERPROXY_APP_RUNTIME
        else process.env.RENTNERPROXY_APP_RUNTIME = appRuntime
    })

    integrationTest('platform and an open handoff still own monitoring', async () => {
        const actor = await createUser([PERMISSIONS.PROXY_HOSTS_VIEW])
        const [host] = await seedHosts(1)
        expect(await context(actor, [host!])).toEqual({ owner: 'platform' })
        await installApp({ handoff: 'exported', grants: [everyHostGrant] })
        expect(await context(actor, [host!])).toEqual({ owner: 'platform' })
    })

    integrationTest('a user without the view permission is rejected', async () => {
        const [host] = await seedHosts(1)
        await installApp({ grants: [everyHostGrant] })
        const noView = await createUser([PERMISSIONS.PROXY_HOSTS_UPDATE])
        await expect(context(noView, [host!])).rejects.toMatchObject({
            code: 'permission_denied',
        })
        await expect(context(randomUUID(), [host!])).rejects.toMatchObject({
            code: 'authentication_required',
        })
    })

    integrationTest('reports only hosts that are requested and covered by the grant', async () => {
        const actor = await createUser([PERMISSIONS.PROXY_HOSTS_VIEW])
        const [first, second, third] = await seedHosts(3)
        const app = await installApp({ grants: [hostGrant(first!)] })
        const result = await context(actor, [first!, second!, third!])
        expect(result).toMatchObject({
            owner: 'app',
            installationId: app.installationId,
            target: {
                installationId: app.installationId,
                generation: 1,
                providerId: provider.id,
            },
            limit: 3,
        })
        if (result.owner !== 'app') throw new Error('Expected the app to own monitoring.')
        expect([...result.hosts]).toEqual([[first!, first!]])
        // A covered host that was not requested is not reported either.
        const narrow = await context(actor, [second!])
        if (narrow.owner !== 'app') throw new Error('Expected the app to own monitoring.')
        expect(narrow.hosts.size).toBe(0)
    })

    integrationTest('an all-hosts grant covers every requested host', async () => {
        const actor = await createUser([PERMISSIONS.PROXY_HOSTS_VIEW])
        const hosts = await seedHosts(3)
        await installApp({ grants: [everyHostGrant] })
        const result = await context(actor, hosts.slice(0, 2))
        if (result.owner !== 'app') throw new Error('Expected the app to own monitoring.')
        expect(new Set(result.hosts.keys())).toEqual(new Set(hosts.slice(0, 2)))
    })

    integrationTest('a grant that does not allow the service covers nothing', async () => {
        const actor = await createUser([PERMISSIONS.PROXY_HOSTS_VIEW])
        const [host] = await seedHosts(1)
        await installApp({ grants: [hostGrant(host!, false)] })
        const result = await context(actor, [host!])
        if (result.owner !== 'app') throw new Error('Expected the app to own monitoring.')
        expect(result.hosts.size).toBe(0)
    })

    integrationTest('maps an app-owned host ID to the platform host', async () => {
        const actor = await createUser([PERMISSIONS.PROXY_HOSTS_VIEW])
        const [owned, other, plain] = await seedHosts(3)
        // The grant names the owned ID of the first host and the platform ID of the third.
        const app = await installApp({
            grants: [hostGrant('app-host-one'), hostGrant('app-host-two'), hostGrant(plain!)],
        })
        await own(app.installationId, 'app-host-one', owned!)
        // The grant also names the owned ID of another installation's host: it covers nothing here.
        const foreign = await installApp({ handoff: null })
        await own(foreign.installationId, 'app-host-two', other!)
        const result = await context(actor, [owned!, other!, plain!])
        if (result.owner !== 'app') throw new Error('Expected the app to own monitoring.')
        expect(Object.fromEntries(result.hosts)).toEqual({
            [owned!]: owned!,
            'app-host-one': owned!,
            [plain!]: plain!,
        })
    })

    integrationTest('cannot call an app without a live, registered, granted provider', async () => {
        const actor = await createUser([PERMISSIONS.PROXY_HOSTS_VIEW])
        const [host] = await seedHosts(1)
        const grants = [everyHostGrant]
        const broken: InstallOptions[] = [
            { grants, activate: false },
            { grants, expired: true },
            { grants, providers: [] },
            { grants, providerGrant: false },
            { grants, providerGrant: 'client-only' },
            { grants, providers: [{ ...provider, profile: 'dns' }] },
        ]
        for (const options of broken) {
            // oxlint-disable-next-line no-await-in-loop -- Each case replaces the single handoff.
            const app = await installApp(options)
            // oxlint-disable-next-line no-await-in-loop -- Each case reads its own installation.
            const result = await context(actor, [host!])
            expect(result).toMatchObject({ owner: 'app', installationId: app.installationId })
            if (result.owner !== 'app') throw new Error('Expected the app to own monitoring.')
            expect(result.target).toBeNull()
            // oxlint-disable-next-line no-await-in-loop -- Reset the journal for the next case.
            await resetHandoff(app.installationId)
        }
    })

    integrationTest('the limit follows the number of hosts within 1 to 1,000', async () => {
        const actor = await createUser([PERMISSIONS.PROXY_HOSTS_VIEW])
        await installApp({ grants: [everyHostGrant] })
        const limitOf = async (ids: readonly string[]) => {
            const result = await context(actor, ids)
            if (result.owner !== 'app') throw new Error('Expected the app to own monitoring.')
            return result.limit
        }
        expect(await limitOf([randomUUID()])).toBe(1)
        const hosts = await seedHosts(2)
        expect(await limitOf(hosts)).toBe(2)
        // The limit counts all hosts, not the requested ones.
        expect(await limitOf([hosts[0]!])).toBe(2)
        const { db } = await import('@/db/index.ts')
        await db.execute(sql`
            insert into ${proxyHosts} (id, forward_scheme, forward_host, forward_port)
            select uuidv7(), 'http', ${marker}, 8080 from generate_series(1, 999)`)
        expect(await limitOf([hosts[0]!])).toBe(1_000)
    })
})
