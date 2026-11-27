import { randomUUID } from 'node:crypto'
import { afterEach, beforeAll, beforeEach, describe, expect, test } from 'bun:test'
import { eq, inArray } from 'drizzle-orm'
import { NOTIFICATION_SETTINGS_KEY, NOTIFICATION_STATE_KEY } from '@/config/notifications.config.ts'
import { PERMISSIONS } from '@/config/permissions.config.ts'
import {
    appRuntimeGenerations,
    appRuntimeMessages,
    appRuntimeOwnedProxyHosts,
    hostDomains,
    permissions,
    proxyHosts,
    rolePermissions,
    roles,
    systemSettings,
    userRoles,
    users,
} from '@/db/schema.ts'
import { createAppRuntimeGateway } from '@/server/AppRuntime/gateway.server.ts'
import { manageAppRuntime } from '@/server/AppRuntime/management.server.ts'
import { executeAppRuntimeCall } from '@/server/AppRuntime/services.server.ts'
import { ensureAuthorizationRegistryInTransaction } from '@/server/Auth/Access/registry.service.ts'
import { getDatabaseUrl } from '@/server/env.server.ts'
import {
    acknowledgeNotificationDelivery,
    authorizeNotificationDelivery,
    claimNextNotificationDelivery,
} from '@/server/Notifications/notification-repository.ts'
import {
    lockNotificationConfiguration,
    lockNotificationRuntime,
    readNotificationRuntime,
    writeNotificationConfiguration,
    writeNotificationRuntime,
} from '@/server/Notifications/notification-storage.ts'
import type {
    StoredNotificationChannel,
    StoredNotificationConfiguration,
} from '@/server/Notifications/Types/notification-internal.types.ts'
import { removeEventApps } from '@/tests/Helpers/appHostEvents.ts'

const enabled = process.env.RENTNERPROXY_DATABASE_INTEGRATION === '1' && getDatabaseUrl() !== null
const integrationTest = enabled ? test : test.skip
const notificationKeys = [NOTIFICATION_SETTINGS_KEY, NOTIFICATION_STATE_KEY]
const incidents = { id: 'notifications.incidents.manage.v1', scope: 'installation' }
const publish = { id: 'notifications.publish.v1', scope: 'installation' }
const readHosts = { id: 'proxy.hosts.read.v1', scope: 'proxyHosts' }
const events = { id: 'app.events.subscribe', scope: 'installation' }
const categories = [
    { id: 'disk', name: 'Disk space', resource: 'none' },
    { id: 'upstream', name: 'Upstream', resource: 'proxyHost' },
]
const appId = 'test.incidents'
const globalChannelId = '00000000-0000-4000-8000-000000000a01'
const token = 'incident-test-bridge'

interface Installed {
    readonly identity: { appId: string; installationId: string; generation: number; uid: number }
    readonly send: (
        path: string,
        body?: unknown,
        headers?: Record<string, string>,
    ) => Promise<Response>
    readonly control: (action: string, fields?: Record<string, unknown>) => Promise<Response>
    readonly incident: (key: string, body: unknown, idempotencyKey: string) => Promise<Response>
}

let nextUid = 40_700
const installed: Installed['identity'][] = []
const hostIds: string[] = []
const userIds: string[] = []
const roleIds: string[] = []
const encryptionKey = process.env.APP_ENCRYPTION_KEY

function grant(capability: { id: string; scope: string }, resourceId: string) {
    return { capability, resourceId, allowService: true }
}

/** Register an app through the management controls and the public gateway, like the broker. */
async function install(
    options: {
        capabilities?: object[]
        grants?: (installationId: string) => object[]
        categories?: object[]
        generation?: number
        installationId?: string
        uid?: number
    } = {},
): Promise<Installed> {
    const identity = {
        appId,
        installationId: options.installationId ?? randomUUID(),
        generation: options.generation ?? 1,
        uid: options.uid ?? nextUid,
    }
    if (options.uid === undefined) nextUid += 1
    if (!installed.some(({ installationId }) => installationId === identity.installationId))
        installed.push(identity)
    const gateway = createAppRuntimeGateway(
        token,
        new AbortController().signal,
        executeAppRuntimeCall,
        manageAppRuntime,
    )
    const send = (path: string, body?: unknown, headers: Record<string, string> = {}) =>
        gateway(
            new Request('http://app-api' + path, {
                method: body === undefined ? 'GET' : 'POST',
                headers: {
                    Authorization: 'Bearer ' + token,
                    'X-App-Installation': identity.installationId,
                    'X-App-Generation': String(identity.generation),
                    'X-RentnerProxy-App-Uid': String(identity.uid),
                    'X-RentnerProxy-App-Id': identity.appId,
                    ...(body !== undefined && { 'Content-Type': 'application/json' }),
                    ...headers,
                },
                ...(body !== undefined && { body: JSON.stringify(body) }),
            }),
        )
    const control = (action: string, fields: Record<string, unknown> = {}) =>
        send('/internal/v1/app-generations/' + action, { identity, ...fields })
    const leaseExpiresAt = new Date(Date.now() + 60_000).toISOString()
    const capabilities = options.capabilities ?? [incidents, readHosts]
    expect(
        (
            await control('register', {
                leaseExpiresAt,
                capabilities,
                incidentCategories: options.categories ?? categories,
            })
        ).status,
    ).toBe(204)
    const grants = options.grants?.(identity.installationId) ?? [
        grant(incidents, identity.installationId),
    ]
    expect(
        (
            await control('grants', {
                grants: [grant(events, identity.installationId), ...grants],
            })
        ).status,
    ).toBe(204)
    expect((await control('activate', { leaseExpiresAt })).status).toBe(204)
    return {
        identity,
        send,
        control,
        incident: (key, body, idempotencyKey) =>
            send('/platform/v1/incidents/' + key, body, { 'Idempotency-Key': idempotencyKey }),
    }
}

function channel(overrides: Partial<StoredNotificationChannel> = {}): StoredNotificationChannel {
    return {
        id: globalChannelId,
        name: 'App incidents fixture',
        kind: 'webhook',
        revision: 1,
        enabled: true,
        events: ['app_incident'],
        minimumSeverity: 'warning',
        thresholdSeconds: 0,
        recovery: true,
        appCategories: [`${appId}/disk`, `${appId}/upstream`],
        // The repository tests neither decrypt nor send this shape-valid sealed destination.
        destination: { ciphertext: 'a'.repeat(32), iv: 'b'.repeat(16) },
        hasAuthorization: false,
        ...overrides,
    }
}

async function configure(
    channels: readonly StoredNotificationChannel[] = [channel()],
    state: { enabled?: boolean; pausedAfterRestore?: boolean } = {},
) {
    const { db } = await import('@/db/index.ts')
    const configuration: StoredNotificationConfiguration = {
        version: 1,
        revision: 1,
        enabled: state.enabled ?? !state.pausedAfterRestore,
        pausedAfterRestore: state.pausedAfterRestore ?? false,
        channels,
    }
    await db.transaction(async (transaction) => {
        await lockNotificationConfiguration(transaction)
        await writeNotificationConfiguration(transaction, configuration)
        const locked = await lockNotificationRuntime(transaction)
        await writeNotificationRuntime(transaction, locked)
    })
}

async function runtime() {
    const { db } = await import('@/db/index.ts')
    return (await db.transaction(readNotificationRuntime, { accessMode: 'read only' })).engine
}

async function createHost() {
    const { db } = await import('@/db/index.ts')
    const id = randomUUID()
    hostIds.push(id)
    const domain = `incident-${id}.example.test`
    await db.insert(proxyHosts).values({
        id,
        forwardScheme: 'http',
        forwardHost: '127.0.0.1',
        forwardPort: 8080,
    })
    await db.insert(hostDomains).values({ proxyHostId: id, domain })
    return { id, domain }
}

async function createUser(permissionKeys: readonly string[]) {
    const { db } = await import('@/db/index.ts')
    const id = randomUUID()
    userIds.push(id)
    await db.insert(users).values({
        id,
        displayName: 'Incident fixture',
        email: `${id}@incident-fixture.invalid`,
        status: 'active',
    })
    const roleId = randomUUID()
    roleIds.push(roleId)
    await db
        .insert(roles)
        .values({ id: roleId, key: `incident-${roleId}`, name: 'Incident fixture' })
    const selected = await db
        .select({ id: permissions.id })
        .from(permissions)
        .where(inArray(permissions.key, [...permissionKeys]))
    expect(selected).toHaveLength(permissionKeys.length)
    await db
        .insert(rolePermissions)
        .values(selected.map((permission) => ({ roleId, permissionId: permission.id })))
    await db.insert(userRoles).values({ userId: id, roleId })
    return id
}

const open = (overrides: Record<string, unknown> = {}) => ({
    status: 'open',
    category: 'disk',
    severity: 'error',
    title: 'Disk almost full',
    message: 'The data volume has 2% left.',
    ...overrides,
})

async function problem(response: Response) {
    return { status: response.status, code: ((await response.json()) as { code?: string }).code }
}

/** Claim and acknowledge deliveries until none is due; returns what each claim carried. */
async function drain() {
    const claims = []
    for (;;) {
        // oxlint-disable-next-line no-await-in-loop -- Deliveries are claimed one at a time.
        const claim = await claimNextNotificationDelivery()
        if (!claim) return claims
        claims.push(claim)
        // oxlint-disable-next-line no-await-in-loop -- Each acknowledgement precedes the next claim.
        await acknowledgeNotificationDelivery(claim.leaseToken, { success: true })
    }
}

describe('app incidents through the App API', () => {
    beforeAll(async () => {
        if (!enabled) return
        const { db } = await import('@/db/index.ts')
        await db.transaction(ensureAuthorizationRegistryInTransaction)
        // Event cursors are sealed with the app encryption key.
        process.env.APP_ENCRYPTION_KEY = Buffer.alloc(32, 71).toString('base64')
    })
    beforeEach(async () => {
        if (!enabled) return
        const { db } = await import('@/db/index.ts')
        await db.delete(systemSettings).where(inArray(systemSettings.key, notificationKeys))
        await configure()
    })
    afterEach(async () => {
        if (!enabled) return
        const { db } = await import('@/db/index.ts')
        const ids = installed.splice(0)
        if (ids.length > 0) {
            await db.delete(appRuntimeOwnedProxyHosts).where(
                inArray(
                    appRuntimeOwnedProxyHosts.installationId,
                    ids.map(({ installationId }) => installationId),
                ),
            )
            await removeEventApps(ids)
        }
        if (hostIds.length > 0)
            await db.delete(proxyHosts).where(inArray(proxyHosts.id, hostIds.splice(0)))
        if (userIds.length > 0) await db.delete(users).where(inArray(users.id, userIds.splice(0)))
        if (roleIds.length > 0) await db.delete(roles).where(inArray(roles.id, roleIds.splice(0)))
        await db.delete(systemSettings).where(inArray(systemSettings.key, notificationKeys))
        if (encryptionKey === undefined) delete process.env.APP_ENCRYPTION_KEY
        else process.env.APP_ENCRYPTION_KEY = encryptionKey
    })

    integrationTest('an app without the incident grant is refused', async () => {
        const app = await install({ grants: () => [] })
        const response = await app.incident('disk-full', open(), 'refused-one')
        expect(await problem(response)).toEqual({ status: 403, code: 'scopeDenied' })
        expect((await runtime()).incidents).toHaveLength(0)
    })

    integrationTest('an app that does not declare the category gets a conflict', async () => {
        const app = await install()
        const response = await app.incident(
            'disk-full',
            open({ category: 'memory' }),
            'undeclared-1',
        )
        expect(await problem(response)).toEqual({ status: 409, code: 'incidentCategoryUndeclared' })
        expect((await runtime()).incidents).toHaveLength(0)
    })

    integrationTest('a category names a host exactly when it is a host category', async () => {
        const app = await install()
        expect(
            (await app.incident('one', open({ resourceId: 'a-host' }), 'shape-one')).status,
        ).toBe(400)
        expect(
            (await app.incident('two', open({ category: 'upstream' }), 'shape-two')).status,
        ).toBe(400)
        expect((await app.incident('three', { ...open(), extra: 1 }, 'shape-three')).status).toBe(
            400,
        )
        expect((await runtime()).incidents).toHaveLength(0)
    })

    integrationTest('open, repeat and resolve notify once each', async () => {
        const app = await install()
        expect((await app.incident('disk-full', open(), 'open-1')).status).toBe(204)
        // The same state again, under another idempotency key, creates nothing.
        expect((await app.incident('disk-full', open(), 'open-2')).status).toBe(204)
        expect((await app.incident('disk-full', open(), 'open-3')).status).toBe(204)
        const kept = await runtime()
        expect(kept.incidents).toHaveLength(1)
        expect(kept.deliveries).toHaveLength(1)
        const failure = await claimNextNotificationDelivery()
        expect(failure?.payload).toMatchObject({
            type: 'incident',
            category: 'app_incident',
            app: { appName: appId, categoryName: 'Disk space', title: 'Disk almost full' },
        })
        expect(await authorizeNotificationDelivery(failure!)).not.toBeNull()
        await acknowledgeNotificationDelivery(failure!.leaseToken, { success: true })
        expect(await claimNextNotificationDelivery()).toBeNull()
        expect((await app.incident('disk-full', { status: 'resolved' }, 'resolve-1')).status).toBe(
            204,
        )
        expect((await app.incident('disk-full', { status: 'resolved' }, 'resolve-2')).status).toBe(
            204,
        )
        const recovery = await claimNextNotificationDelivery()
        expect(recovery?.payload).toMatchObject({
            type: 'recovery',
            app: { title: 'Disk almost full' },
        })
        expect(await authorizeNotificationDelivery(recovery!)).not.toBeNull()
        await acknowledgeNotificationDelivery(recovery!.leaseToken, { success: true })
        expect(await claimNextNotificationDelivery()).toBeNull()
        const done = await runtime()
        expect(done.incidents).toHaveLength(1)
        expect(done.deliveries.map(({ payload }) => payload.type)).toEqual(['incident', 'recovery'])
    })

    integrationTest('an idempotency key replays the same change and refuses another', async () => {
        const { db } = await import('@/db/index.ts')
        const app = await install()
        expect((await app.incident('disk-full', open(), 'same-key')).status).toBe(204)
        expect((await app.incident('disk-full', open(), 'same-key')).status).toBe(204)
        expect(
            await problem(
                await app.incident('disk-full', open({ severity: 'critical' }), 'same-key'),
            ),
        ).toEqual({ status: 409, code: 'idempotencyConflict' })
        // The same change under another incident key is another change.
        expect(await problem(await app.incident('other-key', open(), 'same-key'))).toEqual({
            status: 409,
            code: 'idempotencyConflict',
        })
        const rows = await db
            .select({ kind: appRuntimeMessages.kind })
            .from(appRuntimeMessages)
            .where(eq(appRuntimeMessages.installationId, app.identity.installationId))
        expect(rows).toEqual([{ kind: 'incident' }])
        expect((await runtime()).incidents).toHaveLength(1)
    })

    integrationTest(
        'a host incident needs a covering grant before the host is checked',
        async () => {
            const covered = await createHost()
            const uncovered = await createHost()
            const missing = randomUUID()
            const app = await install({
                grants: (installationId) => [
                    grant(incidents, installationId),
                    grant(readHosts, covered.id),
                    grant(readHosts, missing),
                ],
            })
            const attempt = (hostId: string, key: string) =>
                app.incident(key, open({ category: 'upstream', resourceId: hostId }), key)
            // Uncovered hosts answer alike, whether they exist or not.
            for (const [hostId, key] of [
                [uncovered.id, 'uncovered-one'],
                [randomUUID(), 'uncovered-two'],
                // Covered, but the host does not exist.
                [missing, 'missing-one'],
            ] as const) {
                // oxlint-disable-next-line no-await-in-loop -- Each attempt is checked on its own.
                expect(await problem(await attempt(hostId, key))).toEqual({
                    status: 404,
                    code: 'notFound',
                })
            }
            expect((await runtime()).incidents).toHaveLength(0)
            expect((await attempt(covered.id, 'covered-one')).status).toBe(204)
            const [incident] = (await runtime()).incidents
            expect(incident?.app?.resource).toEqual({ type: 'proxyHost', proxyHostId: covered.id })
        },
    )

    integrationTest('a host the app owns is named by its own ID or its platform ID', async () => {
        const { db } = await import('@/db/index.ts')
        const owned = await createHost()
        const app = await install({
            grants: (installationId) => [
                grant(incidents, installationId),
                grant(readHosts, 'app-host'),
            ],
        })
        await db.insert(appRuntimeOwnedProxyHosts).values({
            installationId: app.identity.installationId,
            hostId: 'app-host',
            proxyHostId: owned.id,
        })
        const body = open({ category: 'upstream', resourceId: 'app-host' })
        expect((await app.incident('owned-host', body, 'owned-1')).status).toBe(204)
        const [incident] = (await runtime()).incidents
        expect(incident?.app?.resource).toEqual({ type: 'proxyHost', proxyHostId: owned.id })
    })

    integrationTest('notifications that are disabled or paused keep no incident', async () => {
        const { db } = await import('@/db/index.ts')
        const app = await install()
        for (const state of [{ enabled: false }, { pausedAfterRestore: true }]) {
            // oxlint-disable-next-line no-await-in-loop -- The states are checked in turn.
            await configure([channel()], state)
            // oxlint-disable-next-line no-await-in-loop -- The states are checked in turn.
            expect((await app.incident('disk-full', open(), 'paused-one')).status).toBe(204)
            // oxlint-disable-next-line no-await-in-loop -- The states are checked in turn.
            expect((await runtime()).incidents).toHaveLength(0)
            // oxlint-disable-next-line no-await-in-loop -- The states are checked in turn.
            const rows = await db
                .select()
                .from(appRuntimeMessages)
                .where(eq(appRuntimeMessages.installationId, app.identity.installationId))
            expect(rows).toHaveLength(0)
        }
        // After the resume the same observation, even under the same key, opens the incident.
        await configure()
        expect((await app.incident('disk-full', open(), 'paused-one')).status).toBe(204)
        expect((await runtime()).incidents).toHaveLength(1)
    })

    integrationTest(
        'a channel without the category, or with an owner who cannot view hosts, gets nothing',
        async () => {
            const host = await createHost()
            const viewer = await createUser([PERMISSIONS.APP_ACCESS, PERMISSIONS.PROXY_HOSTS_VIEW])
            const plain = await createUser([PERMISSIONS.APP_ACCESS])
            const ids = {
                viewer: '00000000-0000-4000-8000-000000000a02',
                plain: '00000000-0000-4000-8000-000000000a03',
                other: '00000000-0000-4000-8000-000000000a04',
            }
            await configure([
                channel({ id: ids.viewer, ownerUserId: viewer }),
                channel({ id: ids.plain, ownerUserId: plain }),
                channel({ id: ids.other, appCategories: [`${appId}/disk`] }),
                channel({ id: globalChannelId, appCategories: undefined }),
            ])
            const app = await install({
                grants: (installationId) => [
                    grant(incidents, installationId),
                    grant(readHosts, host.id),
                ],
            })
            const body = open({ category: 'upstream', resourceId: host.id })
            expect((await app.incident('upstream-down', body, 'host-1')).status).toBe(204)
            const claims = []
            for (let attempt = 0; attempt < 4; attempt++) {
                // oxlint-disable-next-line no-await-in-loop -- Claims are made one at a time.
                const claim = await claimNextNotificationDelivery()
                if (claim) claims.push(claim)
            }
            expect(claims.map(({ channelId }) => channelId).toSorted()).toEqual(
                [ids.plain, ids.viewer].toSorted(),
            )
            const authorized = new Map(
                await Promise.all(
                    claims.map(
                        async (claim) =>
                            [claim.channelId, await authorizeNotificationDelivery(claim)] as const,
                    ),
                ),
            )
            expect(authorized.get(ids.plain)).toBeNull()
            expect(authorized.get(ids.viewer)?.payload?.app?.resource).toEqual({
                type: 'proxyHost',
                hostname: host.domain,
            })
        },
    )

    integrationTest('a revoked grant resolves the incident with its reason', async () => {
        const app = await install()
        expect((await app.incident('disk-full', open(), 'revoke-1')).status).toBe(204)
        await drain()
        expect(
            (
                await app.control('grants', {
                    grants: [grant(events, app.identity.installationId)],
                })
            ).status,
        ).toBe(204)
        // The next delivery pass finds the grant gone and owes the channel its recovery.
        const recovery = await claimNextNotificationDelivery()
        expect(recovery?.payload).toMatchObject({
            type: 'recovery',
            app: { resolution: 'grantRevoked' },
        })
        expect(await authorizeNotificationDelivery(recovery!)).not.toBeNull()
        const [incident] = (await runtime()).incidents
        expect(incident?.app?.resolution).toBe('grantRevoked')
        expect(incident?.recoveredAt).not.toBeNull()
    })

    integrationTest('a stopped installation resolves its incidents once its lease ends', async () => {
        const app = await install()
        expect((await app.incident('disk-full', open(), 'stop-1')).status).toBe(204)
        await drain()
        expect((await app.control('retire')).status).toBe(204)
        // A start or an update registers its next generation within that lease, so nothing ends.
        expect(await claimNextNotificationDelivery()).toBeNull()
        expect((await runtime()).incidents[0]?.recoveredAt).toBeNull()
        const { db } = await import('@/db/index.ts')
        await db
            .update(appRuntimeGenerations)
            .set({ leaseExpiresAt: new Date(Date.now() - 1_000) })
            .where(eq(appRuntimeGenerations.installationId, app.identity.installationId))
        const recovery = await claimNextNotificationDelivery()
        expect(recovery?.payload).toMatchObject({
            type: 'recovery',
            app: { resolution: 'appStopped' },
        })
        expect(await authorizeNotificationDelivery(recovery!)).not.toBeNull()
        expect((await runtime()).incidents[0]?.app?.resolution).toBe('appStopped')
    })

    integrationTest(
        'a restart retires the running generation first and keeps the incident open',
        async () => {
            const app = await install()
            expect((await app.incident('disk-full', open(), 'restart-1')).status).toBe(204)
            await drain()
            // The core retires the running generation before it registers the next one.
            expect((await app.control('retire')).status).toBe(204)
            expect(await claimNextNotificationDelivery()).toBeNull()
            const next = await install({
                installationId: app.identity.installationId,
                generation: 2,
                uid: app.identity.uid,
                grants: (installationId) => [grant(incidents, installationId)],
            })
            expect(next.identity.generation).toBe(2)
            expect(await claimNextNotificationDelivery()).toBeNull()
            expect((await runtime()).incidents[0]?.recoveredAt).toBeNull()
        },
    )

    integrationTest('removing the installation resolves its incidents at once', async () => {
        const app = await install()
        expect((await app.incident('disk-full', open(), 'remove-1')).status).toBe(204)
        await drain()
        expect((await app.control('retire')).status).toBe(204)
        expect((await app.control('purge-data')).status).toBe(204)
        expect((await runtime()).incidents[0]?.app?.resolution).toBe('appStopped')
        const recovery = await claimNextNotificationDelivery()
        expect(recovery?.payload).toMatchObject({
            type: 'recovery',
            app: { resolution: 'appStopped' },
        })
    })

    integrationTest(
        'a host that is gone resolves its incident without a recovery notice',
        async () => {
            const { db } = await import('@/db/index.ts')
            const host = await createHost()
            const app = await install({
                grants: (installationId) => [
                    grant(incidents, installationId),
                    grant(readHosts, host.id),
                ],
            })
            expect(
                (
                    await app.incident(
                        'upstream-down',
                        open({ category: 'upstream', resourceId: host.id }),
                        'gone-1',
                    )
                ).status,
            ).toBe(204)
            await drain()
            await db.delete(proxyHosts).where(eq(proxyHosts.id, host.id))
            expect(await claimNextNotificationDelivery()).toBeNull()
            const [incident] = (await runtime()).incidents
            expect(incident?.app?.resolution).toBe('resourceUnavailable')
            expect(incident?.recoveredAt).not.toBeNull()
            expect((await runtime()).deliveries.map(({ payload }) => payload.type)).toEqual([
                'incident',
            ])
        },
    )

    integrationTest('the notification publish grant behaves as before', async () => {
        const { db } = await import('@/db/index.ts')
        const app = await install({
            capabilities: [publish],
            categories: [],
            grants: (installationId) => [grant(publish, installationId)],
        })
        const notice = { category: 'maintenance', severity: 'info', title: 'Title', message: 'One' }
        const send = (body: unknown, key: string) =>
            app.send('/platform/v1/notifications', body, { 'Idempotency-Key': key })
        expect((await send(notice, 'notice-one')).status).toBe(204)
        expect((await send(notice, 'notice-one')).status).toBe(204)
        expect((await send({ ...notice, message: 'Two' }, 'notice-one')).status).toBe(409)
        // Publishing neither needs nor touches incidents, and the incident route refuses the app.
        expect((await app.incident('disk-full', open(), 'notice-two')).status).toBe(403)
        expect((await runtime()).incidents).toHaveLength(0)
        const rows = await db
            .select({ kind: appRuntimeMessages.kind })
            .from(appRuntimeMessages)
            .where(eq(appRuntimeMessages.installationId, app.identity.installationId))
        expect(rows).toEqual([{ kind: 'notification' }])
    })
})
