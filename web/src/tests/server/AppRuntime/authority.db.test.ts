import { expect, test } from 'bun:test'
import { count, inArray, eq } from 'drizzle-orm'

import { PERMISSIONS } from '@/config/permissions.config.ts'
import {
    appRuntimeDelegations,
    appRuntimeEvents,
    appRuntimeGenerations,
    appRuntimeGrants,
    appRuntimeInstallations,
    appRuntimeSecrets,
    permissions,
    rolePermissions,
    roles,
    sessions,
    userRoles,
    users,
} from '@/db/schema.ts'
import {
    APP_RUNTIME_SUPPORT_CAPABILITIES,
    isAppRuntimeAuthorized,
    issueAppRuntimeDelegationInTransaction,
    putAppRuntimeSecretInTransaction,
    readAppRuntimeContextInTransaction,
    readAppRuntimeSecretInTransaction,
    resolveAppRuntimePrincipalInTransaction,
} from '@/server/AppRuntime/authority.server.ts'
import {
    appRuntimeEventCursorContext,
    appendAppRuntimeEventInTransaction,
    readAppRuntimeEventCursor,
    replayAppRuntimeEventsInTransaction,
} from '@/server/AppRuntime/events.server.ts'
import {
    activateAppRuntimeGenerationInTransaction,
    registerAppRuntimeGenerationInTransaction,
    renewAppRuntimeGenerationLeaseInTransaction,
    replaceAppRuntimeGrantsInTransaction,
    revokeAppRuntimeGenerationInTransaction,
    setAppRuntimeRolePermissionInTransaction,
} from '@/server/AppRuntime/lifecycle.server.ts'
import { createOpaqueToken, hashOpaqueToken } from '@/server/Auth/Core/tokens.server.ts'

const integrationEnabled =
    process.env.RENTNERPROXY_DATABASE_INTEGRATION === '1' && Boolean(process.env.DATABASE_URL)
const integrationTest = integrationEnabled ? test : test.skip

integrationTest(
    'runtime authority persists and fences app generations, delegation, secrets and replay',
    async () => {
        const { db } = await import('@/db/index.ts')
        const rolledBack = new Error('runtime test rollback')
        const originalEncryptionKey = process.env.APP_ENCRYPTION_KEY
        process.env.APP_ENCRYPTION_KEY = Buffer.alloc(32, 51).toString('base64')

        try {
            await expect(
                db.transaction(async (transaction) => {
                    const installationId = crypto.randomUUID()
                    const identity = {
                        installationId,
                        appId: 'test.integration',
                        uid: 40_451,
                        generation: 1,
                    }
                    const now = new Date()
                    const leaseExpiresAt = new Date(now.getTime() + 60_000)
                    const read = { id: 'proxy.hosts.read.v1', scope: 'proxyHosts' }
                    const { events: subscribe, secret } = APP_RUNTIME_SUPPORT_CAPABILITIES
                    const granted = [
                        { capability: read, resourceId: 'managed-host-a', allowService: false },
                        { capability: subscribe, resourceId: installationId, allowService: false },
                        {
                            capability: secret,
                            resourceId: 'local-credential',
                            allowService: false,
                            permissionKey: 'use-secret',
                        },
                    ]
                    const registration = {
                        identity,
                        leaseExpiresAt,
                        capabilities: [read],
                        permissionKeys: ['use-secret'],
                    }
                    await registerAppRuntimeGenerationInTransaction(transaction, registration)
                    await replaceAppRuntimeGrantsInTransaction(transaction, identity, granted)

                    expect(
                        await readAppRuntimeContextInTransaction(transaction, identity),
                    ).toMatchObject({
                        appId: identity.appId,
                        generation: 1,
                        capabilities: [read],
                    })
                    await expect(
                        resolveAppRuntimePrincipalInTransaction(transaction, { identity }),
                    ).rejects.toMatchObject({
                        code: 'unauthorized',
                    })
                    await expect(
                        readAppRuntimeContextInTransaction(transaction, {
                            ...identity,
                            uid: 40_452,
                        }),
                    ).rejects.toMatchObject({
                        code: 'unauthorized',
                    })
                    await activateAppRuntimeGenerationInTransaction(
                        transaction,
                        identity,
                        leaseExpiresAt,
                    )

                    const userId = crypto.randomUUID()
                    const sessionId = crypto.randomUUID()
                    const roleId = crypto.randomUUID()
                    const platformPermissionKeys = [
                        PERMISSIONS.APP_ACCESS,
                        PERMISSIONS.PROXY_HOSTS_VIEW,
                    ]
                    await transaction
                        .insert(permissions)
                        .values(platformPermissionKeys.map((key) => ({ key, name: key })))
                        .onConflictDoNothing()
                    const platformPermissions = await transaction
                        .select({ id: permissions.id })
                        .from(permissions)
                        .where(inArray(permissions.key, platformPermissionKeys))
                    await transaction.insert(users).values({
                        id: userId,
                        displayName: 'App Tester',
                        email: `runtime-${userId}@integration.invalid`,
                        status: 'active',
                    })
                    await transaction
                        .insert(roles)
                        .values({ id: roleId, key: roleId, name: 'App Tester' })
                    await transaction.insert(userRoles).values({ userId, roleId })
                    await transaction
                        .insert(rolePermissions)
                        .values(platformPermissions.map(({ id }) => ({ roleId, permissionId: id })))
                    await transaction.insert(sessions).values({
                        id: sessionId,
                        userId,
                        oidcProof: null,
                        expiresAt: leaseExpiresAt,
                        tokenHash: await hashOpaqueToken(createOpaqueToken()),
                    })
                    await setAppRuntimeRolePermissionInTransaction(
                        transaction,
                        identity,
                        roleId,
                        'use-secret',
                        true,
                    )
                    const delegation = await issueAppRuntimeDelegationInTransaction(
                        transaction,
                        identity,
                        sessionId,
                    )
                    const [binding] = await transaction
                        .select()
                        .from(appRuntimeDelegations)
                        .where(eq(appRuntimeDelegations.sessionId, sessionId))
                    expect(binding).toMatchObject({
                        sessionId,
                        generation: 1,
                        tokenHash: await hashOpaqueToken(delegation),
                    })
                    expect(binding?.tokenHash).not.toBe(delegation)

                    const credentials = { identity, delegation }
                    const user = await resolveAppRuntimePrincipalInTransaction(
                        transaction,
                        credentials,
                    )
                    const service = await resolveAppRuntimePrincipalInTransaction(transaction, {
                        identity,
                    })
                    expect(user.user?.id).toBe(userId)
                    expect(isAppRuntimeAuthorized(user, read, 'managed-host-a')).toBe(true)
                    expect(isAppRuntimeAuthorized(service, read, 'managed-host-a')).toBe(false)
                    await putAppRuntimeSecretInTransaction(
                        transaction,
                        identity,
                        'local-credential',
                        'synthetic secret',
                    )
                    const [secretRow] = await transaction
                        .select()
                        .from(appRuntimeSecrets)
                        .where(eq(appRuntimeSecrets.installationId, installationId))
                    expect(
                        Buffer.from(secretRow?.ciphertext ?? []).includes('synthetic secret'),
                    ).toBe(false)
                    expect(
                        await readAppRuntimeSecretInTransaction(
                            transaction,
                            user,
                            'local-credential',
                        ),
                    ).toEqual({ value: 'synthetic secret' })
                    await expect(
                        readAppRuntimeSecretInTransaction(transaction, service, 'local-credential'),
                    ).rejects.toMatchObject({ code: 'not_found' })

                    const firstEvent = await appendAppRuntimeEventInTransaction(transaction, {
                        installationId,
                        type: 'proxyHostChanged',
                        capability: read,
                        resourceId: 'managed-host-a',
                        revision: 'v1',
                    })
                    const hiddenEvent = await appendAppRuntimeEventInTransaction(transaction, {
                        installationId,
                        type: 'proxyHostChanged',
                        capability: read,
                        resourceId: 'managed-host-b',
                        revision: 'v1',
                    })
                    const secondEvent = await appendAppRuntimeEventInTransaction(transaction, {
                        installationId,
                        type: 'proxyHostChanged',
                        capability: read,
                        resourceId: 'managed-host-a',
                        revision: 'v2',
                    })
                    const trailingHiddenEvent = await appendAppRuntimeEventInTransaction(
                        transaction,
                        {
                            installationId,
                            type: 'proxyHostChanged',
                            capability: read,
                            resourceId: 'managed-host-b',
                            revision: 'v2',
                        },
                    )
                    const initial = await replayAppRuntimeEventsInTransaction(
                        transaction,
                        credentials,
                    )
                    expect(initial.events.map(({ id }) => id)).toEqual([firstEvent, secondEvent])
                    expect(initial.events.at(-1)?.cursor).toBe(initial.cursor)
                    const firstCursor = initial.events.at(0)?.cursor
                    expect(firstCursor).toBeDefined()
                    await replaceAppRuntimeGrantsInTransaction(
                        transaction,
                        identity,
                        granted.toReversed(),
                    )
                    await setAppRuntimeRolePermissionInTransaction(
                        transaction,
                        identity,
                        roleId,
                        'use-secret',
                        true,
                    )
                    const resumed = await replayAppRuntimeEventsInTransaction(
                        transaction,
                        credentials,
                        firstCursor,
                    )
                    expect(resumed.events.map(({ id }) => id)).toEqual([secondEvent])
                    expect(resumed.events.at(-1)?.cursor).toBe(resumed.cursor)
                    const empty = await replayAppRuntimeEventsInTransaction(
                        transaction,
                        credentials,
                        resumed.cursor,
                    )
                    const [trailing] = await transaction
                        .select({ sequence: appRuntimeEvents.sequence })
                        .from(appRuntimeEvents)
                        .where(eq(appRuntimeEvents.id, trailingHiddenEvent))
                    expect(empty.events).toEqual([])
                    expect(trailing?.sequence).toBe(
                        await readAppRuntimeEventCursor(
                            empty.cursor,
                            Date.now(),
                            appRuntimeEventCursorContext(user),
                        ),
                    )

                    await transaction
                        .update(appRuntimeEvents)
                        .set({ occurredAt: new Date(0) })
                        .where(inArray(appRuntimeEvents.id, [firstEvent, hiddenEvent]))
                    await expect(
                        replayAppRuntimeEventsInTransaction(transaction, credentials, firstCursor),
                    ).rejects.toMatchObject({ code: 'cursor_expired' })
                    const recovered = await replayAppRuntimeEventsInTransaction(
                        transaction,
                        credentials,
                    )
                    expect(recovered.events.map(({ id }) => id)).toEqual([secondEvent])

                    const event = {
                        installationId,
                        type: 'proxyHostChanged',
                        capability: read,
                        resourceId: 'managed-host-a',
                    }
                    await appendAppRuntimeEventInTransaction(transaction, event)
                    const oldRows = await transaction
                        .select({ id: appRuntimeEvents.id })
                        .from(appRuntimeEvents)
                        .where(inArray(appRuntimeEvents.id, [firstEvent, hiddenEvent]))
                    expect(oldRows).toEqual([])
                    await expect(
                        replayAppRuntimeEventsInTransaction(transaction, credentials, firstCursor),
                    ).rejects.toMatchObject({ code: 'cursor_expired' })

                    // Fill the retained window without opening thousands of app transactions.
                    await transaction.insert(appRuntimeEvents).values(
                        Array.from({ length: 4_096 }, () => ({
                            installationId,
                            type: 'proxyHostChanged',
                            capabilityId: read.id,
                            scope: read.scope,
                            resourceId: 'managed-host-b',
                        })),
                    )
                    const newest = await appendAppRuntimeEventInTransaction(transaction, event)
                    const [remaining] = await transaction
                        .select({ total: count() })
                        .from(appRuntimeEvents)
                        .where(eq(appRuntimeEvents.installationId, installationId))
                    expect(remaining?.total).toBe(4_096)
                    await expect(
                        replayAppRuntimeEventsInTransaction(
                            transaction,
                            credentials,
                            recovered.cursor,
                        ),
                    ).rejects.toMatchObject({ code: 'cursor_expired' })
                    const current = await replayAppRuntimeEventsInTransaction(
                        transaction,
                        credentials,
                    )
                    expect(current.events.map(({ id }) => id)).toEqual([newest])

                    await replaceAppRuntimeGrantsInTransaction(
                        transaction,
                        identity,
                        granted.slice(1),
                    )
                    await expect(
                        replayAppRuntimeEventsInTransaction(
                            transaction,
                            credentials,
                            current.cursor,
                        ),
                    ).rejects.toMatchObject({
                        code: 'cursor_expired',
                    })
                    expect(
                        (await replayAppRuntimeEventsInTransaction(transaction, credentials))
                            .events,
                    ).toEqual([])
                    await transaction
                        .update(sessions)
                        .set({ expiresAt: new Date(0) })
                        .where(eq(sessions.id, sessionId))
                    await expect(
                        resolveAppRuntimePrincipalInTransaction(transaction, credentials),
                    ).rejects.toMatchObject({
                        code: 'unauthorized',
                    })

                    const next = { ...identity, generation: 2 }
                    await registerAppRuntimeGenerationInTransaction(transaction, {
                        ...registration,
                        identity: next,
                    })
                    await activateAppRuntimeGenerationInTransaction(
                        transaction,
                        next,
                        leaseExpiresAt,
                    )
                    await expect(
                        readAppRuntimeContextInTransaction(transaction, identity),
                    ).rejects.toMatchObject({
                        code: 'unauthorized',
                    })
                    await expect(
                        resolveAppRuntimePrincipalInTransaction(transaction, {
                            identity: next,
                            delegation,
                        }),
                    ).rejects.toMatchObject({
                        code: 'unauthorized',
                    })
                    await expect(
                        renewAppRuntimeGenerationLeaseInTransaction(
                            transaction,
                            identity,
                            leaseExpiresAt,
                        ),
                    ).rejects.toMatchObject({
                        code: 'conflict',
                    })
                    await transaction
                        .update(appRuntimeGenerations)
                        .set({ leaseExpiresAt: new Date(0) })
                        .where(eq(appRuntimeGenerations.installationId, installationId))
                    await expect(
                        renewAppRuntimeGenerationLeaseInTransaction(
                            transaction,
                            next,
                            leaseExpiresAt,
                        ),
                    ).rejects.toMatchObject({
                        code: 'conflict',
                    })
                    await revokeAppRuntimeGenerationInTransaction(transaction, next)
                    await expect(
                        resolveAppRuntimePrincipalInTransaction(transaction, { identity: next }),
                    ).rejects.toMatchObject({
                        code: 'unauthorized',
                    })
                    // Roll back synthetic principals and event rows from the dedicated CI database.
                    throw rolledBack
                }),
            ).rejects.toBe(rolledBack)
        } finally {
            if (originalEncryptionKey === undefined) delete process.env.APP_ENCRYPTION_KEY
            else process.env.APP_ENCRYPTION_KEY = originalEncryptionKey
        }
    },
)

integrationTest(
    'v1 gateway commits scoped mutations and resumes only authorized events',
    async () => {
        const { db } = await import('@/db/index.ts')
        const { createAppRuntimeGateway } = await import('@/server/AppRuntime/gateway.server.ts')
        const { manageAppRuntime } = await import('@/server/AppRuntime/management.server.ts')
        const { executeAppRuntimeCall } = await import('@/server/AppRuntime/services.server.ts')
        const originalEncryptionKey = process.env.APP_ENCRYPTION_KEY
        process.env.APP_ENCRYPTION_KEY = Buffer.alloc(32, 63).toString('base64')

        const identity = {
            appId: 'test.gateway',
            installationId: crypto.randomUUID(),
            generation: 1,
            uid: 40_453,
        }
        const shutdown = new AbortController()
        const token = 'gateway-test-bridge'
        const gateway = createAppRuntimeGateway(
            token,
            shutdown.signal,
            executeAppRuntimeCall,
            manageAppRuntime,
        )
        const send = (
            path: string,
            body?: unknown,
            headers: Readonly<Record<string, string>> = {},
            emptyPost = false,
        ) =>
            gateway(
                new Request('http://app-api' + path, {
                    method: body === undefined && !emptyPost ? 'GET' : 'POST',
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
        const api = (path: string, body?: unknown, key?: string, emptyPost = false) =>
            send('/platform/v1/' + path, body, key ? { 'Idempotency-Key': key } : {}, emptyPost)
        const publish = { id: 'notifications.publish.v1', scope: 'installation' }
        const manage = { id: 'proxy.hosts.manage-owned.v1', scope: 'ownedProxyHosts' }
        const leaseExpiresAt = new Date(Date.now() + 60_000).toISOString()

        try {
            expect((await control('unknown')).status).toBe(404)
            expect(
                (await control('register', { leaseExpiresAt, capabilities: [publish, manage] }))
                    .status,
            ).toBe(204)
            expect((await api('context')).status).toBe(200)
            const authorization = { capability: publish, resourceId: identity.installationId }
            expect((await api('authorization', authorization)).status).toBe(401)
            const { events, audit, secret } = APP_RUNTIME_SUPPORT_CAPABILITIES
            expect(
                (
                    await control('grants', {
                        grants: [
                            {
                                capability: publish,
                                resourceId: identity.installationId,
                                allowService: true,
                            },
                            {
                                capability: events,
                                resourceId: identity.installationId,
                                allowService: true,
                            },
                            {
                                capability: audit,
                                resourceId: identity.installationId,
                                allowService: true,
                            },
                            {
                                capability: secret,
                                resourceId: 'locally-assigned',
                                allowService: true,
                            },
                            { capability: manage, resourceId: 'app-host', allowService: true },
                        ],
                    })
                ).status,
            ).toBe(204)
            expect((await control('activate', { leaseExpiresAt })).status).toBe(204)
            expect((await control('renew', { leaseExpiresAt })).status).toBe(204)
            expect(await (await api('authorization', authorization)).json()).toEqual({
                allowed: true,
            })
            expect((await api('proxy-hosts/query', { limit: 0 })).status).toBe(400)
            expect(await (await api('proxy-hosts/query', { limit: 20 })).json()).toEqual({
                hosts: [],
            })
            expect((await api('providers/unregistered')).status).toBe(404)
            expect((await api('secrets/foreign')).status).toBe(404)
            expect(
                (
                    await control('put-secret', {
                        secretId: 'locally-assigned',
                        value: 'fixture-value',
                    })
                ).status,
            ).toBe(204)
            expect(await (await api('secrets/locally-assigned')).json()).toEqual({
                value: 'fixture-value',
            })
            expect((await control('delete-secret', { secretId: 'locally-assigned' })).status).toBe(
                204,
            )
            expect((await api('secrets/locally-assigned')).status).toBe(404)

            const update = await api(
                'proxy-hosts/owned',
                {
                    action: 'upsert',
                    hostId: 'app-host',
                    expectedRevision: null,
                    hostname: 'runtime-gateway.test',
                    upstream: { scheme: 'http', address: '127.0.0.1', port: 8080 },
                },
                'change-one',
            )
            expect(update.status).toBe(202)
            const operation: unknown = await update.json()
            if (
                typeof operation !== 'object' ||
                operation === null ||
                !('id' in operation) ||
                typeof operation.id !== 'string'
            )
                throw new Error('Missing operation identity')
            expect(await (await api('operations/' + operation.id)).json()).toMatchObject({
                status: 'accepted',
            })
            const cancel = await api(
                'operations/' + operation.id + '/cancel',
                undefined,
                'cancel-one',
                true,
            )
            expect(cancel.status).toBe(202)
            expect(await cancel.json()).toMatchObject({ status: 'cancelled' })

            const notification = {
                category: 'fixture',
                severity: 'warning',
                title: 'Fixture',
                message: 'One',
            }
            expect((await api('notifications', notification, 'notice-one')).status).toBe(204)
            expect((await api('notifications', notification, 'notice-one')).status).toBe(204)
            expect(
                (await api('notifications', { ...notification, message: 'Two' }, 'notice-one'))
                    .status,
            ).toBe(409)
            expect(
                (
                    await api(
                        'audit-events',
                        { action: 'validate', outcome: 'succeeded' },
                        'audit-one',
                    )
                ).status,
            ).toBe(204)

            const stream = await api('events')
            expect(stream.headers.get('Content-Type')).toBe('text/event-stream')
            // The opening transaction already delivered its authorized page to the stream.
            expect((await control('revoke')).status).toBe(204)
            const reader = stream.body?.getReader()
            if (!reader) throw new Error('Missing app event stream')
            try {
                const decoder = new TextDecoder()
                expect(decoder.decode((await reader.read()).value)).toContain(': connected')
                const firstPage = decoder.decode((await reader.read()).value)
                expect(firstPage.match(/appNotificationPublished/gu)).toHaveLength(1)
                expect(firstPage.match(/appAuditRecorded/gu)).toHaveLength(1)
                expect((await reader.read()).done).toBe(true)
            } finally {
                await reader.cancel()
            }
            expect((await api('events')).status).toBe(401)
            const replacement = { ...identity, generation: 2 }
            expect(
                (
                    await control('register', {
                        identity: replacement,
                        leaseExpiresAt,
                        capabilities: [publish, manage],
                    })
                ).status,
            ).toBe(204)
            expect(
                (await control('activate', { identity: replacement, leaseExpiresAt })).status,
            ).toBe(204)
            expect(
                (
                    await control('put-secret', {
                        identity: replacement,
                        secretId: 'locally-assigned',
                        value: 'replacement-value',
                    })
                ).status,
            ).toBe(204)
            expect(
                (
                    await control('put-secret', {
                        secretId: 'locally-assigned',
                        value: 'stale-update',
                    })
                ).status,
            ).toBe(401)
            expect((await control('delete-secret', { secretId: 'locally-assigned' })).status).toBe(
                401,
            )
            expect(
                await (
                    await send('/platform/v1/secrets/locally-assigned', undefined, {
                        'X-App-Generation': '2',
                    })
                ).json(),
            ).toEqual({ value: 'replacement-value' })
            expect(
                (
                    await control('delete-secret', {
                        identity: replacement,
                        secretId: 'locally-assigned',
                    })
                ).status,
            ).toBe(204)
        } finally {
            shutdown.abort()
            await db.transaction(async (tx) => {
                const { installationId } = identity
                await tx
                    .delete(appRuntimeEvents)
                    .where(eq(appRuntimeEvents.installationId, installationId))
                await tx
                    .delete(appRuntimeGrants)
                    .where(eq(appRuntimeGrants.installationId, installationId))
                await tx
                    .delete(appRuntimeGenerations)
                    .where(eq(appRuntimeGenerations.installationId, installationId))
                await tx
                    .delete(appRuntimeInstallations)
                    .where(eq(appRuntimeInstallations.id, installationId))
            })
            if (originalEncryptionKey === undefined) delete process.env.APP_ENCRYPTION_KEY
            else process.env.APP_ENCRYPTION_KEY = originalEncryptionKey
        }
    },
)
