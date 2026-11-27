import { expect, test } from 'bun:test'
import { count, inArray, eq, sql } from 'drizzle-orm'

import { PERMISSIONS } from '@/config/permissions.config.ts'
import {
    appRuntimeDelegations,
    appRuntimeEvents,
    appRuntimeGenerations,
    appRuntimeGrants,
    appRuntimeInstallations,
    appRuntimeOperations,
    appRuntimeOwnedProxyHosts,
    appRuntimeSecrets,
    permissions,
    proxyHosts,
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
    readAppUiActorInTransaction,
    readAppUiPrincipalInTransaction,
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
    checkAppRuntimeDependenciesInTransaction,
    registerAppRuntimeGenerationInTransaction,
    renewAppRuntimeGenerationLeaseInTransaction,
    replaceAppRuntimeGrantsInTransaction,
    revokeAppRuntimeGenerationInTransaction,
    setAppRuntimeRolePermissionInTransaction,
} from '@/server/AppRuntime/lifecycle.server.ts'
import { requireAppRuntimeAuthorization } from '@/server/AppRuntime/authority-policy.server.ts'
import { withAppRuntimeErrors } from '@/server/AppRuntime/services.server.ts'
import { createOpaqueToken, hashOpaqueToken } from '@/server/Auth/Core/tokens.server.ts'

const integrationEnabled =
    process.env.RENTNERPROXY_DATABASE_INTEGRATION === '1' && Boolean(process.env.DATABASE_URL)
const integrationTest = integrationEnabled ? test : test.skip

integrationTest('retirement waits for a registration that has not committed', async () => {
    const { db } = await import('@/db/index.ts')
    const identity = {
        installationId: crypto.randomUUID(),
        appId: 'fixture.retirement',
        uid: 40_495,
        generation: 1,
    }
    const inserted = Promise.withResolvers<void>()
    const commit = Promise.withResolvers<void>()
    const registering = db.transaction(async (transaction) => {
        await registerAppRuntimeGenerationInTransaction(transaction, {
            identity,
            leaseExpiresAt: new Date(Date.now() + 60_000),
            capabilities: [],
        })
        inserted.resolve()
        await commit.promise
    })
    try {
        await Promise.race([inserted.promise, registering])
        await expect(
            db.transaction(async (transaction) => {
                await transaction.execute(sql`set local lock_timeout = '100ms'`)
                await revokeAppRuntimeGenerationInTransaction(transaction, identity, true)
            }),
        ).rejects.toThrow()
        commit.resolve()
        await registering
        await db.transaction(async (transaction) => {
            await revokeAppRuntimeGenerationInTransaction(transaction, identity, true)
            await checkAppRuntimeDependenciesInTransaction(transaction, identity, 'purge-data')
        })
    } finally {
        commit.resolve()
        await registering
        await db.transaction(async (transaction) => {
            await transaction
                .delete(appRuntimeGenerations)
                .where(eq(appRuntimeGenerations.installationId, identity.installationId))
            await transaction
                .delete(appRuntimeInstallations)
                .where(eq(appRuntimeInstallations.id, identity.installationId))
        })
    }
})

integrationTest(
    'revoking a grant of the active generation refuses its next call at once',
    async () => {
        const { db } = await import('@/db/index.ts')
        const rolledBack = new Error('grant revocation test rollback')
        const originalEncryptionKey = process.env.APP_ENCRYPTION_KEY
        // Event cursors are sealed with the app encryption key.
        process.env.APP_ENCRYPTION_KEY = Buffer.alloc(32, 52).toString('base64')
        try {
            await expect(
                db.transaction(async (transaction) => {
                    const installationId = crypto.randomUUID()
                    const identity = {
                        installationId,
                        appId: 'fixture.revocation',
                        uid: 40_497,
                        generation: 1,
                    }
                    const credentials = { identity }
                    const leaseExpiresAt = new Date(Date.now() + 60_000)
                    const read = { id: 'proxy.hosts.read.v1', scope: 'proxyHosts' }
                    const host = crypto.randomUUID()
                    const granted = [
                        { capability: read, resourceId: host, allowService: true },
                        {
                            capability: APP_RUNTIME_SUPPORT_CAPABILITIES.events,
                            resourceId: installationId,
                            allowService: true,
                        },
                    ]
                    await registerAppRuntimeGenerationInTransaction(transaction, {
                        identity,
                        leaseExpiresAt,
                        capabilities: [read],
                    })
                    await replaceAppRuntimeGrantsInTransaction(transaction, identity, granted)
                    await activateAppRuntimeGenerationInTransaction(
                        transaction,
                        identity,
                        leaseExpiresAt,
                    )
                    const before = await resolveAppRuntimePrincipalInTransaction(
                        transaction,
                        credentials,
                    )
                    expect(before.kind).toBe('service')
                    expect(isAppRuntimeAuthorized(before, read, host)).toBe(true)
                    await appendAppRuntimeEventInTransaction(transaction, {
                        installationId,
                        type: 'proxyHostChanged',
                        capability: read,
                        resourceId: host,
                    })
                    const replay = await replayAppRuntimeEventsInTransaction(
                        transaction,
                        credentials,
                    )
                    expect(replay.events).toHaveLength(1)

                    // The app manager publishes the remaining approval for the same live generation.
                    await replaceAppRuntimeGrantsInTransaction(
                        transaction,
                        identity,
                        granted.slice(1),
                    )
                    const after = await resolveAppRuntimePrincipalInTransaction(
                        transaction,
                        credentials,
                    )
                    expect(after.identity.generation).toBe(1)
                    expect(after.authorizationEpoch).toBe(before.authorizationEpoch + 1n)
                    await expect(
                        withAppRuntimeErrors(async () => {
                            requireAppRuntimeAuthorization(after, read, host)
                        }),
                    ).rejects.toMatchObject({ status: 403 })
                    const generations = await transaction
                        .select({
                            generation: appRuntimeGenerations.generation,
                            state: appRuntimeGenerations.state,
                        })
                        .from(appRuntimeGenerations)
                        .where(eq(appRuntimeGenerations.installationId, installationId))
                    expect(generations).toEqual([{ generation: 1, state: 'active' }])
                    // The epoch is part of the event cursor, so a cursor from before the change expires.
                    await expect(
                        replayAppRuntimeEventsInTransaction(
                            transaction,
                            credentials,
                            replay.cursor,
                        ),
                    ).rejects.toMatchObject({ code: 'cursor_expired' })
                    expect(
                        (await replayAppRuntimeEventsInTransaction(transaction, credentials))
                            .events,
                    ).toEqual([])
                    // Publishing an identical set changes nothing, so every launch may republish it.
                    await replaceAppRuntimeGrantsInTransaction(
                        transaction,
                        identity,
                        granted.slice(1),
                    )
                    const unchanged = await resolveAppRuntimePrincipalInTransaction(
                        transaction,
                        credentials,
                    )
                    expect(unchanged.authorizationEpoch).toBe(after.authorizationEpoch)
                    // Revoking the event subscription refuses the next replay as well.
                    await replaceAppRuntimeGrantsInTransaction(transaction, identity, [])
                    await expect(
                        withAppRuntimeErrors(() =>
                            replayAppRuntimeEventsInTransaction(transaction, credentials),
                        ),
                    ).rejects.toMatchObject({ status: 403 })
                    throw rolledBack
                }),
            ).rejects.toBe(rolledBack)
        } finally {
            if (originalEncryptionKey === undefined) delete process.env.APP_ENCRYPTION_KEY
            else process.env.APP_ENCRYPTION_KEY = originalEncryptionKey
        }
    },
)

integrationTest('removal and data purge wait while the app owns a proxy host', async () => {
    const { db } = await import('@/db/index.ts')
    const rolledBack = new Error('owned host test rollback')
    await expect(
        db.transaction(async (transaction) => {
            const identity = {
                installationId: crypto.randomUUID(),
                appId: 'fixture.owned-host',
                uid: 40_496,
                generation: 1,
            }
            const leaseExpiresAt = new Date(Date.now() + 60_000)
            await registerAppRuntimeGenerationInTransaction(transaction, {
                identity,
                leaseExpiresAt,
                capabilities: [],
            })
            await activateAppRuntimeGenerationInTransaction(transaction, identity, leaseExpiresAt)
            const proxyHostId = crypto.randomUUID()
            await transaction.insert(proxyHosts).values({
                id: proxyHostId,
                forwardScheme: 'http',
                forwardHost: '172.22.0.5',
                forwardPort: 8080,
            })
            await transaction.insert(appRuntimeOwnedProxyHosts).values({
                installationId: identity.installationId,
                hostId: 'owned-host',
                proxyHostId,
            })

            // The app manager checks before and after it stopped the generation.
            await expect(
                checkAppRuntimeDependenciesInTransaction(transaction, identity, 'removable'),
            ).rejects.toMatchObject({ code: 'conflict' })
            await checkAppRuntimeDependenciesInTransaction(transaction, identity, 'workers-stopped')
            await revokeAppRuntimeGenerationInTransaction(transaction, identity)
            await expect(
                checkAppRuntimeDependenciesInTransaction(transaction, identity, 'removable'),
            ).rejects.toMatchObject({ code: 'conflict' })
            await expect(
                checkAppRuntimeDependenciesInTransaction(transaction, identity, 'purge-data'),
            ).rejects.toMatchObject({ code: 'conflict' })

            // Deleting the host ends the ownership, so removal and the purge may proceed.
            await transaction.delete(proxyHosts).where(eq(proxyHosts.id, proxyHostId))
            await checkAppRuntimeDependenciesInTransaction(transaction, identity, 'removable')
            await checkAppRuntimeDependenciesInTransaction(transaction, identity, 'purge-data')
            // Roll back the synthetic installation and host in the dedicated CI database.
            throw rolledBack
        }),
    ).rejects.toBe(rolledBack)
})

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
                        hasUi: true,
                    }
                    const retired = {
                        ...identity,
                        installationId: crypto.randomUUID(),
                        uid: 40_494,
                    }
                    await revokeAppRuntimeGenerationInTransaction(transaction, retired, true)
                    await expect(
                        registerAppRuntimeGenerationInTransaction(transaction, {
                            ...registration,
                            identity: retired,
                        }),
                    ).rejects.toMatchObject({ code: 'conflict' })
                    const successor = { ...retired, generation: 2 }
                    await registerAppRuntimeGenerationInTransaction(transaction, {
                        ...registration,
                        identity: successor,
                    })
                    await replaceAppRuntimeGrantsInTransaction(transaction, successor, [
                        { capability: read, resourceId: 'other-host', allowService: false },
                    ])
                    await activateAppRuntimeGenerationInTransaction(
                        transaction,
                        successor,
                        leaseExpiresAt,
                    )
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
                    const uiActor = await readAppUiActorInTransaction(transaction, sessionId)
                    await expect(
                        readAppUiPrincipalInTransaction(transaction, identity, uiActor),
                    ).rejects.toMatchObject({ code: 'forbidden' })
                    await setAppRuntimeRolePermissionInTransaction(
                        transaction,
                        identity,
                        roleId,
                        'use-secret',
                        true,
                    )
                    const uiPrincipal = await readAppUiPrincipalInTransaction(
                        transaction,
                        identity,
                        uiActor,
                        true,
                    )
                    expect(uiPrincipal.appPermissions).toEqual(['app:test.integration:use-secret'])
                    expect(isAppRuntimeAuthorized(uiPrincipal, read, 'managed-host-a')).toBe(true)
                    expect(isAppRuntimeAuthorized(uiPrincipal, read, 'other-host')).toBe(false)
                    await expect(
                        readAppUiPrincipalInTransaction(
                            transaction,
                            { ...identity, generation: 2 },
                            uiActor,
                        ),
                    ).rejects.toMatchObject({ code: 'unauthorized' })
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
                    await expect(
                        checkAppRuntimeDependenciesInTransaction(transaction, next, 'purge-data'),
                    ).rejects.toMatchObject({ code: 'conflict' })
                    await revokeAppRuntimeGenerationInTransaction(transaction, next)
                    const operation = crypto.randomUUID()
                    await transaction.insert(appRuntimeOperations).values({
                        id: operation,
                        installationId,
                        generation: next.generation,
                        requestId: 'fixture-work',
                        status: 'accepted',
                        input: { action: 'remove', hostId: 'fixture', expectedRevision: 'one' },
                    })
                    await expect(
                        checkAppRuntimeDependenciesInTransaction(transaction, next, 'removable'),
                    ).rejects.toMatchObject({ code: 'conflict' })
                    await transaction
                        .update(appRuntimeOperations)
                        .set({ status: 'cancelled' })
                        .where(eq(appRuntimeOperations.id, operation))
                    await checkAppRuntimeDependenciesInTransaction(
                        transaction,
                        next,
                        'workers-stopped',
                    )
                    await checkAppRuntimeDependenciesInTransaction(transaction, next, 'removable')
                    const grantsFor = (id: string) =>
                        transaction
                            .select({ id: appRuntimeGrants.resourceId })
                            .from(appRuntimeGrants)
                            .where(eq(appRuntimeGrants.installationId, id))
                    expect((await grantsFor(installationId)).length).toBeGreaterThan(0)
                    await checkAppRuntimeDependenciesInTransaction(transaction, next, 'purge-data')
                    expect(await grantsFor(installationId)).toEqual([])
                    expect(await grantsFor(successor.installationId)).toEqual([
                        { id: 'other-host' },
                    ])
                    await expect(
                        checkAppRuntimeDependenciesInTransaction(
                            transaction,
                            { ...next, uid: next.uid + 1 },
                            'purge-data',
                        ),
                    ).rejects.toMatchObject({ code: 'unauthorized' })
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
        const assignedSecret = 'locally-assigned'
        const retiredSecret = 'retired-on-activation'
        const putSecret = (secretId: string, value: string, target = identity) =>
            control('put-secret', { identity: target, secretId, value })
        const deleteSecret = (secretId: string, target = identity) =>
            control('delete-secret', { identity: target, secretId })
        const readSecret = (secretId: string, target = identity) =>
            send('/platform/v1/secrets/' + secretId, undefined, {
                'X-App-Generation': String(target.generation),
            })

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
            const secretGrants = [assignedSecret, retiredSecret].map((resourceId) => ({
                capability: secret,
                resourceId,
                allowService: true,
            }))
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
                            ...secretGrants,
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
            expect((await putSecret(assignedSecret, 'fixture-value')).status).toBe(204)
            expect(await (await readSecret(assignedSecret)).json()).toEqual({
                value: 'fixture-value',
            })
            expect((await deleteSecret(assignedSecret)).status).toBe(204)
            expect((await readSecret(assignedSecret)).status).toBe(404)
            expect((await putSecret(assignedSecret, 'active-value')).status).toBe(204)
            expect((await putSecret(retiredSecret, 'retired-value')).status).toBe(204)

            const abandoned = { ...identity, generation: 2 }
            expect(
                (
                    await control('register', {
                        identity: abandoned,
                        leaseExpiresAt,
                        capabilities: [publish],
                    })
                ).status,
            ).toBe(204)
            expect((await control('grants', { identity: abandoned, grants: [] })).status).toBe(204)
            expect((await putSecret(assignedSecret, 'abandoned-value', abandoned)).status).toBe(204)
            expect((await deleteSecret(retiredSecret, abandoned)).status).toBe(204)
            const abandonedContext = await send('/platform/v1/context', undefined, {
                'X-App-Generation': String(abandoned.generation),
            })
            expect(await abandonedContext.json()).toMatchObject({ capabilities: [] })
            expect(await (await api('authorization', authorization)).json()).toEqual({
                allowed: true,
            })
            expect(await (await readSecret(assignedSecret)).json()).toEqual({
                value: 'active-value',
            })
            expect(await (await readSecret(retiredSecret)).json()).toEqual({
                value: 'retired-value',
            })
            expect(
                (
                    await control('activate', {
                        identity: abandoned,
                        leaseExpiresAt: new Date(0).toISOString(),
                    })
                ).status,
            ).toBe(400)
            const failedActivation = new Error('synthetic activation rollback')
            await expect(
                db.transaction(async (transaction) => {
                    await activateAppRuntimeGenerationInTransaction(
                        transaction,
                        abandoned,
                        new Date(leaseExpiresAt),
                    )
                    await expect(
                        readAppRuntimeContextInTransaction(transaction, identity),
                    ).rejects.toMatchObject({ code: 'unauthorized' })
                    throw failedActivation
                }),
            ).rejects.toBe(failedActivation)
            expect((await control('revoke', { identity: abandoned })).status).toBe(204)
            expect(await (await api('authorization', authorization)).json()).toEqual({
                allowed: true,
            })
            expect(await (await readSecret(assignedSecret)).json()).toEqual({
                value: 'active-value',
            })
            expect(await (await readSecret(retiredSecret)).json()).toEqual({
                value: 'retired-value',
            })

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
            const payloads = await db
                .select({ kind: sql<string>`jsonb_typeof(${appRuntimeEvents.payload})` })
                .from(appRuntimeEvents)
                .where(eq(appRuntimeEvents.installationId, identity.installationId))
            expect(payloads.map(({ kind }) => kind)).toEqual(['object', 'object'])

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
            const replacement = { ...identity, generation: 3 }
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
                (await control('grants', { identity: replacement, grants: secretGrants })).status,
            ).toBe(204)
            expect((await putSecret(assignedSecret, 'replacement-value', replacement)).status).toBe(
                204,
            )
            expect((await deleteSecret(retiredSecret, replacement)).status).toBe(204)
            expect(
                (await control('activate', { identity: replacement, leaseExpiresAt })).status,
            ).toBe(204)
            expect((await putSecret(assignedSecret, 'stale-update')).status).toBe(401)
            expect((await deleteSecret(assignedSecret)).status).toBe(401)
            expect(await (await readSecret(assignedSecret, replacement)).json()).toEqual({
                value: 'replacement-value',
            })
            expect((await readSecret(retiredSecret, replacement)).status).toBe(404)
            const replacementAuthorization = await send(
                '/platform/v1/authorization',
                authorization,
                {
                    'X-App-Generation': String(replacement.generation),
                },
            )
            expect(await replacementAuthorization.json()).toEqual({ allowed: false })
        } finally {
            shutdown.abort()
            if (originalEncryptionKey === undefined) delete process.env.APP_ENCRYPTION_KEY
            else process.env.APP_ENCRYPTION_KEY = originalEncryptionKey
            await db.transaction(async (tx) => {
                const { installationId } = identity
                await tx
                    .delete(appRuntimeEvents)
                    .where(eq(appRuntimeEvents.installationId, installationId))
                await tx
                    .delete(appRuntimeGrants)
                    .where(eq(appRuntimeGrants.installationId, installationId))
                await tx
                    .delete(appRuntimeSecrets)
                    .where(eq(appRuntimeSecrets.installationId, installationId))
                await tx
                    .delete(appRuntimeGenerations)
                    .where(eq(appRuntimeGenerations.installationId, installationId))
                await tx
                    .delete(appRuntimeInstallations)
                    .where(eq(appRuntimeInstallations.id, installationId))
            })
        }
    },
)
