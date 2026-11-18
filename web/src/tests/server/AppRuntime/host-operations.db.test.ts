import { randomUUID } from 'node:crypto'
import { expect, test } from 'bun:test'
import { and, eq, inArray, notInArray, sql } from 'drizzle-orm'
import {
    appRuntimeEvents,
    appRuntimeGenerations,
    appRuntimeGrants,
    appRuntimeInstallations,
    appRuntimeOperations,
    appRuntimeOwnedProxyHosts,
    auditEvents,
    proxyHosts,
} from '@/db/schema.ts'
import {
    listAppProxyHosts,
    manageOwnedHosts,
    probeAppProxyUpstream,
} from '@/server/AppRuntime/hosts.server.ts'
import {
    activateAppRuntimeGenerationInTransaction,
    registerAppRuntimeGenerationInTransaction,
    replaceAppRuntimeGrantsInTransaction,
} from '@/server/AppRuntime/lifecycle.server.ts'
import {
    cancelAppOperation,
    createAppProxyOperationWorker,
    getAppOperation,
    updateAppOwnedProxyHost,
} from '@/server/AppRuntime/operations.server.ts'
import type {
    AppRuntimeGrant,
    AppRuntimeIdentity,
} from '@/server/AppRuntime/Types/authority.types.ts'
import type { AppOperation } from '@/server/AppRuntime/Types/operations.types.ts'
import type { ProxyRuntimeMutationStatus } from '@/lib/ProxyRuntime/Types/proxy-runtime.types.ts'
import { getAuthDatabase } from '@/server/Auth/Core/database.server.ts'
import { getDatabaseUrl } from '@/server/env.server.ts'

const integrationTest =
    process.env.RENTNERPROXY_DATABASE_INTEGRATION === '1' && getDatabaseUrl() !== null
        ? test
        : test.skip
const readHosts = { id: 'proxy.hosts.read.v1', scope: 'proxyHosts' }
const probeHosts = { id: 'diagnostics.upstream.probe.v1', scope: 'proxyHosts' }

async function install(identity: AppRuntimeIdentity, grants: readonly AppRuntimeGrant[]) {
    const leaseExpiresAt = new Date(Date.now() + 60_000)
    await getAuthDatabase().transaction(async (transaction) => {
        await registerAppRuntimeGenerationInTransaction(transaction, {
            identity,
            leaseExpiresAt,
            capabilities: [manageOwnedHosts, readHosts, probeHosts],
        })
        await activateAppRuntimeGenerationInTransaction(transaction, identity, leaseExpiresAt)
        await replaceAppRuntimeGrantsInTransaction(transaction, identity, grants)
    })
}

async function waitForOperation(
    read: () => Promise<AppOperation>,
    status: AppOperation['status'],
): Promise<AppOperation> {
    const deadline = Date.now() + 4_000
    let operation = await read()
    while (operation.status !== status && Date.now() < deadline) {
        if (operation.status === 'failed')
            throw new Error(`Unexpected operation problem: ${operation.problem.code}`)
        // oxlint-disable-next-line no-await-in-loop -- The worker is asynchronous across transactions.
        await Bun.sleep(25)
        // oxlint-disable-next-line no-await-in-loop -- The worker is asynchronous across transactions.
        operation = await read()
    }
    expect(operation.status).toBe(status)
    return operation
}

integrationTest(
    'app proxy operations fence ownership, cancellation, and duplicate replay across worker restart',
    async () => {
        const db = getAuthDatabase()
        const [database] = await db.execute<{ name: string }>(
            sql`select current_database() as name`,
        )
        if (database?.name !== 'rentnerproxy_upstream_test')
            throw new Error('App proxy operations require the dedicated integration database')
        const installationId = randomUUID()
        const foreignInstallationId = randomUUID()
        const installationIds = [installationId, foreignInstallationId]
        const owner = {
            identity: { appId: 'fixture.app', installationId, generation: 1, uid: 59_974 },
        }
        const foreign = {
            identity: {
                appId: 'fixture.other',
                installationId: foreignInstallationId,
                generation: 1,
                uid: 59_975,
            },
        }
        const acceptedGrant = {
            capability: manageOwnedHosts,
            resourceId: 'owned-host',
            allowService: true,
        }
        const cancelGrant = {
            capability: manageOwnedHosts,
            resourceId: 'cancelled-host',
            allowService: true,
        }
        const change = {
            action: 'upsert',
            hostId: 'owned-host',
            expectedRevision: null,
            hostname: `app-${installationId}.example.test`,
            upstream: { scheme: 'http', address: 'upstream.example.test', port: 8080 },
        } as const
        const { promise: heldReconcile, resolve: releaseReconcile } =
            Promise.withResolvers<ProxyRuntimeMutationStatus>()
        const firstWorker = createAppProxyOperationWorker(() => heldReconcile)
        const recoveredWorker = createAppProxyOperationWorker(() => Promise.resolve('applied'))

        const [foreignPending] = await db
            .select({ id: appRuntimeOperations.id })
            .from(appRuntimeOperations)
            .where(
                and(
                    notInArray(appRuntimeOperations.installationId, installationIds),
                    inArray(appRuntimeOperations.status, ['running', 'accepted']),
                ),
            )
            .limit(1)
        if (foreignPending)
            throw new Error('Unexpected queued app operation in dedicated test database')

        try {
            await install(owner.identity, [acceptedGrant, cancelGrant])
            await install(foreign.identity, [acceptedGrant])
            await expect(
                updateAppOwnedProxyHost(
                    owner,
                    { ...change, hostId: 'out-of-scope' },
                    'scope',
                    'r1',
                ),
            ).rejects.toMatchObject({ code: 'forbidden' })
            const accepted = await updateAppOwnedProxyHost(owner, change, 'owned-change', 'r2')
            expect(accepted.status).toBe('accepted')
            expect(await updateAppOwnedProxyHost(owner, change, 'owned-change', 'r3')).toEqual(
                accepted,
            )
            await expect(
                updateAppOwnedProxyHost(
                    owner,
                    { ...change, hostname: 'different.example.test' },
                    'owned-change',
                    'r4',
                ),
            ).rejects.toMatchObject({ code: 'idempotencyConflict' })
            await expect(getAppOperation(foreign, accepted.id)).rejects.toMatchObject({
                code: 'not_found',
            })
            await expect(
                cancelAppOperation(foreign, accepted.id, 'cancel', 'r5'),
            ).rejects.toMatchObject({ code: 'not_found' })

            const other = await updateAppOwnedProxyHost(
                owner,
                {
                    ...change,
                    hostId: 'cancelled-host',
                    hostname: `cancelled-${installationId}.example.test`,
                },
                'cancelled-change',
                'r6',
            )
            const cancelled = { id: other.id, status: 'cancelled' } as const
            expect(await cancelAppOperation(owner, other.id, 'cancel', 'r7')).toEqual(cancelled)
            expect(await cancelAppOperation(owner, other.id, 'cancel', 'r8')).toEqual(cancelled)

            firstWorker.start()
            await waitForOperation(() => getAppOperation(owner, accepted.id), 'running')
            await firstWorker.stop()
            releaseReconcile('pending')
            recoveredWorker.start()
            const result = await waitForOperation(
                () => getAppOperation(owner, accepted.id),
                'succeeded',
            )
            expect(await updateAppOwnedProxyHost(owner, change, 'owned-change', 'r9')).toEqual(
                result,
            )
            expect(await getAppOperation(owner, other.id)).toEqual(cancelled)

            if (result.status !== 'succeeded' || result.result?.action !== 'upsert')
                throw new Error('Expected durable owned host result')
            const { platformHostId, revision } = result.result.host
            const ownership = await db
                .select()
                .from(appRuntimeOwnedProxyHosts)
                .where(eq(appRuntimeOwnedProxyHosts.installationId, installationId))
            expect(ownership).toEqual([
                { installationId, hostId: change.hostId, proxyHostId: platformHostId },
            ])
            await expect(
                updateAppOwnedProxyHost(
                    owner,
                    { ...change, expectedRevision: 'stale' },
                    'stale',
                    'r10',
                ),
            ).rejects.toMatchObject({ code: 'hostRevisionConflict' })
            await expect(
                updateAppOwnedProxyHost(
                    foreign,
                    { ...change, expectedRevision: revision },
                    'foreign',
                    'r11',
                ),
            ).rejects.toMatchObject({ code: 'hostRevisionConflict' })
            expect(await listAppProxyHosts(owner, { limit: 10 })).toEqual({ hosts: [] })
            await db.transaction((transaction) =>
                replaceAppRuntimeGrantsInTransaction(transaction, owner.identity, [
                    acceptedGrant,
                    { capability: readHosts, resourceId: change.hostId, allowService: true },
                    { capability: probeHosts, resourceId: change.hostId, allowService: true },
                ]),
            )
            expect(await listAppProxyHosts(owner, { limit: 10 })).toEqual({
                hosts: [{ id: change.hostId, hostname: change.hostname, revision }],
            })
            await expect(
                probeAppProxyUpstream(foreign, { hostId: change.hostId, timeoutMs: 1 }),
            ).rejects.toMatchObject({ code: 'forbidden' })
            expect(
                await probeAppProxyUpstream(owner, { hostId: change.hostId, timeoutMs: 1 }),
            ).toEqual({ outcome: 'timedOut' })
            await db.transaction((transaction) =>
                replaceAppRuntimeGrantsInTransaction(transaction, foreign.identity, [
                    acceptedGrant,
                    { capability: readHosts, resourceId: change.hostId, allowService: true },
                    { capability: probeHosts, resourceId: change.hostId, allowService: true },
                ]),
            )
            expect(await listAppProxyHosts(foreign, { limit: 10 })).toEqual({ hosts: [] })
            await expect(
                probeAppProxyUpstream(foreign, { hostId: change.hostId, timeoutMs: 1 }),
            ).rejects.toMatchObject({ code: 'not_found' })
        } finally {
            await firstWorker.stop()
            releaseReconcile('pending')
            await recoveredWorker.stop()
            await db.transaction(async (transaction) => {
                const owned = await transaction
                    .select({ id: appRuntimeOwnedProxyHosts.proxyHostId })
                    .from(appRuntimeOwnedProxyHosts)
                    .where(inArray(appRuntimeOwnedProxyHosts.installationId, installationIds))
                const ids = owned.map(({ id }) => id)
                if (ids.length) {
                    await transaction.delete(auditEvents).where(inArray(auditEvents.targetId, ids))
                    await transaction.delete(proxyHosts).where(inArray(proxyHosts.id, ids))
                }
                await transaction
                    .delete(appRuntimeEvents)
                    .where(inArray(appRuntimeEvents.installationId, installationIds))
                await transaction
                    .delete(appRuntimeGrants)
                    .where(inArray(appRuntimeGrants.installationId, installationIds))
                await transaction
                    .delete(appRuntimeGenerations)
                    .where(inArray(appRuntimeGenerations.installationId, installationIds))
                await transaction
                    .delete(appRuntimeInstallations)
                    .where(inArray(appRuntimeInstallations.id, installationIds))
            })
        }
    },
    15_000,
)
