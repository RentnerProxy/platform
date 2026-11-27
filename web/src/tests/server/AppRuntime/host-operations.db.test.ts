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
    hostDomains,
    proxyHosts,
    systemSettings,
} from '@/db/schema.ts'
import { getPageErrorDetails } from '@/lib/Errors/pageError.ts'
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
import {
    lockProxyRuntimeSettings,
    PROXY_RUNTIME_SETTINGS_KEY,
} from '@/server/ProxyRuntime/proxy-runtime-settings.ts'
import { getProxyRuntimeSnapshotService } from '@/server/ProxyRuntime/proxy-runtime.service.ts'

const integrationTest =
    process.env.RENTNERPROXY_DATABASE_INTEGRATION === '1' && getDatabaseUrl() !== null
        ? test
        : test.skip
const readHosts = { id: 'proxy.hosts.read.v1', scope: 'proxyHosts' }
const probeHosts = { id: 'diagnostics.upstream.probe.v1', scope: 'proxyHosts' }

async function acknowledgeCurrentProxySnapshot() {
    const { revision } = await getProxyRuntimeSnapshotService()
    return { available: true, running: true, activeRevision: revision, lastApplyAt: null }
}

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

async function waitForReleasedClaim(operationId: string): Promise<void> {
    const db = getAuthDatabase()
    const readClaim = async () => {
        const [claim] = await db
            .select({ token: appRuntimeOperations.leaseToken })
            .from(appRuntimeOperations)
            .where(eq(appRuntimeOperations.id, operationId))
        return claim
    }
    const deadline = Date.now() + 4_000
    let claim = await readClaim()
    while (claim?.token && Date.now() < deadline) {
        // oxlint-disable-next-line no-await-in-loop -- Observe a separate worker transaction's rollback and release.
        await Bun.sleep(25)
        // oxlint-disable-next-line no-await-in-loop -- Observe a separate worker transaction's rollback and release.
        claim = await readClaim()
    }
    expect(claim?.token).toBeNull()
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
        const {
            promise: settingsHeld,
            resolve: announceSettingsLock,
            reject: rejectSettingsLock,
        } = Promise.withResolvers<void>()
        const { promise: settingsRelease, resolve: releaseSettingsLock } =
            Promise.withResolvers<void>()
        let settingsBlocker: Promise<void> | undefined
        let controllerSampleHeldSettingsLock = false
        let recoveredAttempts = 0
        const recoveredWorker = createAppProxyOperationWorker(
            async () => {
                recoveredAttempts += 1
                if (recoveredAttempts === 1) {
                    settingsBlocker = db
                        .transaction(async (transaction) => {
                            await lockProxyRuntimeSettings(transaction)
                            announceSettingsLock()
                            await settingsRelease
                        })
                        .catch(rejectSettingsLock)
                    await settingsHeld
                }
                return 'applied'
            },
            async () => {
                try {
                    await db.execute(sql`select id from ${systemSettings}
                    where key = ${PROXY_RUNTIME_SETTINGS_KEY} for update nowait`)
                } catch (error) {
                    if (getPageErrorDetails(error).code !== 'RP_DATABASE_BUSY') throw error
                    controllerSampleHeldSettingsLock = true
                }
                return acknowledgeCurrentProxySnapshot()
            },
        )
        const recreatedHostIds: string[] = []

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
            const cancelledRead = new Error('Cancelled read')
            const cancelledSignal = AbortSignal.abort(cancelledRead)
            await expect(getAppOperation(owner, accepted.id, cancelledSignal)).rejects.toBe(
                cancelledRead,
            )
            await expect(listAppProxyHosts(owner, { limit: 10 }, cancelledSignal)).rejects.toBe(
                cancelledRead,
            )
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

            // Simulate an operation that spent longer than the apply budget in the queue.
            const [queued] = await db
                .update(appRuntimeOperations)
                .set({ createdAt: sql`clock_timestamp() - interval '5 minutes'` })
                .where(eq(appRuntimeOperations.id, accepted.id))
                .returning({
                    createdAt: appRuntimeOperations.createdAt,
                    startedAt: appRuntimeOperations.startedAt,
                })
            if (!queued) throw new Error('Expected queued operation')
            expect(queued.startedAt).toBeNull()
            firstWorker.start()
            await waitForOperation(() => getAppOperation(owner, accepted.id), 'running')
            const [running] = await db
                .select({ startedAt: appRuntimeOperations.startedAt })
                .from(appRuntimeOperations)
                .where(eq(appRuntimeOperations.id, accepted.id))
            if (!running?.startedAt) throw new Error('Expected durable confirmation start')
            expect(running.startedAt.getTime() - queued.createdAt.getTime()).toBeGreaterThan(
                120_000,
            )
            await firstWorker.stop()
            releaseReconcile('pending')
            recoveredWorker.start()
            await settingsHeld
            // The first confirmation times out while this lock is still held. Release must
            // use its own transaction and cannot depend on reacquiring the settings lock.
            await waitForReleasedClaim(accepted.id)
            expect(await getAppOperation(owner, accepted.id)).toEqual({
                id: accepted.id,
                status: 'running',
            })
            releaseSettingsLock()
            await settingsBlocker
            const result = await waitForOperation(
                () => getAppOperation(owner, accepted.id),
                'succeeded',
            )
            expect(recoveredAttempts).toBe(2)
            expect(controllerSampleHeldSettingsLock).toBe(true)
            const [settled] = await db
                .select({ startedAt: appRuntimeOperations.startedAt })
                .from(appRuntimeOperations)
                .where(eq(appRuntimeOperations.id, accepted.id))
            expect(settled?.startedAt).toEqual(running.startedAt)
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
                hosts: [
                    {
                        id: change.hostId,
                        hostname: change.hostname,
                        revision,
                        platformHostId,
                        enabled: true,
                        domains: [change.hostname],
                        upstream: {
                            scheme: change.upstream.scheme,
                            targets: [
                                { address: change.upstream.address, port: change.upstream.port },
                            ],
                            pool: null,
                        },
                        probeRevision: expect.stringMatching(/^[a-f0-9]{64}$/u),
                    },
                ],
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

            await recoveredWorker.stop()
            const changed = {
                ...change,
                expectedRevision: revision,
                upstream: { ...change.upstream, port: 8081 },
            }
            const queuedUpdate = await updateAppOwnedProxyHost(
                owner,
                changed,
                'superseded-update',
                'r12',
            )
            const editingWorker = createAppProxyOperationWorker(async () => {
                await db.transaction(async (transaction) => {
                    await lockProxyRuntimeSettings(transaction)
                    await transaction
                        .update(proxyHosts)
                        .set({ forwardPort: 8082, updatedAt: new Date() })
                        .where(eq(proxyHosts.id, platformHostId))
                })
                return 'applied'
            }, acknowledgeCurrentProxySnapshot)
            editingWorker.start()
            try {
                const failed = await waitForOperation(
                    () => getAppOperation(owner, queuedUpdate.id),
                    'failed',
                )
                expect(failed).toMatchObject({
                    problem: { status: 409, code: 'hostRevisionConflict' },
                })
                expect(
                    await updateAppOwnedProxyHost(owner, changed, 'superseded-update', 'r13'),
                ).toEqual(failed)
            } finally {
                await editingWorker.stop()
            }

            const [ownedHost] = (await listAppProxyHosts(owner, { limit: 10 })).hosts
            const [restoredHost] = await db
                .select()
                .from(proxyHosts)
                .where(eq(proxyHosts.id, platformHostId))
            if (!ownedHost || !restoredHost) throw new Error('Expected the superseding host')
            expect(restoredHost.forwardPort).toBe(8082)
            const queuedRemove = await updateAppOwnedProxyHost(
                owner,
                {
                    action: 'remove',
                    hostId: ownedHost.id,
                    expectedRevision: ownedHost.revision,
                },
                'superseded-remove',
                'r14',
            )
            recreatedHostIds.push(platformHostId)
            const restoringWorker = createAppProxyOperationWorker(async () => {
                await db.transaction(async (transaction) => {
                    await lockProxyRuntimeSettings(transaction)
                    await transaction.insert(proxyHosts).values(restoredHost)
                    await transaction.insert(hostDomains).values({
                        proxyHostId: platformHostId,
                        domain: change.hostname,
                    })
                })
                return 'applied'
            }, acknowledgeCurrentProxySnapshot)
            restoringWorker.start()
            try {
                const failed = await waitForOperation(
                    () => getAppOperation(owner, queuedRemove.id),
                    'failed',
                )
                expect(failed).toMatchObject({
                    problem: { status: 409, code: 'hostRevisionConflict' },
                })
            } finally {
                await restoringWorker.stop()
            }
        } finally {
            releaseSettingsLock()
            await settingsBlocker
            await firstWorker.stop()
            releaseReconcile('pending')
            await recoveredWorker.stop()
            await db.transaction(async (transaction) => {
                const owned = await transaction
                    .select({ id: appRuntimeOwnedProxyHosts.proxyHostId })
                    .from(appRuntimeOwnedProxyHosts)
                    .where(inArray(appRuntimeOwnedProxyHosts.installationId, installationIds))
                const ids = [...new Set([...owned.map(({ id }) => id), ...recreatedHostIds])]
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
