import { randomUUID } from 'node:crypto'
import { afterAll, afterEach, beforeAll, describe, expect, test } from 'bun:test'
import { eq, inArray, sql } from 'drizzle-orm'
import { HOST_MONITORING_LIMITS } from '@/config/host-monitoring.config.ts'
import { PERMISSIONS } from '@/config/permissions.config.ts'
import {
    appRuntimeInstallations,
    hostCheckIncidents,
    hostCheckPolicies,
    legacyFeatureHandoffs,
    permissions,
    proxyHosts,
    rolePermissions,
    roles,
    userRoles,
    users,
} from '@/db/schema.ts'
import { ensureAuthorizationRegistryInTransaction } from '@/server/Auth/Access/registry.service.ts'
import { getAuthDatabase } from '@/server/Auth/Core/database.server.ts'
import { getDatabaseUrl } from '@/server/env.server.ts'
import { HostMonitoringError } from '@/server/HostMonitoring/host-monitoring.errors.ts'
import {
    claimDueHostMonitoringPolicies,
    completeHostMonitoringClaim,
    completeHostMonitoringClaims,
    invalidateHostMonitoringForHostsInTransaction,
    pruneHostMonitoringHistory,
    releaseHostMonitoringClaims,
} from '@/server/HostMonitoring/host-monitoring.repository.ts'
import { createHostMonitoringService } from '@/server/HostMonitoring/host-monitoring.service.ts'
import type { HostMonitoringClaim } from '@/server/HostMonitoring/Types/host-monitoring.repository.types.ts'
import { LEGACY_HANDOFF_LIMITS } from '@/config/legacy-handoff.config.ts'
import { appProviderProfiles } from '@/server/AppRuntime/contract.ts'
import {
    signalLegacyFeatureOwnership,
    subscribeToLegacyFeatureOwnership,
} from '@/server/LegacyHandoff/ownership-signal.server.ts'
import {
    lockLegacyFeatureDomain,
    shareLegacyFeatureDomain,
} from '@/server/LegacyHandoff/ownership.server.ts'
import { createLegacyFeatureWorkerGate } from '@/server/LegacyHandoff/worker-admission.server.ts'

const enabled = process.env.RENTNERPROXY_DATABASE_INTEGRATION === '1' && getDatabaseUrl() !== null
const integrationTest = enabled ? test : test.skip
const marker = 'monitoring-fence.invalid'
const context = { proof: 'sha256:' + 'a'.repeat(64), revision: 'sha256:' + 'b'.repeat(64) }
const unhealthy = {
    status: 'unhealthy',
    code: 'upstream_timeout',
    durationMs: null,
    httpStatus: null,
} as const
const installationId = randomUUID()
const userIds: string[] = []
const roleIds: string[] = []

async function seedHosts(count: number) {
    const { db } = await import('@/db/index.ts')
    await db.execute(sql`
        insert into ${proxyHosts} (id, forward_scheme, forward_host, forward_port)
        select uuidv7(), 'http', ${marker}, 8080 from generate_series(1, ${count})`)
    await db.execute(sql`
        insert into rentnerproxy.host_domains (proxy_host_id, domain)
        select id, 'fence-' || replace(id::text, '-', '') || '.example.test'
        from ${proxyHosts} where forward_host = ${marker}`)
    const hosts = await db.execute<{ id: string; domain: string }>(sql`
        select h.id, d.domain from ${proxyHosts} h
        join rentnerproxy.host_domains d on d.proxy_host_id = h.id
        where h.forward_host = ${marker} order by h.id`)
    await db.insert(hostCheckPolicies).values(
        hosts.map((host) => ({
            proxyHostId: host.id,
            domain: host.domain,
            enabled: true,
            failureThreshold: 1,
        })),
    )
    // An observation retention would delete, were it not fenced.
    await db.execute(sql`
        insert into rentnerproxy.host_check_observations (policy_id, policy_version, checked_at, status, code)
        select p.id, p.version, statement_timestamp() - interval '40 days', 'healthy', 'expected_status'
        from ${hostCheckPolicies} p join ${proxyHosts} h on h.id = p.proxy_host_id
        where h.forward_host = ${marker}`)
    return hosts
}

/** A digest of every monitoring row of this test's hosts. */
async function snapshot() {
    const { db } = await import('@/db/index.ts')
    const [row] = await db.execute<Record<string, string>>(sql`
        with owned as (
            select p.* from ${hostCheckPolicies} p
            join ${proxyHosts} h on h.id = p.proxy_host_id where h.forward_host = ${marker}
        )
        select
            coalesce((select md5(string_agg(owned::text, ',' order by id)) from owned), '') as policies,
            coalesce((select md5(string_agg(o::text, ',' order by o.id))
                from rentnerproxy.host_check_observations o where o.policy_id in (select id from owned)), '') as observations,
            coalesce((select md5(string_agg(i::text, ',' order by i.id))
                from rentnerproxy.host_check_incidents i where i.policy_id in (select id from owned)), '') as incidents`)
    return row
}

async function claimAll(): Promise<HostMonitoringClaim[]> {
    const claims: HostMonitoringClaim[] = []
    for (;;) {
        // oxlint-disable-next-line no-await-in-loop -- Claims fill one bounded batch at a time.
        const batch = await claimDueHostMonitoringPolicies(HOST_MONITORING_LIMITS.claimBatchSize)
        claims.push(...batch)
        if (batch.length < HOST_MONITORING_LIMITS.claimBatchSize) return claims
    }
}

/** Record what a begin, a commit or an abort leaves in the journal, then signal like they do. */
async function journal(state: 'exported' | 'committed' | null) {
    const { db } = await import('@/db/index.ts')
    await db.delete(legacyFeatureHandoffs).where(eq(legacyFeatureHandoffs.domain, 'monitoring'))
    if (state !== null)
        await db.insert(legacyFeatureHandoffs).values({
            domain: 'monitoring',
            installationId,
            state,
            digest: 'a'.repeat(64),
            partCount: 0,
            ...(state === 'committed' && { committedAt: new Date() }),
        })
    signalLegacyFeatureOwnership(['monitoring'])
}

async function service() {
    const { db } = await import('@/db/index.ts')
    const id = randomUUID()
    userIds.push(id)
    await db.insert(users).values({
        id,
        displayName: 'Monitoring fence fixture',
        email: `${id}@monitoring-fence.invalid`,
        status: 'active',
    })
    const roleId = randomUUID()
    roleIds.push(roleId)
    await db.insert(roles).values({ id: roleId, key: `fence-${roleId}`, name: 'Fence fixture' })
    const selected = await db
        .select({ id: permissions.id })
        .from(permissions)
        .where(
            inArray(permissions.key, [
                PERMISSIONS.PROXY_HOSTS_VIEW,
                PERMISSIONS.PROXY_HOSTS_UPDATE,
            ]),
        )
    await db
        .insert(rolePermissions)
        .values(selected.map((permission) => ({ roleId, permissionId: permission.id })))
    await db.insert(userRoles).values({ userId: id, roleId })
    return createHostMonitoringService({
        database: getAuthDatabase,
        requireActor: async () => ({ id }),
        rateLimit: async () => undefined,
    })
}

async function expiredObservations() {
    const { db } = await import('@/db/index.ts')
    const [row] = await db.execute<{ count: number }>(sql`
        select count(*)::integer as count from rentnerproxy.host_check_observations o
        join ${hostCheckPolicies} p on p.id = o.policy_id
        join ${proxyHosts} h on h.id = p.proxy_host_id
        where h.forward_host = ${marker} and o.checked_at < statement_timestamp() - interval '30 days'`)
    return Number(row?.count ?? 0)
}

function settingsOf(policy: typeof hostCheckPolicies.$inferSelect) {
    const { domain, intervalSeconds, timeoutMs, expectedStatus, failureThreshold } = policy
    const { recoveryThreshold, retentionDays, sampleLimit, incidentLimit } = policy
    return {
        domain,
        enabled: policy.enabled,
        intervalSeconds,
        timeoutMs,
        expectedStatus,
        failureThreshold,
        recoveryThreshold,
        retentionDays,
        sampleLimit,
        incidentLimit,
    }
}

/** A begin's domain lock, held until the test commits or rolls it back, like a begin's export. */
function holdBegin() {
    const held = Promise.withResolvers<void>()
    const decided = Promise.withResolvers<boolean>()
    const done = getAuthDatabase()
        .transaction(async (transaction) => {
            await transaction.execute(sql`select set_config('lock_timeout', '10000ms', true)`)
            await lockLegacyFeatureDomain(transaction, 'monitoring')
            held.resolve()
            if (!(await decided.promise)) throw new Error('begin rolled back')
            await transaction.insert(legacyFeatureHandoffs).values({
                domain: 'monitoring',
                installationId,
                state: 'exported',
                digest: 'a'.repeat(64),
                partCount: 0,
            })
        })
        .catch((error: unknown) => {
            if (!(error instanceof Error && error.message === 'begin rolled back')) throw error
        })
    return {
        held: held.promise,
        done,
        commit: () => decided.resolve(true),
        rollBack: () => decided.resolve(false),
    }
}

/** A platform writer inside the domain, so a begin has to queue behind it. */
function holdWriter() {
    const held = Promise.withResolvers<void>()
    const released = Promise.withResolvers<void>()
    const done = getAuthDatabase().transaction(async (transaction) => {
        await shareLegacyFeatureDomain(transaction, 'monitoring')
        held.resolve()
        await released.promise
    })
    return { held: held.promise, done, release: () => released.resolve() }
}

/** Wait until at least `count` sessions queue for the monitoring domain lock in the mode. */
async function awaitLockWaiter(mode: 'ExclusiveLock' | 'ShareLock', count: number) {
    const { db } = await import('@/db/index.ts')
    const key = appProviderProfiles.indexOf('monitoring')
    for (let attempt = 0; attempt < 200; attempt += 1) {
        // oxlint-disable-next-line no-await-in-loop -- Poll the lock table until the waiters appear.
        const [state] = await db.execute<{ waiting: number }>(sql`
            select count(*)::integer as waiting from pg_locks
            where locktype = 'advisory' and not granted and mode = ${mode}
                and classid = (${LEGACY_HANDOFF_LIMITS.advisoryLockClass})::oid
                and objid = (${key})::oid and objsubid = 2`)
        if (Number(state?.waiting ?? 0) >= count) return
        // oxlint-disable-next-line no-await-in-loop -- See above.
        await Bun.sleep(10)
    }
    throw new Error('No session queued for the monitoring domain lock')
}

async function waitFor(condition: () => boolean, label: string) {
    for (let attempt = 0; attempt < 200; attempt += 1) {
        if (condition()) return
        // oxlint-disable-next-line no-await-in-loop -- Poll until the gate followed the journal.
        await Bun.sleep(10)
    }
    throw new Error('Timed out waiting for ' + label)
}

describe('built-in monitoring writers behind the handoff fence', () => {
    beforeAll(async () => {
        if (!enabled) return
        const { db } = await import('@/db/index.ts')
        const [held] = await db
            .select({ domain: legacyFeatureHandoffs.domain })
            .from(legacyFeatureHandoffs)
            .where(eq(legacyFeatureHandoffs.domain, 'monitoring'))
        if (held) throw new Error('Another monitoring handoff exists; use an isolated database.')
        await db.transaction(ensureAuthorizationRegistryInTransaction)
        await db.insert(appRuntimeInstallations).values({
            id: installationId,
            appId: 'test.monitoring-fence',
            uid: 20_000 + Math.floor(Math.random() * 39_000),
        })
    })

    afterAll(async () => {
        if (!enabled) return
        const { db } = await import('@/db/index.ts')
        await db
            .delete(appRuntimeInstallations)
            .where(eq(appRuntimeInstallations.id, installationId))
    })

    afterEach(async () => {
        if (!enabled) return
        const { db } = await import('@/db/index.ts')
        await db
            .delete(legacyFeatureHandoffs)
            .where(eq(legacyFeatureHandoffs.installationId, installationId))
        await db.delete(proxyHosts).where(eq(proxyHosts.forwardHost, marker))
        if (userIds.length > 0) await db.delete(users).where(inArray(users.id, userIds.splice(0)))
        if (roleIds.length > 0) await db.delete(roles).where(inArray(roles.id, roleIds.splice(0)))
    })

    integrationTest('an open handoff turns every writer away and keeps the reads', async () => {
        const hosts = await seedHosts(4)
        // Three probes run when the handoff begins; the fourth policy is due but unclaimed.
        const inFlight = await claimDueHostMonitoringPolicies(3)
        expect(inFlight).toHaveLength(3)
        const monitoring = await service()
        const before = await snapshot()
        expect(await expiredObservations()).toBe(4)
        await journal('exported')

        expect(await claimAll()).toEqual([])
        expect(
            await completeHostMonitoringClaim(inFlight[0]!, unhealthy, async () => true, context),
        ).toBe(false)
        expect(
            await completeHostMonitoringClaims([
                {
                    claim: inFlight[1]!,
                    outcome: unhealthy,
                    // The fence turns the batch away before it reads the probe context.
                    before: { availability: context } as never,
                    signal: new AbortController().signal,
                },
            ]),
        ).toEqual([{ status: 'fulfilled', value: false }])
        expect(await releaseHostMonitoringClaims(inFlight.slice(2))).toEqual([false])
        await pruneHostMonitoringHistory()
        expect(await expiredObservations()).toBe(4)
        await getAuthDatabase().transaction((transaction) =>
            invalidateHostMonitoringForHostsInTransaction(transaction, [hosts[0]!.id]),
        )
        const policy = await monitoring.getPolicy({ proxyHostId: hosts[0]!.id })
        expect(policy).toMatchObject({ proxyHostId: hosts[0]!.id })
        await expect(
            monitoring.savePolicy({
                proxyHostId: hosts[0]!.id,
                expectedVersion: policy!.version,
                settings: { ...policy!.settings, enabled: false },
            }),
        ).rejects.toEqual(new HostMonitoringError('handed_off'))
        expect(await snapshot()).toEqual(before)

        // Once an app committed, the routes report the handoff instead of retired data.
        await journal('committed')
        for (const read of [
            () => monitoring.getSummary({ proxyHostIds: [hosts[0]!.id] }),
            () => monitoring.getPolicy({ proxyHostId: hosts[0]!.id }),
            () => monitoring.getHistory({ proxyHostId: hosts[0]!.id }),
        ])
            // oxlint-disable-next-line no-await-in-loop -- Each read reports the handoff.
            await expect(read()).rejects.toEqual(new HostMonitoringError('handed_off'))
        expect(await snapshot()).toEqual(before)

        // Without a handoff the same writers work again on the untouched state.
        await journal(null)
        const resumed = await claimAll()
        expect(resumed).toHaveLength(1)
        expect(inFlight.map(({ policy: claimed }) => claimed.id)).not.toContain(
            resumed[0]!.policy.id,
        )
        expect(await releaseHostMonitoringClaims([...inFlight, ...resumed])).toEqual([
            true,
            true,
            true,
            true,
        ])
        await pruneHostMonitoringHistory()
        expect(await expiredObservations()).toBe(0)
    })

    integrationTest(
        'resets and saves wait for a running begin and apply when it rolls back',
        async () => {
            const { db } = await import('@/db/index.ts')
            const [host, other] = await seedHosts(2)
            const monitoring = await service()
            const policyOf = async (proxyHostId: string) =>
                (
                    await db
                        .select()
                        .from(hostCheckPolicies)
                        .where(eq(hostCheckPolicies.proxyHostId, proxyHostId))
                )[0]!
            const [incident] = await db.execute<{ id: string }>(sql`
                insert into rentnerproxy.host_check_incidents
                    (policy_id, started_at, detected_at, failure_code)
                select id, statement_timestamp(), statement_timestamp(), 'upstream_timeout'
                from ${hostCheckPolicies} where proxy_host_id = ${host!.id}
                returning id::text`)
            const closedReason = async () =>
                (
                    await db
                        .select({ closedReason: hostCheckIncidents.closedReason })
                        .from(hostCheckIncidents)
                        .where(eq(hostCheckIncidents.id, incident!.id))
                )[0]!.closedReason
            const original = await policyOf(host!.id)
            const otherOriginal = await policyOf(other!.id)

            // A begin that holds the domain, and one that only waits behind a running writer.
            for (const queued of [false, true]) {
                const writer = queued ? holdWriter() : undefined
                // oxlint-disable-next-line no-await-in-loop -- Each begin runs alone.
                if (writer) await writer.held
                const begin = holdBegin()
                // oxlint-disable-next-line no-await-in-loop -- See above.
                if (queued) await awaitLockWaiter('ExclusiveLock', 1)
                // oxlint-disable-next-line no-await-in-loop -- See above.
                else await begin.held
                const reset = getAuthDatabase().transaction((transaction) =>
                    invalidateHostMonitoringForHostsInTransaction(
                        transaction,
                        [host!.id],
                        'monitoring_disabled',
                    ),
                )
                const policy = queued ? otherOriginal : original
                const save = monitoring.savePolicy({
                    proxyHostId: queued ? other!.id : host!.id,
                    expectedVersion: queued ? policy.version : null,
                    settings: { ...settingsOf(policy), intervalSeconds: 120 },
                })
                // A refused save must not settle while the begin is undecided.
                save.catch(() => undefined)
                // oxlint-disable-next-line no-await-in-loop -- Both writers queue for the domain.
                await awaitLockWaiter('ShareLock', 2)
                writer?.release()
                begin.rollBack()
                // oxlint-disable-next-line no-await-in-loop -- See above.
                await begin.done
                // oxlint-disable-next-line no-await-in-loop -- The writers then apply.
                await reset
                if (queued) {
                    // oxlint-disable-next-line no-await-in-loop -- See above.
                    expect(await save).toMatchObject({
                        settings: { intervalSeconds: 120 },
                    })
                } else {
                    // The first save named a stale version: it reached the policy, not the fence.
                    // oxlint-disable-next-line no-await-in-loop -- See above.
                    await expect(save).rejects.toEqual(new HostMonitoringError('conflict'))
                }
            }
            expect((await policyOf(host!.id)).version).not.toBe(original.version)
            expect(await closedReason()).toBe('monitoring_disabled')
            expect((await policyOf(other!.id)).intervalSeconds).toBe(120)

            // A begin that commits fences the writers that waited for it.
            const before = await snapshot()
            const begin = holdBegin()
            await begin.held
            const reset = getAuthDatabase().transaction((transaction) =>
                invalidateHostMonitoringForHostsInTransaction(transaction, [other!.id]),
            )
            const current = await policyOf(other!.id)
            const save = monitoring.savePolicy({
                proxyHostId: other!.id,
                expectedVersion: current.version,
                settings: { ...settingsOf(current), intervalSeconds: 300 },
            })
            save.catch(() => undefined)
            await awaitLockWaiter('ShareLock', 2)
            begin.commit()
            await begin.done
            await reset
            await expect(save).rejects.toEqual(new HostMonitoringError('handed_off'))
            expect(await snapshot()).toEqual(before)
        },
        30_000,
    )

    integrationTest('the gate stops and resumes its worker as the journal changes', async () => {
        const worker = { running: false, starts: 0 }
        let listening = 0
        const gate = createLegacyFeatureWorkerGate(
            'monitoring',
            {
                start: () => {
                    worker.running = true
                    worker.starts += 1
                },
                stop: async () => {
                    worker.running = false
                },
            },
            {
                subscribe: (domain, listener) => {
                    listening += 1
                    const stop = subscribeToLegacyFeatureOwnership(domain, listener)
                    return () => {
                        listening -= 1
                        stop()
                    }
                },
            },
        )
        await gate.start()
        try {
            expect(worker).toEqual({ running: true, starts: 1 })
            await journal('exported')
            await waitFor(() => !worker.running, 'the handoff to stop the worker')
            await journal(null)
            await waitFor(() => worker.running, 'the abort to resume the worker')
            await journal('exported')
            await waitFor(() => !worker.running, 'the second handoff to stop the worker')
            await journal('committed')
            // The gate stops listening once it read the commit, which is final.
            await waitFor(() => listening === 0, 'the commit to end the gate')
            await journal(null)
            await Bun.sleep(50)
            expect(worker).toEqual({ running: false, starts: 2 })
        } finally {
            await gate.stop()
        }
    })
})
