import { randomUUID } from 'node:crypto'
import { afterEach, beforeAll, beforeEach, describe, expect, test } from 'bun:test'
import { eq, inArray, sql } from 'drizzle-orm'
import { HOST_MONITORING_HANDOFF, HOST_MONITORING_LIMITS } from '@/config/host-monitoring.config.ts'
import { LEGACY_HANDOFF_LIMITS } from '@/config/legacy-handoff.config.ts'
import {
    HOST_AVAILABILITY_HANDOVER_MS,
    NOTIFICATION_SETTINGS_KEY,
    NOTIFICATION_STATE_KEY,
} from '@/config/notifications.config.ts'
import { PERMISSIONS } from '@/config/permissions.config.ts'
import {
    hostCheckPolicies,
    legacyFeatureHandoffParts,
    legacyFeatureHandoffs,
    permissions,
    proxyHosts,
    rolePermissions,
    roles,
    systemSettings,
    userRoles,
    users,
} from '@/db/schema.ts'
import { evaluateUpgradePreview } from '@/lib/ApplicationVersion/upgradePreview.ts'
import type { HostMonitoringOutcome } from '@/lib/HostMonitoring/Types/host-monitoring.types.ts'
import { APP_RUNTIME_SUPPORT_CAPABILITIES } from '@/server/AppRuntime/authority-policy.server.ts'
import { appRpcLimits } from '@/server/AppRuntime/contract.ts'
import { createAppRuntimeGateway } from '@/server/AppRuntime/gateway.server.ts'
import { manageAppRuntime } from '@/server/AppRuntime/management.server.ts'
import { executeAppRuntimeCall } from '@/server/AppRuntime/services.server.ts'
import { ensureAuthorizationRegistryInTransaction } from '@/server/Auth/Access/registry.service.ts'
import { getAuthDatabase } from '@/server/Auth/Core/database.server.ts'
import type { AuthTransaction } from '@/server/Auth/Core/Types/database.types.ts'
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
import { inspectLegacyFeaturesInTransaction } from '@/server/LegacyHandoff/journal.server.ts'
import { legacyFeatureHandoffSources } from '@/server/LegacyHandoff/sources.server.ts'
import { createLegacyFeatureWorkerGate } from '@/server/LegacyHandoff/worker-admission.server.ts'
import {
    acknowledgeNotificationDelivery,
    claimNextNotificationDelivery,
} from '@/server/Notifications/notification-repository.ts'
import {
    lockNotificationConfiguration,
    lockNotificationRuntime,
    readNotificationRuntime,
    writeNotificationConfiguration,
    writeNotificationRuntime,
} from '@/server/Notifications/notification-storage.ts'
import type { StoredNotificationChannel } from '@/server/Notifications/Types/notification-internal.types.ts'
import { removeEventApps } from '@/tests/Helpers/appHostEvents.ts'

const enabled = process.env.RENTNERPROXY_DATABASE_INTEGRATION === '1' && getDatabaseUrl() !== null
const integrationTest = enabled ? test : test.skip
const token = 'monitoring-handoff-bridge'
const appId = 'test.monitoring'
const marker = 'monitoring-handoff.invalid'
const notificationKeys = [NOTIFICATION_SETTINGS_KEY, NOTIFICATION_STATE_KEY]
const incidentGrant = { id: 'notifications.incidents.manage.v1', scope: 'installation' }
const readHosts = { id: 'proxy.hosts.read.v1', scope: 'proxyHosts' }
const categories = [{ id: 'availability', name: 'Host availability', resource: 'proxyHost' }]
const channelId = '00000000-0000-4000-8000-000000000b01'
const fixtureContext = { proof: 'sha256:' + 'a'.repeat(64), revision: 'sha256:' + 'b'.repeat(64) }
const unhealthy: HostMonitoringOutcome = {
    status: 'unhealthy',
    code: 'upstream_timeout',
    durationMs: null,
    httpStatus: null,
}
const encryptionKey = process.env.APP_ENCRYPTION_KEY
const installed: { appId: string; installationId: string; generation: number; uid: number }[] = []
const userIds: string[] = []
const roleIds: string[] = []
let nextUid = 41_300

interface Reply {
    readonly status: number
    readonly body: unknown
}

interface Exported {
    readonly digest: string
    readonly partCount: number
}

type Row = (string | number | boolean | null)[]

const grant = (capability: { id: string; scope: string }, resourceId: string) => ({
    capability,
    resourceId,
    allowService: true,
})
const route = (suffix = '') => '/platform/v1/legacy-handoffs/monitoring' + suffix

/** Register and activate the monitoring app like the broker does, through the public gateway. */
async function install() {
    const identity = { appId, installationId: randomUUID(), generation: 1, uid: nextUid++ }
    installed.push(identity)
    const gateway = createAppRuntimeGateway(
        token,
        new AbortController().signal,
        executeAppRuntimeCall,
        manageAppRuntime,
    )
    const send = async (
        path: string,
        body?: unknown,
        headers: Record<string, string> = {},
        method = body === undefined ? 'GET' : 'POST',
    ): Promise<Reply> => {
        const response = await gateway(
            new Request('http://app-api' + path, {
                method,
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
        const text = await response.text()
        return { status: response.status, body: text ? (JSON.parse(text) as unknown) : null }
    }
    const control = (action: string, fields: Record<string, unknown> = {}) =>
        send('/internal/v1/app-generations/' + action, { identity, ...fields })
    const leaseExpiresAt = new Date(Date.now() + 120_000).toISOString()
    expect(
        (
            await control('register', {
                leaseExpiresAt,
                capabilities: [incidentGrant, readHosts],
                providerProfiles: ['monitoring'],
                incidentCategories: categories,
            })
        ).status,
    ).toBe(204)
    expect(
        (
            await control('grants', {
                grants: [
                    grant(APP_RUNTIME_SUPPORT_CAPABILITIES.events, identity.installationId),
                    grant(APP_RUNTIME_SUPPORT_CAPABILITIES.provider, 'monitoring'),
                    grant(incidentGrant, identity.installationId),
                    grant({ id: readHosts.id, scope: 'allProxyHosts' }, 'all'),
                ],
            })
        ).status,
    ).toBe(204)
    expect((await control('activate', { leaseExpiresAt })).status).toBe(204)
    return {
        identity,
        control,
        begin: (key = 'begin-1') =>
            send(route('/begin'), undefined, { 'Idempotency-Key': key }, 'POST'),
        part: (digest: string, sequence: number) => send(route('/parts'), { digest, sequence }),
        commit: (digest: string, key = 'commit-1') =>
            send(route('/commit'), { digest }, { 'Idempotency-Key': key }),
        incident: (key: string, body: unknown, idempotencyKey: string) =>
            send('/platform/v1/incidents/' + key, body, { 'Idempotency-Key': idempotencyKey }),
    }
}

type MonitoringApp = Awaited<ReturnType<typeof install>>

function exported(reply: Reply): Exported {
    expect(reply.status).toBe(200)
    expect(reply.body).toMatchObject({ domain: 'monitoring', state: 'exported' })
    return reply.body as Exported
}

async function readParts(app: MonitoringApp, { digest, partCount }: Exported, from = 0) {
    const parts: unknown[] = []
    for (let sequence = from; sequence < partCount; sequence += 1) {
        // oxlint-disable-next-line no-await-in-loop -- An importer reads the parts in order.
        const reply = await app.part(digest, sequence)
        expect(reply.status).toBe(200)
        const body = reply.body as { sequence: number; part: unknown }
        expect(body.sequence).toBe(sequence)
        expect(Buffer.byteLength(JSON.stringify(body.part))).toBeLessThanOrEqual(
            LEGACY_HANDOFF_LIMITS.partBytes,
        )
        parts.push(body.part)
    }
    return parts
}

/** Reassemble an export the way an importer does: manifest, rows by kind, end. */
function decode(parts: readonly unknown[]) {
    const [manifest, ...rest] = parts as { kind: string }[]
    expect(manifest as unknown).toEqual({
        format: HOST_MONITORING_HANDOFF.format,
        version: HOST_MONITORING_HANDOFF.version,
        kind: 'manifest',
        columns: HOST_MONITORING_HANDOFF.columns,
    })
    const end = rest.pop() as { kind: string; counts: Record<string, number> }
    expect(end.kind).toBe('end')
    const rows: Record<string, Row[]> = { policies: [], observations: [], incidents: [] }
    let previous = -1
    for (const part of rest as { kind: keyof typeof rows; rows: Row[] }[]) {
        const order = Object.keys(rows).indexOf(part.kind)
        // Kinds never interleave and no part is empty.
        expect(order).toBeGreaterThanOrEqual(previous)
        expect(part.rows.length).toBeGreaterThan(0)
        previous = order
        rows[part.kind]!.push(...part.rows)
    }
    for (const kind of Object.keys(rows)) expect(rows[kind]).toHaveLength(end.counts[kind]!)
    return { rows: rows as Record<'policies' | 'observations' | 'incidents', Row[]>, end }
}

async function seedHosts(count: number, policy: Record<string, unknown> = {}) {
    const { db } = await import('@/db/index.ts')
    await db.execute(sql`
        insert into ${proxyHosts} (id, forward_scheme, forward_host, forward_port)
        select uuidv7(), 'http', ${marker}, 8080 from generate_series(1, ${count})`)
    await db.execute(sql`
        insert into rentnerproxy.host_domains (proxy_host_id, domain)
        select id, 'handoff-' || replace(id::text, '-', '') || '.example.test'
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
            ...policy,
        })),
    )
    return hosts
}

/** The retained maximum: 1,000 policies, 100,000 observations and 10,000 incidents. */
async function seedMaximumHistory() {
    const { db } = await import('@/db/index.ts')
    await seedHosts(HOST_MONITORING_LIMITS.maxPolicies)
    const policies = sql`select p.id, p.version from ${hostCheckPolicies} p
        join ${proxyHosts} h on h.id = p.proxy_host_id where h.forward_host = ${marker}`
    const perPolicy = HOST_MONITORING_LIMITS.maxObservations / HOST_MONITORING_LIMITS.maxPolicies
    await db.execute(sql`
        insert into rentnerproxy.host_check_observations
            (policy_id, policy_version, checked_at, status, code, duration_ms, http_status)
        select p.id, p.version,
            statement_timestamp() - n * interval '1 minute' - (n % 7) * interval '1 microsecond',
            case when n % 10 = 0 then 'unhealthy' else 'healthy' end,
            case when n % 10 = 0 then 'upstream_timeout' else 'expected_status' end,
            case when n % 10 = 0 then null else 20 + n % 50 end,
            case when n % 10 = 0 then null else 200 end
        from (${policies}) p cross join generate_series(1, ${perPolicy}) n`)
    const closed = HOST_MONITORING_LIMITS.maxIncidents / HOST_MONITORING_LIMITS.maxPolicies - 1
    await db.execute(sql`
        insert into rentnerproxy.host_check_incidents
            (policy_id, started_at, detected_at, recovery_started_at, recovered_at,
             failure_code, recovery_code, closed_reason, closed_at)
        select p.id, t - interval '3 minutes', t - interval '2 minutes', t - interval '1 minute', t,
            'upstream_timeout', 'expected_status', 'recovered', t
        from (${policies}) p cross join generate_series(1, ${closed}) n
        cross join lateral (select statement_timestamp() - n * interval '1 hour' as t) times`)
    await db.execute(sql`
        insert into rentnerproxy.host_check_incidents (policy_id, started_at, detected_at, failure_code)
        select p.id, statement_timestamp() - interval '5 minutes',
            statement_timestamp() - interval '4 minutes', 'upstream_unreachable'
        from (${policies}) p`)
}

/** A digest of every monitoring row of this test's hosts, to prove nothing was written. */
async function monitoringSnapshot() {
    const { db } = await import('@/db/index.ts')
    const [row] = await db.execute<{
        policies: string
        observations: string
        incidents: string
    }>(sql`
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

async function configureNotifications(channels: readonly StoredNotificationChannel[]) {
    const { db } = await import('@/db/index.ts')
    await db.transaction(async (transaction) => {
        await lockNotificationConfiguration(transaction)
        await writeNotificationConfiguration(transaction, {
            version: 1,
            revision: 1,
            enabled: true,
            pausedAfterRestore: false,
            channels,
        })
        await writeNotificationRuntime(transaction, await lockNotificationRuntime(transaction))
    })
}

async function notificationEngine() {
    const { db } = await import('@/db/index.ts')
    return (await db.transaction(readNotificationRuntime, { accessMode: 'read only' })).engine
}

/** Claim and acknowledge every due delivery; returns what each one announced. */
async function deliver() {
    const delivered = []
    for (;;) {
        // oxlint-disable-next-line no-await-in-loop -- Deliveries are claimed one at a time.
        const claim = await claimNextNotificationDelivery()
        if (!claim) return delivered
        delivered.push(claim.payload)
        // oxlint-disable-next-line no-await-in-loop -- Each acknowledgement precedes the next claim.
        await acknowledgeNotificationDelivery(claim.leaseToken, { success: true })
    }
}

async function createUser() {
    const { db } = await import('@/db/index.ts')
    const id = randomUUID()
    userIds.push(id)
    await db.insert(users).values({
        id,
        displayName: 'Monitoring handoff fixture',
        email: `${id}@monitoring-handoff.invalid`,
        status: 'active',
    })
    const roleId = randomUUID()
    roleIds.push(roleId)
    await db.insert(roles).values({ id: roleId, key: `handoff-${roleId}`, name: 'Handoff fixture' })
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
    return id
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

async function waitFor(condition: () => boolean, label: string) {
    for (let attempt = 0; attempt < 200; attempt += 1) {
        if (condition()) return
        // oxlint-disable-next-line no-await-in-loop -- Poll until the gate followed the journal.
        await Bun.sleep(10)
    }
    throw new Error('Timed out waiting for ' + label)
}

describe('monitoring legacy handoff', () => {
    beforeAll(async () => {
        if (!enabled) return
        const { db } = await import('@/db/index.ts')
        const [held] = await db
            .select({ domain: legacyFeatureHandoffs.domain })
            .from(legacyFeatureHandoffs)
            .where(eq(legacyFeatureHandoffs.domain, 'monitoring'))
        if (held) throw new Error('Another monitoring handoff exists; use an isolated database.')
        await db.transaction(ensureAuthorizationRegistryInTransaction)
    })

    beforeEach(async () => {
        if (!enabled) return
        const { db } = await import('@/db/index.ts')
        // Parts and event cursors are sealed with the app encryption key.
        process.env.APP_ENCRYPTION_KEY = Buffer.alloc(32, 95).toString('base64')
        await db.delete(systemSettings).where(inArray(systemSettings.key, notificationKeys))
    })

    afterEach(async () => {
        if (!enabled) return
        const { db } = await import('@/db/index.ts')
        const ids = installed.splice(0)
        await db.transaction(async (transaction) => {
            await transaction
                .delete(legacyFeatureHandoffParts)
                .where(eq(legacyFeatureHandoffParts.domain, 'monitoring'))
            if (ids.length > 0)
                await transaction.delete(legacyFeatureHandoffs).where(
                    inArray(
                        legacyFeatureHandoffs.installationId,
                        ids.map(({ installationId }) => installationId),
                    ),
                )
        })
        await removeEventApps(ids)
        await db.delete(proxyHosts).where(eq(proxyHosts.forwardHost, marker))
        if (userIds.length > 0) await db.delete(users).where(inArray(users.id, userIds.splice(0)))
        if (roleIds.length > 0) await db.delete(roles).where(inArray(roles.id, roleIds.splice(0)))
        await db.delete(systemSettings).where(inArray(systemSettings.key, notificationKeys))
        if (encryptionKey === undefined) delete process.env.APP_ENCRYPTION_KEY
        else process.env.APP_ENCRYPTION_KEY = encryptionKey
    })

    integrationTest(
        'one App API begin exports the maximum history completely, deterministically and resumably',
        async () => {
            const { db } = await import('@/db/index.ts')
            await seedMaximumHistory()
            const app = await install()

            const started = performance.now()
            const first = exported(await app.begin())
            const elapsed = performance.now() - started
            console.info('[monitoring-handoff] maximum history begin', {
                elapsedMs: Math.round(elapsed),
                partCount: first.partCount,
            })
            // The whole export ran inside the App API transaction and its budget.
            expect(elapsed).toBeLessThan(appRpcLimits.requestMs)
            expect(first.partCount).toBeLessThanOrEqual(LEGACY_HANDOFF_LIMITS.maximumParts)

            // An interrupted import begins again with the same key and resumes at its next part.
            const half = Math.floor(first.partCount / 2)
            const head = await readParts(app, { ...first, partCount: half })
            expect(exported(await app.begin())).toEqual(first)
            const parts = [...head, ...(await readParts(app, first, half))]
            const { rows, end } = decode(parts)

            // Complete and ordered: every retained row of every policy, in the documented order.
            const ids = async (query: ReturnType<typeof sql>) =>
                (await db.execute<{ id: string }>(query)).map(({ id }) => id)
            expect(rows.policies.map((row) => row[0])).toEqual(
                await ids(sql`select id::text as id from ${hostCheckPolicies} order by id`),
            )
            expect(rows.observations.map((row) => row[0])).toEqual(
                await ids(sql`select id::text as id from rentnerproxy.host_check_observations
                    order by policy_id, checked_at, id`),
            )
            expect(rows.incidents.map((row) => row[0])).toEqual(
                await ids(sql`select id::text as id from rentnerproxy.host_check_incidents
                    order by policy_id, started_at, id`),
            )
            expect(end.counts.observations).toBeGreaterThanOrEqual(
                HOST_MONITORING_LIMITS.maxObservations,
            )
            expect(end.counts.incidents).toBeGreaterThanOrEqual(HOST_MONITORING_LIMITS.maxIncidents)
            const { columns } = HOST_MONITORING_HANDOFF
            for (const kind of ['policies', 'observations', 'incidents'] as const)
                for (const row of rows[kind]) expect(row).toHaveLength(columns[kind].length)

            // Rows keep their values at full precision.
            const [observation] = await db.execute<Record<string, unknown>>(sql`
                select id::text, policy_id::text, policy_version::text,
                    to_char(checked_at at time zone 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"') as checked_at,
                    status, code, duration_ms, http_status
                from rentnerproxy.host_check_observations where id = ${rows.observations[7]![0]}::uuid`)
            expect(rows.observations[7]).toEqual(Object.values(observation!) as Row)
            const open = rows.incidents.filter(
                (row) => row[columns.incidents.indexOf('closedReason')] === null,
            )
            expect(open.length).toBeGreaterThanOrEqual(HOST_MONITORING_LIMITS.maxPolicies)

            // Aborting returns the domain; the same retained state exports to the same digest.
            expect((await app.control('removable')).status).toBe(204)
            expect(exported(await app.begin('begin-2'))).toEqual(first)
            expect(await readParts(app, first)).toEqual(parts)
        },
        180_000,
    )

    integrationTest(
        'after begin no built-in policy, observation or incident is written',
        async () => {
            const { db } = await import('@/db/index.ts')
            const hosts = await seedHosts(3, { failureThreshold: 1 })
            await db.execute(sql`
                insert into rentnerproxy.host_check_observations
                    (policy_id, policy_version, checked_at, status, code)
                select p.id, p.version, statement_timestamp() - interval '40 days',
                    'healthy', 'expected_status'
                from ${hostCheckPolicies} p join ${proxyHosts} h on h.id = p.proxy_host_id
                where h.forward_host = ${marker}`)
            // A probe that was claimed before the handoff began.
            const inFlight = await claimAll()
            expect(inFlight.length).toBe(3)
            const app = await install()
            const before = await monitoringSnapshot()
            const export1 = exported(await app.begin())

            expect(await claimAll()).toEqual([])
            expect(
                await completeHostMonitoringClaim(
                    inFlight[0]!,
                    unhealthy,
                    async () => true,
                    fixtureContext,
                ),
            ).toBe(false)
            expect(
                await completeHostMonitoringClaims(
                    inFlight.slice(1, 2).map((claim) => ({
                        claim,
                        outcome: unhealthy,
                        // The fence turns the batch away before it reads the probe context.
                        before: { availability: fixtureContext } as never,
                        signal: new AbortController().signal,
                    })),
                ),
            ).toEqual([{ status: 'fulfilled', value: false }])
            expect(await releaseHostMonitoringClaims(inFlight.slice(2))).toEqual([false])
            await pruneHostMonitoringHistory()
            await getAuthDatabase().transaction((transaction) =>
                invalidateHostMonitoringForHostsInTransaction(transaction, [hosts[0]!.id]),
            )
            const actorId = await createUser()
            const service = createHostMonitoringService({
                database: getAuthDatabase,
                requireActor: async () => ({ id: actorId }),
                rateLimit: async () => undefined,
            })
            const [policy] = await db
                .select()
                .from(hostCheckPolicies)
                .where(eq(hostCheckPolicies.proxyHostId, hosts[0]!.id))
            await expect(
                service.savePolicy({
                    proxyHostId: hosts[0]!.id,
                    expectedVersion: policy!.version,
                    settings: {
                        domain: hosts[0]!.domain,
                        enabled: false,
                        intervalSeconds: 60,
                        timeoutMs: 3_000,
                        expectedStatus: 200,
                        failureThreshold: 1,
                        recoveryThreshold: 2,
                        retentionDays: 7,
                        sampleLimit: 1_440,
                        incidentLimit: 100,
                    },
                }),
            ).rejects.toEqual(new HostMonitoringError('handed_off'))
            // Reads still serve the fenced state until an app commits.
            expect(await service.getPolicy({ proxyHostId: hosts[0]!.id })).toMatchObject({
                id: policy!.id,
            })

            expect(await monitoringSnapshot()).toEqual(before)
            expect(exported(await app.begin())).toEqual(export1)
        },
        30_000,
    )

    integrationTest(
        'begin stops the running worker, abort resumes it with intact data and commit keeps it stopped',
        async () => {
            const hosts = await seedHosts(2)
            const worker = { running: false, starts: 0, stops: 0 }
            const gate = createLegacyFeatureWorkerGate('monitoring', {
                start: () => {
                    worker.running = true
                    worker.starts += 1
                },
                stop: async () => {
                    worker.running = false
                    worker.stops += 1
                },
            })
            await gate.start()
            try {
                expect(worker).toMatchObject({ running: true, starts: 1 })
                const app = await install()
                const before = await monitoringSnapshot()

                // The begin's committed journal row reaches the gate without a restart.
                const export1 = exported(await app.begin())
                await waitFor(() => !worker.running, 'the begin to stop the worker')

                // Uninstalling before commit aborts: the worker resumes on the untouched data.
                expect((await app.control('removable')).status).toBe(204)
                await waitFor(() => worker.running, 'the abort to resume the worker')
                expect(worker.starts).toBe(2)
                expect(await monitoringSnapshot()).toEqual(before)
                const resumed = await claimAll()
                expect(resumed.map(({ policy }) => policy.proxyHostId).toSorted()).toEqual(
                    hosts.map(({ id }) => id).toSorted(),
                )
                expect(await releaseHostMonitoringClaims(resumed)).toEqual([true, true])

                const export2 = exported(await app.begin('begin-2'))
                expect(export2.partCount).toBe(export1.partCount)
                await waitFor(() => !worker.running, 'the second begin to stop the worker')
                expect(
                    decode(await readParts(app, export2)).end.counts.policies,
                ).toBeGreaterThanOrEqual(hosts.length)
                expect((await app.commit(export2.digest)).body).toEqual({
                    domain: 'monitoring',
                    state: 'committed',
                    digest: export2.digest,
                })
                // A committed handoff is final: the gate never starts the worker again.
                await Bun.sleep(100)
                expect(worker).toMatchObject({ running: false, starts: 2 })
                expect(await claimAll()).toEqual([])

                // The routes report the handed-off state; the upgrade preview reports the app.
                const actorId = await createUser()
                const service = createHostMonitoringService({
                    database: getAuthDatabase,
                    requireActor: async () => ({ id: actorId }),
                    rateLimit: async () => undefined,
                })
                await expect(service.getSummary({ proxyHostIds: [hosts[0]!.id] })).rejects.toEqual(
                    new HostMonitoringError('handed_off'),
                )
                const features = await getAuthDatabase().transaction(
                    (transaction: AuthTransaction) =>
                        inspectLegacyFeaturesInTransaction(
                            transaction,
                            legacyFeatureHandoffSources,
                        ),
                    { accessMode: 'read only' },
                )
                const monitoring = features.find(({ domain }) => domain === 'monitoring')
                expect(monitoring).toEqual({
                    domain: 'monitoring',
                    ownership: {
                        owner: 'app',
                        installationId: app.identity.installationId,
                        digest: export2.digest,
                    },
                })
                const preview = evaluateUpgradePreview(
                    [{ domain: 'monitoring', status: 'retired', apps: [appId] }],
                    features,
                    [
                        {
                            installationId: app.identity.installationId,
                            appId,
                            version: '1.0.0',
                            state: 'running',
                            providers: ['monitoring'],
                            target: 'compatible',
                        },
                    ],
                )
                expect(preview.features).toEqual([
                    expect.objectContaining({ domain: 'monitoring', owner: 'app' }),
                ])
                expect(preview.issues).toEqual([])
            } finally {
                await gate.stop()
            }
        },
        30_000,
    )

    integrationTest(
        'an open outage continues in the app without a second outage notice',
        async () => {
            const { db } = await import('@/db/index.ts')
            const [host, abandoned] = await seedHosts(2, {
                failureThreshold: 1,
                recoveryThreshold: 1,
            })
            await configureNotifications([
                {
                    id: channelId,
                    name: 'Monitoring handoff fixture',
                    kind: 'webhook',
                    revision: 1,
                    enabled: true,
                    events: ['host_availability', 'app_incident'],
                    minimumSeverity: 'warning',
                    thresholdSeconds: 0,
                    recovery: true,
                    appCategories: [`${appId}/availability`],
                    destination: { ciphertext: 'a'.repeat(32), iv: 'b'.repeat(16) },
                    hasAuthorization: false,
                },
            ])
            for (const claim of await claimAll()) {
                // oxlint-disable-next-line no-await-in-loop -- Each outage is recorded on its own.
                const recorded = await completeHostMonitoringClaim(
                    claim,
                    unhealthy,
                    async () => true,
                    fixtureContext,
                )
                expect(recorded).toBe(true)
            }
            const outages = await deliver()
            expect(outages).toEqual([
                expect.objectContaining({ category: 'host_availability', type: 'incident' }),
                expect.objectContaining({ category: 'host_availability', type: 'incident' }),
            ])
            const incidentId = outages.find(({ resourceId }) => resourceId === host!.id)!.incidentId

            const app = await install()
            const export1 = exported(await app.begin())
            const { rows } = decode(await readParts(app, export1))
            const { columns } = HOST_MONITORING_HANDOFF
            // Both outages are exported open, under the IDs their notices carried.
            expect(
                rows.incidents
                    .filter((row) => row[columns.incidents.indexOf('closedReason')] === null)
                    .map((row) => row[columns.incidents.indexOf('id')])
                    .toSorted(),
            ).toEqual(outages.map((outage) => outage.incidentId).toSorted())
            expect((await app.commit(export1.digest)).status).toBe(200)

            // Built-in monitoring records nothing more, so it announces nothing more.
            const [next] = await db
                .select()
                .from(hostCheckPolicies)
                .where(eq(hostCheckPolicies.proxyHostId, host!.id))
            expect(next!.leaseToken).toBeNull()
            expect(await claimAll()).toEqual([])

            // The app continues the exported open incident by its ID: no second outage notice.
            const opened = await app.incident(
                incidentId,
                {
                    status: 'open',
                    category: 'availability',
                    severity: 'error',
                    title: 'Host unavailable',
                    message: 'The upstream did not answer.',
                    resourceId: host!.id,
                },
                'continue-1',
            )
            expect(opened.status).toBe(204)
            expect(await deliver()).toEqual([])
            const engine = await notificationEngine()
            expect(
                engine.incidents
                    .filter((incident) => incident.category === 'host_availability')
                    .map((incident) => incident.resourceId),
            ).toEqual([abandoned!.id])
            const continued = engine.incidents.find((incident) => incident.app?.key === incidentId)
            expect(continued?.channels).toEqual([
                expect.objectContaining({ channelId, failure: 'succeeded', notified: true }),
            ])

            // The app's recovery reaches the channel that got the built-in outage notice, once.
            expect(
                (await app.incident(incidentId, { status: 'resolved' }, 'resolve-1')).status,
            ).toBe(204)
            expect(await deliver()).toEqual([
                expect.objectContaining({ category: 'app_incident', type: 'recovery' }),
            ])
            expect(await deliver()).toEqual([])

            // An outage the app never continued ends silently once the handover window passed.
            await db
                .update(legacyFeatureHandoffs)
                .set({ committedAt: new Date(Date.now() - HOST_AVAILABILITY_HANDOVER_MS - 60_000) })
                .where(eq(legacyFeatureHandoffs.domain, 'monitoring'))
            expect(await deliver()).toEqual([])
            expect(
                (await notificationEngine()).incidents.some(
                    (incident) => incident.category === 'host_availability',
                ),
            ).toBe(false)
        },
        30_000,
    )
})
