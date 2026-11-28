import { randomUUID } from 'node:crypto'
import { afterEach, beforeAll, beforeEach, describe, expect, test } from 'bun:test'
import { eq, inArray, sql } from 'drizzle-orm'
import { HOST_MONITORING_HANDOFF, HOST_MONITORING_LIMITS } from '@/config/host-monitoring.config.ts'
import { LEGACY_HANDOFF_LIMITS } from '@/config/legacy-handoff.config.ts'
import {
    APP_INCIDENT_LIMITS,
    HOST_AVAILABILITY_HANDOVER_MS,
    NOTIFICATION_LIMITS,
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
import { deleteProxyHostInTransaction } from '@/server/Admin/ProxyHostManagement/proxy-hosts.mutations.server.ts'
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
import { subscribeToLegacyFeatureOwnership } from '@/server/LegacyHandoff/ownership-signal.server.ts'
import { createLegacyFeatureWorkerGate } from '@/server/LegacyHandoff/worker-admission.server.ts'
import { appendNotificationIncident } from '@/server/Notifications/incident-engine.ts'
import { resolveEffectiveNotificationConfigurationInTransaction } from '@/server/Notifications/notification-access.ts'
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
import type { StoredNotificationChannel } from '@/server/Notifications/Types/notification-internal.types.ts'
import type { NotificationIncident } from '@/server/Notifications/Types/notification-state.types.ts'
import { removeEventApps } from '@/tests/Helpers/appHostEvents.ts'

const enabled = process.env.RENTNERPROXY_DATABASE_INTEGRATION === '1' && getDatabaseUrl() !== null
const integrationTest = enabled ? test : test.skip
// The maximum-scale handover takes minutes; like the PostgreSQL profile it runs on request.
const scaleTest = enabled && process.env.RENTNERPROXY_HANDOFF_SCALE === '1' ? test : test.skip
const token = 'monitoring-handoff-bridge'
const appId = 'test.monitoring'
const marker = 'monitoring-handoff.invalid'
const notificationKeys = [NOTIFICATION_SETTINGS_KEY, NOTIFICATION_STATE_KEY]
const incidentGrant = { id: 'notifications.incidents.manage.v1', scope: 'installation' }
const readHosts = { id: 'proxy.hosts.read.v1', scope: 'proxyHosts' }
const categories = [
    { id: 'availability', name: 'Host availability', resource: 'proxyHost' },
    { id: 'latency', name: 'Host latency', resource: 'proxyHost' },
    { id: 'service', name: 'Monitoring service', resource: 'none' },
]
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
        /** Keep a long-running app's lease alive, as its broker does. */
        renew: async () =>
            expect(
                (
                    await control('renew', {
                        leaseExpiresAt: new Date(Date.now() + 120_000).toISOString(),
                    })
                ).status,
            ).toBe(204),
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

async function configureNotifications(
    channels: readonly StoredNotificationChannel[],
    revision = 1,
) {
    const { db } = await import('@/db/index.ts')
    await db.transaction(async (transaction) => {
        await lockNotificationConfiguration(transaction)
        await writeNotificationConfiguration(transaction, {
            version: 1,
            revision,
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

const hostOnlyChannel = {
    id: '00000000-0000-4000-8000-000000000c01',
    events: ['host_availability'],
    thresholdSeconds: 0,
} as const
const bothChannel = {
    id: '00000000-0000-4000-8000-000000000c02',
    events: ['host_availability', 'app_incident'],
    thresholdSeconds: 0,
} as const
const appOnlyChannel = {
    id: '00000000-0000-4000-8000-000000000c03',
    events: ['app_incident'],
    thresholdSeconds: 0,
} as const
const slowChannelId = '00000000-0000-4000-8000-000000000c04'

const subscribes = (events: readonly string[], event: 'host_availability' | 'app_incident') =>
    events.includes(event)

function fixtureChannel(channel: {
    readonly id: string
    readonly events: readonly ('host_availability' | 'app_incident')[]
    readonly thresholdSeconds: number
}): StoredNotificationChannel {
    return {
        id: channel.id,
        name: 'Handoff channel ' + channel.id.slice(-2),
        kind: 'webhook',
        revision: 1,
        enabled: true,
        events: [...channel.events],
        minimumSeverity: 'warning',
        thresholdSeconds: channel.thresholdSeconds,
        recovery: true,
        ...(channel.events.includes('app_incident')
            ? { appCategories: [`${appId}/availability`] }
            : {}),
        destination: { ciphertext: 'a'.repeat(32), iv: 'b'.repeat(16) },
        hasAuthorization: false,
    }
}

/** Claim and acknowledge every due delivery; returns channel, category and type of each, sorted. */
async function deliverTo() {
    const delivered: string[][] = []
    for (;;) {
        // oxlint-disable-next-line no-await-in-loop -- Deliveries are claimed one at a time.
        const claim = await claimNextNotificationDelivery()
        if (!claim) return delivered.toSorted()
        delivered.push([claim.channelId, claim.payload.category, claim.payload.type])
        // oxlint-disable-next-line no-await-in-loop -- Each acknowledgement precedes the next claim.
        await acknowledgeNotificationDelivery(claim.leaseToken, { success: true })
    }
}

const outageBody = (resourceId: string, category = 'availability') => ({
    status: 'open',
    category,
    severity: 'error',
    title: 'Host unavailable',
    message: 'The upstream did not answer.',
    resourceId,
})

/** Record an outage for every claimed policy, as built-in monitoring did before the handoff. */
async function recordOutages() {
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
}

/** Begin, import and commit the monitoring handoff for the app. */
async function handOver(app: MonitoringApp) {
    const handoff = exported(await app.begin())
    const { rows } = decode(await readParts(app, handoff))
    expect((await app.commit(handoff.digest)).status).toBe(200)
    return rows
}

/** 1 when the ended incident sent or still owes the channel its recovery notice, else 0. */
function owedRecoveries(incident: NotificationIncident | undefined, channel: string) {
    const item = incident?.channels.find((entry) => entry.channelId === channel)
    return item !== undefined &&
        incident!.recoveredAt !== null &&
        (item.failure === 'succeeded' || item.notified === true) &&
        item.recovery !== 'failed'
        ? 1
        : 0
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
                PERMISSIONS.PROXY_HOSTS_DELETE,
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
        // The hooks replace the global notification settings; never touch a configured database.
        const [settings] = await db
            .select({ key: systemSettings.key })
            .from(systemSettings)
            .where(inArray(systemSettings.key, notificationKeys))
        if (settings) throw new Error('Notification settings exist; use an isolated database.')
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
            const hosts = await seedHosts(4, { failureThreshold: 1 })
            await db.execute(sql`
                insert into rentnerproxy.host_check_observations
                    (policy_id, policy_version, checked_at, status, code)
                select p.id, p.version, statement_timestamp() - interval '40 days',
                    'healthy', 'expected_status'
                from ${hostCheckPolicies} p join ${proxyHosts} h on h.id = p.proxy_host_id
                where h.forward_host = ${marker}`)
            // Probes that were claimed before the handoff began; one due policy stays unclaimed.
            const inFlight = await claimDueHostMonitoringPolicies(3)
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
                        worker.stops += 1
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
                // A committed handoff is final: the gate stops listening and never starts again.
                await waitFor(() => listening === 0, 'the commit to end the gate')
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
            const [host, abandoned, leased] = await seedHosts(3, {
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
            const claims = await claimAll()
            // The third probe is still running when the app commits.
            const live = claims.find(({ policy }) => policy.proxyHostId === leased!.id)!
            for (const claim of claims.filter((candidate) => candidate !== live)) {
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
            const leaseOf = async () =>
                (
                    await db
                        .select({ leaseToken: hostCheckPolicies.leaseToken })
                        .from(hostCheckPolicies)
                        .where(eq(hostCheckPolicies.proxyHostId, leased!.id))
                )[0]!.leaseToken
            expect(await leaseOf()).toBe(live.leaseToken)
            expect((await app.commit(export1.digest)).status).toBe(200)

            // Commit drops the lease of the probe still running, and nothing is claimed again.
            expect(await leaseOf()).toBeNull()
            expect(
                await completeHostMonitoringClaim(
                    live,
                    unhealthy,
                    async () => true,
                    fixtureContext,
                ),
            ).toBe(false)
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
    for (const [scenario, channels] of [
        ['a channel subscribed only to host availability', [hostOnlyChannel]],
        ['a channel subscribed to both', [bothChannel]],
        [
            'mixed channels',
            [
                hostOnlyChannel,
                bothChannel,
                appOnlyChannel,
                { ...hostOnlyChannel, id: slowChannelId, thresholdSeconds: 3_600 },
            ],
        ],
    ] as const)
        for (const drained of [true, false])
            integrationTest(
                `${scenario}: a continued outage resolved at once ends once on every notified channel` +
                    (drained ? '' : ' without a drain before the resolve'),
                async () => {
                    const [host] = await seedHosts(1, { failureThreshold: 1, recoveryThreshold: 1 })
                    await configureNotifications(channels.map(fixtureChannel))
                    const [claim] = await claimAll()
                    expect(
                        await completeHostMonitoringClaim(
                            claim!,
                            unhealthy,
                            async () => true,
                            fixtureContext,
                        ),
                    ).toBe(true)
                    const told = channels
                        .filter(
                            ({ events, thresholdSeconds }) =>
                                subscribes(events, 'host_availability') && thresholdSeconds === 0,
                        )
                        .map(({ id }) => id)
                    const outage = await deliverTo()
                    expect(outage).toEqual(
                        told.map((id) => [id, 'host_availability', 'incident']).toSorted(),
                    )
                    const incidentId = (await notificationEngine()).incidents.find(
                        (incident) => incident.category === 'host_availability',
                    )!.id

                    const app = await install()
                    const handoff = exported(await app.begin())
                    await readParts(app, handoff)
                    expect((await app.commit(handoff.digest)).status).toBe(200)
                    // From commit on the built-in outage reaches no channel it had not reached.
                    const frozen = (await notificationEngine()).incidents.find(
                        (incident) => incident.id === incidentId,
                    )!
                    expect(frozen.frozen).toBe(true)

                    // The app continues the outage and resolves it at once, as after a recovery
                    // during the handoff.
                    expect(
                        (
                            await app.incident(
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
                        ).status,
                    ).toBe(204)
                    const continued = channels
                        .filter(({ events }) => subscribes(events, 'app_incident'))
                        .map(({ id }) => id)
                    const announced = continued
                        .filter((id) => !told.includes(id))
                        .map((id) => [id, 'app_incident', 'incident'])
                    if (drained) expect(await deliverTo()).toEqual(announced.toSorted())
                    expect(
                        (await app.incident(incidentId, { status: 'resolved' }, 'resolve-1'))
                            .status,
                    ).toBe(204)
                    const heard = [...new Set([...told, ...continued])]
                    // Without the drain, the continuation's own outage notice goes out first.
                    expect(await deliverTo()).toEqual(
                        [
                            ...(drained ? [] : announced),
                            ...heard.map((id) => [
                                id,
                                continued.includes(id) ? 'app_incident' : 'host_availability',
                                'recovery',
                            ]),
                        ].toSorted(),
                    )
                    expect(await deliverTo()).toEqual([])
                    expect(
                        (await notificationEngine()).incidents.some(
                            (incident) =>
                                incident.category === 'host_availability' &&
                                incident.recoveredAt === null,
                        ),
                    ).toBe(false)
                },
                30_000,
            )

    integrationTest(
        'more exported open outages than the ordinary incident limit can all be continued',
        async () => {
            const outages = APP_INCIDENT_LIMITS.openPerInstallation + 8
            const hosts = await seedHosts(outages, { failureThreshold: 1 })
            await configureNotifications([fixtureChannel(hostOnlyChannel)])
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
            await deliverTo()
            const engine = await notificationEngine()
            const app = await install()
            const handoff = exported(await app.begin())
            await readParts(app, handoff)
            expect((await app.commit(handoff.digest)).status).toBe(200)
            const open = (key: string, resourceId: string) =>
                app.incident(
                    key,
                    {
                        status: 'open',
                        category: 'availability',
                        severity: 'error',
                        title: 'Host unavailable',
                        message: 'The upstream did not answer.',
                        resourceId,
                    },
                    'open-' + key,
                )
            for (const incident of engine.incidents) {
                if (incident.category !== 'host_availability') continue
                // oxlint-disable-next-line no-await-in-loop -- Continuations are opened in turn.
                expect((await open(incident.id, incident.resourceId)).status).toBe(204)
            }
            // Ordinary incidents keep their own limit next to the continuations.
            for (let index = 0; index < APP_INCIDENT_LIMITS.openPerInstallation; index += 1)
                // oxlint-disable-next-line no-await-in-loop -- See above.
                expect((await open('ordinary-' + index, hosts[index]!.id)).status).toBe(204)
            const refused = await open('ordinary-limit', hosts[0]!.id)
            expect(refused).toMatchObject({ status: 429, body: { code: 'incidentLimit' } })
            expect(
                (await notificationEngine()).incidents.filter(
                    (incident) => incident.app !== undefined && incident.recoveredAt === null,
                ),
            ).toHaveLength(outages + APP_INCIDENT_LIMITS.openPerInstallation)
        },
        60_000,
    )
    for (const outcome of ['succeeds', 'finally fails'] as const)
        integrationTest(
            `a built-in notice in flight across a host change that ${outcome} is heard once`,
            async () => {
                const [host] = await seedHosts(1, { failureThreshold: 1, recoveryThreshold: 1 })
                await configureNotifications([fixtureChannel(bothChannel)])
                await recordOutages()
                // The built-in outage notice is still being sent when the app takes over.
                const sending = await claimNextNotificationDelivery()
                expect(sending?.payload).toMatchObject({
                    category: 'host_availability',
                    type: 'incident',
                })
                const incidentId = sending!.payload.incidentId
                const app = await install()
                await handOver(app)
                expect(
                    (await app.incident(incidentId, outageBody(host!.id), 'continue-1')).status,
                ).toBe(204)
                // A host change keeps the frozen outage and its send, so nothing is announced.
                await getAuthDatabase().transaction((transaction) =>
                    invalidateHostMonitoringForHostsInTransaction(transaction, [host!.id]),
                )
                expect(await deliverTo()).toEqual([])
                await acknowledgeNotificationDelivery(
                    sending!.leaseToken,
                    outcome === 'succeeds'
                        ? { success: true }
                        : { success: false, code: 'destination_blocked', retryable: false },
                )
                // Only a send that never arrived is repeated, now by the continuation.
                expect(await deliverTo()).toEqual(
                    outcome === 'succeeds' ? [] : [[bothChannel.id, 'app_incident', 'incident']],
                )
                expect(
                    (await app.incident(incidentId, { status: 'resolved' }, 'resolve-1')).status,
                ).toBe(204)
                expect(await deliverTo()).toEqual([[bothChannel.id, 'app_incident', 'recovery']])
                expect(await deliverTo()).toEqual([])
            },
            30_000,
        )

    integrationTest(
        'a channel that stayed with the built-in outage gets its recovery after a host edit',
        async () => {
            const [host] = await seedHosts(1, { failureThreshold: 1, recoveryThreshold: 1 })
            await configureNotifications([
                fixtureChannel(hostOnlyChannel),
                fixtureChannel(bothChannel),
            ])
            await recordOutages()
            await deliverTo()
            const incidentId = (await notificationEngine()).incidents[0]!.id
            const app = await install()
            await handOver(app)
            expect(
                (await app.incident(incidentId, outageBody(host!.id), 'continue-1')).status,
            ).toBe(204)
            // The upstream changes after the continuation took over.
            await getAuthDatabase().transaction((transaction) =>
                invalidateHostMonitoringForHostsInTransaction(transaction, [host!.id]),
            )
            expect(
                (await notificationEngine()).incidents.find(
                    (incident) => incident.id === incidentId,
                )?.frozen,
            ).toBe(true)
            expect(
                (await app.incident(incidentId, { status: 'resolved' }, 'resolve-1')).status,
            ).toBe(204)
            // The worker authorizes the built-in recovery although the host context changed.
            const delivered: string[][] = []
            for (;;) {
                // oxlint-disable-next-line no-await-in-loop -- Deliveries are claimed one at a time.
                const claim = await claimNextNotificationDelivery()
                if (!claim) break
                // oxlint-disable-next-line no-await-in-loop -- Each claim is authorized like a send.
                expect(await authorizeNotificationDelivery(claim)).not.toBeNull()
                delivered.push([claim.channelId, claim.payload.category, claim.payload.type])
                // oxlint-disable-next-line no-await-in-loop -- See above.
                await acknowledgeNotificationDelivery(claim.leaseToken, { success: true })
            }
            expect(delivered.toSorted()).toEqual(
                [
                    [hostOnlyChannel.id, 'host_availability', 'recovery'],
                    [bothChannel.id, 'app_incident', 'recovery'],
                ].toSorted(),
            )
        },
        30_000,
    )

    integrationTest(
        'a monitored host cannot be deleted while the handoff is open',
        async () => {
            const { db } = await import('@/db/index.ts')
            const [host, other] = await seedHosts(2, { failureThreshold: 1 })
            await recordOutages()
            const actorId = await createUser()
            const remove = (hostId: string) =>
                getAuthDatabase().transaction((transaction) =>
                    deleteProxyHostInTransaction(transaction, actorId, hostId),
                )
            const app = await install()
            exported(await app.begin())
            const before = await monitoringSnapshot()
            await expect(remove(host!.id)).rejects.toMatchObject({
                code: 'monitoring_handoff_open',
            })
            expect(await monitoringSnapshot()).toEqual(before)
            // Once the handoff is aborted, or committed, the host can be deleted again.
            expect((await app.control('removable')).status).toBe(204)
            await remove(host!.id)
            exported(await app.begin('begin-2'))
            await handOver(app)
            await remove(other!.id)
            expect(
                await db
                    .select({ id: proxyHosts.id })
                    .from(proxyHosts)
                    .where(eq(proxyHosts.forwardHost, marker)),
            ).toEqual([])
        },
        30_000,
    )

    integrationTest(
        'an abort resets policies whose host lost its domain or was disabled meanwhile',
        async () => {
            const { db } = await import('@/db/index.ts')
            const [renamed, disabled, untouched] = await seedHosts(3, { failureThreshold: 1 })
            await recordOutages()
            const app = await install()
            exported(await app.begin())
            // The fence keeps these host changes from resetting monitoring during the handoff.
            await db.execute(
                sql`delete from rentnerproxy.host_domains where proxy_host_id = ${renamed!.id}`,
            )
            await db
                .update(proxyHosts)
                .set({ enabled: false })
                .where(eq(proxyHosts.id, disabled!.id))
            await getAuthDatabase().transaction((transaction) =>
                invalidateHostMonitoringForHostsInTransaction(transaction, [
                    renamed!.id,
                    disabled!.id,
                ]),
            )
            const state = async (hostId: string) => {
                const [row] = await db.execute<{
                    state: string
                    reason: string | null
                    proof: string | null
                }>(sql`
                    select p.state, p.context_proof as proof,
                        (select string_agg(coalesce(i.closed_reason, 'open'), ',')
                         from rentnerproxy.host_check_incidents i where i.policy_id = p.id) as reason
                    from ${hostCheckPolicies} p where p.proxy_host_id = ${hostId}`)
                return row
            }
            expect(await state(renamed!.id)).toMatchObject({ state: 'unhealthy', reason: 'open' })
            // The abort applies the skipped resets before the worker resumes, and only once.
            expect((await app.control('removable')).status).toBe(204)
            expect(await state(renamed!.id)).toEqual({
                state: 'unknown',
                reason: 'policy_changed',
                proof: null,
            })
            expect(await state(disabled!.id)).toEqual({
                state: 'unknown',
                reason: 'monitoring_disabled',
                proof: null,
            })
            expect(await state(untouched!.id)).toMatchObject({
                state: 'unhealthy',
                reason: 'open',
            })
            const reset = await monitoringSnapshot()
            exported(await app.begin('begin-2'))
            expect((await app.control('removable')).status).toBe(204)
            expect(await monitoringSnapshot()).toEqual(reset)
        },
        30_000,
    )

    integrationTest(
        'historical exported IDs and other hosts stay ordinary incidents',
        async () => {
            const { db } = await import('@/db/index.ts')
            const [first, second] = await seedHosts(2, { failureThreshold: 1 })
            await configureNotifications([fixtureChannel(hostOnlyChannel)])
            await recordOutages()
            const closed = await db.execute<{ id: string }>(sql`
                insert into rentnerproxy.host_check_incidents
                    (policy_id, started_at, detected_at, recovery_started_at, recovered_at,
                     failure_code, recovery_code, closed_reason, closed_at)
                select p.id, t - interval '3 minutes', t - interval '2 minutes',
                    t - interval '1 minute', t, 'upstream_timeout', 'expected_status', 'recovered', t
                from ${hostCheckPolicies} p
                cross join generate_series(1, 40) n
                cross join lateral (select statement_timestamp() - n * interval '1 hour' as t) times
                where p.proxy_host_id = ${first!.id}
                returning id::text`)
            const app = await install()
            const rows = await handOver(app)
            const { columns } = HOST_MONITORING_HANDOFF
            const open = rows.incidents.filter(
                (row) => row[columns.incidents.indexOf('closedReason')] === null,
            )
            const openOn = async (hostId: string) => {
                const [policy] = await db
                    .select({ id: hostCheckPolicies.id })
                    .from(hostCheckPolicies)
                    .where(eq(hostCheckPolicies.proxyHostId, hostId))
                return String(
                    open.find(
                        (row) => row[columns.incidents.indexOf('policyId')] === policy!.id,
                    )![0],
                )
            }
            const firstOutage = await openOn(first!.id)
            const secondOutage = await openOn(second!.id)
            // The real takeover is a continuation and leaves the ordinary limit untouched.
            expect(
                (await app.incident(firstOutage, outageBody(first!.id), 'continue-1')).status,
            ).toBe(204)
            // An open outage on another host, closed history with or without a host: ordinary.
            const ordinary = [
                app.incident(secondOutage, outageBody(first!.id), 'ordinary-0'),
                app.incident(
                    closed[0]!.id,
                    { ...outageBody(first!.id), category: 'service', resourceId: undefined },
                    'ordinary-1',
                ),
            ]
            for (const reply of ordinary)
                // oxlint-disable-next-line no-await-in-loop -- Opened in turn.
                expect((await reply).status).toBe(204)
            for (let index = 2; index < APP_INCIDENT_LIMITS.openPerInstallation; index += 1) {
                // oxlint-disable-next-line no-await-in-loop -- Opened in turn.
                const reply = await app.incident(
                    closed[index]!.id,
                    outageBody(first!.id),
                    'ordinary-' + index,
                )
                expect(reply.status).toBe(204)
            }
            const refused = await app.incident(
                closed[39]!.id,
                outageBody(first!.id),
                'ordinary-limit',
            )
            expect(refused).toMatchObject({ status: 429, body: { code: 'incidentLimit' } })
            expect(
                (await notificationEngine()).incidents.filter(
                    (incident) => incident.continuation === true,
                ),
            ).toHaveLength(1)
        },
        30_000,
    )

    integrationTest(
        'channels added or revised after commit get no new built-in outage notice',
        async () => {
            const [host] = await seedHosts(1, { failureThreshold: 1, recoveryThreshold: 1 })
            await configureNotifications([
                fixtureChannel(hostOnlyChannel),
                fixtureChannel(bothChannel),
            ])
            await recordOutages()
            expect(await deliverTo()).toEqual(
                [
                    [hostOnlyChannel.id, 'host_availability', 'incident'],
                    [bothChannel.id, 'host_availability', 'incident'],
                ].toSorted(),
            )
            const incidentId = (await notificationEngine()).incidents[0]!.id
            const app = await install()
            await handOver(app)
            const added = { ...hostOnlyChannel, id: '00000000-0000-4000-8000-000000000c05' }
            const addedBoth = { ...bothChannel, id: '00000000-0000-4000-8000-000000000c06' }
            await configureNotifications(
                [
                    { ...fixtureChannel(hostOnlyChannel), revision: 2 },
                    { ...fixtureChannel(bothChannel), revision: 2 },
                    fixtureChannel(added),
                    fixtureChannel(addedBoth),
                ],
                2,
            )
            expect(await deliverTo()).toEqual([])
            expect(
                (await app.incident(incidentId, outageBody(host!.id), 'continue-1')).status,
            ).toBe(204)
            // Only the continuation speaks to channels that may hear the app, once each.
            expect(await deliverTo()).toEqual(
                [
                    [bothChannel.id, 'app_incident', 'incident'],
                    [addedBoth.id, 'app_incident', 'incident'],
                ].toSorted(),
            )
            expect(
                (await app.incident(incidentId, { status: 'resolved' }, 'resolve-1')).status,
            ).toBe(204)
            expect(await deliverTo()).toEqual(
                [
                    [bothChannel.id, 'app_incident', 'recovery'],
                    [addedBoth.id, 'app_incident', 'recovery'],
                ].toSorted(),
            )
            expect(await deliverTo()).toEqual([])
        },
        30_000,
    )

    integrationTest(
        're-opening a continuation on another host or category is refused',
        async () => {
            const [host, other] = await seedHosts(2, { failureThreshold: 1, recoveryThreshold: 1 })
            await configureNotifications([fixtureChannel(bothChannel)])
            await recordOutages()
            await deliverTo()
            const incidentId = (await notificationEngine()).incidents.find(
                (incident) => incident.resourceId === host!.id,
            )!.id
            const app = await install()
            await handOver(app)
            expect(
                (await app.incident(incidentId, outageBody(host!.id), 'continue-1')).status,
            ).toBe(204)
            for (const [body, key] of [
                [outageBody(host!.id, 'latency'), 'moved-category'],
                [outageBody(other!.id), 'moved-host'],
            ] as const)
                // oxlint-disable-next-line no-await-in-loop -- Each refusal is checked in turn.
                expect(await app.incident(incidentId, body, key)).toMatchObject({
                    status: 409,
                    body: { code: 'incidentContinuationConflict' },
                })
            expect(
                (await app.incident(incidentId, { status: 'resolved' }, 'resolve-1')).status,
            ).toBe(204)
            expect(await deliverTo()).toEqual([[bothChannel.id, 'app_incident', 'recovery']])
        },
        30_000,
    )

    integrationTest(
        'continuations keep their own capacity next to a full shared incident limit',
        async () => {
            const { db } = await import('@/db/index.ts')
            const hosts = await seedHosts(4, { failureThreshold: 1, recoveryThreshold: 1 })
            await configureNotifications([fixtureChannel(hostOnlyChannel)])
            await recordOutages()
            await deliverTo()
            // Other categories fill the rest of the shared limit with incidents nothing may evict.
            const now = Date.now()
            const certificate = (index: number): NotificationIncident => ({
                id: randomUUID(),
                category: 'certificate_renewal',
                resourceId: 'certificate-' + index,
                severity: 'error',
                startedAt: now,
                observedAt: now,
                evidence: 'certificate-' + index,
                failures: 1,
                recoveredAt: null,
                recoveryEvidence: null,
                channels: [],
            })
            await db.transaction(async (transaction) => {
                await lockNotificationConfiguration(transaction)
                const runtime = await lockNotificationRuntime(transaction)
                const filler = Array.from(
                    { length: NOTIFICATION_LIMITS.incidents - runtime.engine.incidents.length },
                    (_, index) => certificate(index),
                )
                await writeNotificationRuntime(transaction, {
                    ...runtime,
                    engine: {
                        ...runtime.engine,
                        incidents: [...runtime.engine.incidents, ...filler],
                    },
                })
            })
            const builtIn = (await notificationEngine()).incidents.filter(
                (incident) => incident.category === 'host_availability',
            )
            expect(builtIn).toHaveLength(hosts.length)
            const app = await install()
            await handOver(app)
            for (const incident of builtIn) {
                // oxlint-disable-next-line no-await-in-loop -- Continued in turn.
                const reply = await app.incident(
                    incident.id,
                    outageBody(incident.resourceId),
                    'continue-' + incident.id,
                )
                expect(reply.status).toBe(204)
            }
            // The frozen outages moved out of the shared limit: another category fits again.
            const engine = await notificationEngine()
            const configuration = await db.transaction(async (transaction) =>
                resolveEffectiveNotificationConfigurationInTransaction(
                    transaction,
                    await lockNotificationConfiguration(transaction),
                ),
            )
            expect(
                appendNotificationIncident(
                    structuredClone(engine),
                    configuration,
                    certificate(9_999),
                ),
            ).toBe(true)
            for (const incident of builtIn) {
                // oxlint-disable-next-line no-await-in-loop -- Resolved in turn.
                const reply = await app.incident(
                    incident.id,
                    { status: 'resolved' },
                    'resolve-' + incident.id,
                )
                expect(reply.status).toBe(204)
            }
            // The outage notices used the channel's sends of this rate window.
            await Bun.sleep(NOTIFICATION_LIMITS.rateWindowMs + 50)
            expect(await deliverTo()).toEqual(
                builtIn.map(() => [hostOnlyChannel.id, 'host_availability', 'recovery']),
            )
        },
        30_000,
    )

    scaleTest(
        'every one of the maximum open outages continues and ends once per channel',
        async () => {
            const { db } = await import('@/db/index.ts')
            const started = performance.now()
            const hosts = await seedHosts(HOST_MONITORING_LIMITS.maxPolicies)
            const outages = await db.execute<{ id: string; policy_id: string }>(sql`
                insert into rentnerproxy.host_check_incidents
                    (policy_id, started_at, detected_at, failure_code)
                select p.id, statement_timestamp() - interval '5 minutes',
                    statement_timestamp() - interval '4 minutes', 'upstream_timeout'
                from ${hostCheckPolicies} p join ${proxyHosts} h on h.id = p.proxy_host_id
                where h.forward_host = ${marker}
                returning id::text, policy_id::text`)
            expect(outages).toHaveLength(hosts.length)
            const policies = new Map(
                (
                    await db
                        .select({
                            id: hostCheckPolicies.id,
                            proxyHostId: hostCheckPolicies.proxyHostId,
                            version: hostCheckPolicies.version,
                            domain: hostCheckPolicies.domain,
                        })
                        .from(hostCheckPolicies)
                ).map((policy) => [policy.id, policy]),
            )
            const channels = [hostOnlyChannel, bothChannel]
            await configureNotifications(channels.map(fixtureChannel))
            // Built-in monitoring announced every outage to both channels before the handoff.
            const now = Date.now()
            const incidents: NotificationIncident[] = outages.map((outage) => {
                const policy = policies.get(outage.policy_id)!
                return {
                    id: outage.id,
                    category: 'host_availability',
                    resourceId: policy.proxyHostId,
                    severity: 'error',
                    startedAt: now - 300_000,
                    observedAt: now - 240_000,
                    evidence: outage.id,
                    failures: 1,
                    recoveredAt: null,
                    recoveryEvidence: null,
                    channels: channels.map(({ id }) => ({
                        channelId: id,
                        channelRevision: 1,
                        failure: 'succeeded',
                        recovery: null,
                        notified: true,
                    })),
                    host: {
                        policyId: policy.id,
                        policyVersion: policy.version,
                        contextProof: fixtureContext.proof,
                        contextRevision: fixtureContext.revision,
                        domain: policy.domain,
                        failureCode: 'upstream_timeout',
                        detectedAt: new Date(now - 240_000).toISOString(),
                        recoveryStartedAt: null,
                        managementPath: '/proxy-hosts',
                        subscriptions: channels.map(({ id }) => ({
                            channelId: id,
                            channelRevision: 1,
                        })),
                    },
                }
            })
            await db.transaction(async (transaction) => {
                await lockNotificationConfiguration(transaction)
                const runtime = await lockNotificationRuntime(transaction)
                await writeNotificationRuntime(transaction, {
                    ...runtime,
                    engine: { ...runtime.engine, incidents },
                })
            })
            const app = await install()
            const rows = await handOver(app)
            expect(rows.incidents).toHaveLength(outages.length)
            const seeded = performance.now()

            for (const [index, incident] of incidents.entries()) {
                // oxlint-disable-next-line no-await-in-loop -- The broker renews the lease meanwhile.
                if (index % 250 === 0) await app.renew()
                // oxlint-disable-next-line no-await-in-loop -- The app continues outages in turn.
                const reply = await app.incident(
                    incident.id,
                    outageBody(incident.resourceId),
                    'continue-' + incident.id,
                )
                expect(reply.status).toBe(204)
            }
            const continued = performance.now()
            const engine = await notificationEngine()
            expect(engine.incidents.filter((incident) => incident.continuation)).toHaveLength(
                outages.length,
            )
            // The handover leaves the shared capacity to the other categories.
            const configuration = await db.transaction(async (transaction) =>
                resolveEffectiveNotificationConfigurationInTransaction(
                    transaction,
                    await lockNotificationConfiguration(transaction),
                ),
            )
            expect(
                appendNotificationIncident(structuredClone(engine), configuration, {
                    id: randomUUID(),
                    category: 'certificate_renewal',
                    resourceId: 'certificate-fixture',
                    severity: 'error',
                    startedAt: now,
                    observedAt: now,
                    evidence: 'certificate-fixture',
                    failures: 1,
                    recoveredAt: null,
                    recoveryEvidence: null,
                    channels: [],
                }),
            ).toBe(true)

            for (const [index, incident] of incidents.entries()) {
                // oxlint-disable-next-line no-await-in-loop -- The broker renews the lease meanwhile.
                if (index % 250 === 0) await app.renew()
                // oxlint-disable-next-line no-await-in-loop -- The app resolves outages in turn.
                const reply = await app.incident(
                    incident.id,
                    { status: 'resolved' },
                    'resolve-' + incident.id,
                )
                expect(reply.status).toBe(204)
            }
            const resolved = performance.now()
            // Every channel that heard of an outage is owed or sent exactly one end of it.
            const final = await notificationEngine()
            const byId = new Map(final.incidents.map((incident) => [incident.id, incident]))
            for (const incident of incidents) {
                const builtIn = byId.get(incident.id)
                const continuation = final.incidents.find(
                    (candidate) => candidate.continuation && candidate.app?.key === incident.id,
                )
                expect(owedRecoveries(builtIn, hostOnlyChannel.id)).toBe(1)
                expect(owedRecoveries(continuation, hostOnlyChannel.id)).toBe(0)
                expect(owedRecoveries(builtIn, bothChannel.id)).toBe(0)
                expect(owedRecoveries(continuation, bothChannel.id)).toBe(1)
            }
            console.info('[monitoring-handoff] maximum continuation', {
                outages: outages.length,
                seedMs: Math.round(seeded - started),
                continueMs: Math.round(continued - seeded),
                resolveMs: Math.round(resolved - continued),
                stateBytes: Buffer.byteLength(JSON.stringify(final)),
            })
        },
        600_000,
    )
})
