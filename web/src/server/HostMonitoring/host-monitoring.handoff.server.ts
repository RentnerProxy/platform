import '@tanstack/react-start/server-only'

import { sql, type SQL } from 'drizzle-orm'
import { HOST_MONITORING_HANDOFF } from '@/config/host-monitoring.config.ts'
import { LEGACY_HANDOFF_LIMITS } from '@/config/legacy-handoff.config.ts'
import { hostCheckIncidents, hostCheckObservations, hostCheckPolicies } from '@/db/schema.ts'
import type { AppRuntimeJsonValue } from '@/server/AppRuntime/Types/authority.types.ts'
import type { AuthTransaction } from '@/server/Auth/Core/Types/database.types.ts'
import type {
    LegacyFeatureHandoffSource,
    LegacyFeatureInspection,
} from '@/server/LegacyHandoff/Types/legacy-handoff.types.ts'
import type {
    HostMonitoringHandoffPart,
    HostMonitoringHandoffRowKind,
    HostMonitoringHandoffValue,
} from './Types/host-monitoring-handoff.types.ts'

const cursor = sql.raw('rentnerproxy_monitoring_handoff')
const kinds = [
    'policies',
    'observations',
    'incidents',
] as const satisfies readonly HostMonitoringHandoffRowKind[]

/** Render a timestamp independently of the session time zone, with its full precision. */
function utc(column: string): SQL {
    return sql`to_char(${sql.raw(column)} at time zone 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"')`
}

/**
 * One cursor reads every row from a single snapshot, in export order. Each branch builds its row in
 * the manifest's column order; the sort keys keep policies, observations and incidents apart.
 */
const exportQuery = sql`
    select exported.kind, exported.row from (
        select 0 as kind, p.id as k1, null::timestamptz as k2, null::uuid as k3,
            json_build_array(
                p.id, p.proxy_host_id, p.domain, p.enabled, p.interval_seconds, p.timeout_ms,
                p.expected_status, p.failure_threshold, p.recovery_threshold, p.retention_days,
                p.sample_limit, p.incident_limit, p.version, p.state, p.failure_count,
                p.recovery_count, ${utc('p.failure_started_at')}, ${utc('p.recovery_started_at')},
                ${utc('p.last_checked_at')}, p.last_outcome, p.last_code, p.last_duration_ms,
                p.last_http_status, ${utc('p.next_check_at')}, ${utc('p.created_at')},
                ${utc('p.updated_at')}
            )::text as row
        from ${hostCheckPolicies} p
        union all
        select 1, o.policy_id, o.checked_at, o.id,
            json_build_array(
                o.id, o.policy_id, o.policy_version, ${utc('o.checked_at')}, o.status, o.code,
                o.duration_ms, o.http_status
            )::text
        from ${hostCheckObservations} o
        union all
        select 2, i.policy_id, i.started_at, i.id,
            json_build_array(
                i.id, i.policy_id, ${utc('i.started_at')}, ${utc('i.detected_at')},
                ${utc('i.recovery_started_at')}, ${utc('i.recovered_at')}, i.failure_code,
                i.recovery_code, i.closed_reason, ${utc('i.closed_at')}
            )::text
        from ${hostCheckIncidents} i
    ) exported
    order by exported.kind, exported.k1, exported.k2, exported.k3`

/** The serialized size of a part of the kind without rows. */
function envelopeBytes(kind: HostMonitoringHandoffRowKind): number {
    return Buffer.byteLength(JSON.stringify({ kind, rows: [] }))
}

/** Fill parts of one kind up to the byte limit, exactly as the journal will serialize them. */
function createPartWriter(emit: (part: AppRuntimeJsonValue) => Promise<void>) {
    let kind: HostMonitoringHandoffRowKind | undefined
    let rows: HostMonitoringHandoffValue[][] = []
    let bytes = 0
    const send = (part: HostMonitoringHandoffPart) =>
        // The part types hold only JSON values; the journal validates the serialized text again.
        emit(part as unknown as AppRuntimeJsonValue)
    const flush = async () => {
        if (kind === undefined || rows.length === 0) return
        const part = { kind, rows }
        rows = []
        bytes = 0
        await send(part)
    }
    return {
        send,
        flush,
        async add(rowKind: HostMonitoringHandoffRowKind, row: HostMonitoringHandoffValue[]) {
            const size = Buffer.byteLength(JSON.stringify(row))
            if (rowKind !== kind) {
                await flush()
                kind = rowKind
            }
            if (rows.length > 0 && bytes + 1 + size > LEGACY_HANDOFF_LIMITS.partBytes) await flush()
            if (rows.length === 0) bytes = envelopeBytes(rowKind) + size
            else bytes += 1 + size
            // A single row is a few hundred bytes; the journal refuses anything larger than a part.
            rows.push(row)
        },
    }
}

function columns(): Record<HostMonitoringHandoffRowKind, string[]> {
    const { policies, observations, incidents } = HOST_MONITORING_HANDOFF.columns
    return { policies: [...policies], observations: [...observations], incidents: [...incidents] }
}

/**
 * Hand built-in monitoring over to the monitoring app. Every built-in writer runs behind the fence,
 * so the export sees state no platform worker changes; the single cursor snapshot also keeps a host
 * removal that cascades into monitoring rows from splitting the export.
 */
export const hostMonitoringHandoffSource: LegacyFeatureHandoffSource = {
    domain: 'monitoring',

    async inspect(transaction: AuthTransaction): Promise<LegacyFeatureInspection> {
        const [row] = await transaction.execute<{ policies: number }>(
            sql`select count(*)::integer as policies from ${hostCheckPolicies}`,
        )
        const policies = Number(row?.policies ?? 0)
        return { configured: policies > 0, references: policies }
    },

    async export(transaction, emit) {
        const writer = createPartWriter(emit)
        const counts = { policies: 0, observations: 0, incidents: 0 }
        await writer.send({
            format: HOST_MONITORING_HANDOFF.format,
            version: HOST_MONITORING_HANDOFF.version,
            kind: 'manifest',
            columns: columns(),
        })
        await transaction.execute(sql`declare ${cursor} no scroll cursor for ${exportQuery}`)
        try {
            for (;;) {
                // oxlint-disable-next-line no-await-in-loop -- The cursor is read page by page.
                const page = await transaction.execute<{ kind: number; row: string }>(
                    sql`fetch forward ${sql.raw(String(HOST_MONITORING_HANDOFF.fetchRows))} from ${cursor}`,
                )
                for (const { kind: index, row } of page) {
                    const kind = kinds[Number(index)]
                    if (kind === undefined) throw new Error('Unknown monitoring export row.')
                    counts[kind] += 1
                    // oxlint-disable-next-line no-await-in-loop -- Parts are emitted in order.
                    await writer.add(kind, JSON.parse(row) as HostMonitoringHandoffValue[])
                }
                if (page.length < HOST_MONITORING_HANDOFF.fetchRows) break
            }
        } finally {
            await transaction.execute(sql`close ${cursor}`).catch(() => undefined)
        }
        await writer.flush()
        await writer.send({ kind: 'end', counts })
    },

    /**
     * Commit leaves every table and row in place for the removal step: the committed journal marks
     * them retired, the fence keeps every built-in writer out and the worker gate stops for good.
     * No lease survives the transfer, so no claimed probe can still complete against these rows.
     */
    async retire(transaction) {
        // A row a host removal is deleting goes away anyway; skipping it avoids waiting on that
        // removal, which itself waits for this commit before it resets monitoring.
        await transaction.execute(sql`
            update ${hostCheckPolicies} as policy
            set lease_token = null, lease_expires_at = null
            from (
                select id from ${hostCheckPolicies}
                where lease_token is not null
                for update skip locked
            ) leased
            where policy.id = leased.id`)
    },
}
