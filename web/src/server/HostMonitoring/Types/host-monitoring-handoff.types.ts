import type { HOST_MONITORING_HANDOFF } from '@/config/host-monitoring.config.ts'

/**
 * Monitoring legacy handoff export, format `rentnerproxy.monitoring` version 1.
 *
 * Part 0 is the manifest with the format, the version and the column names of every row kind. The
 * policy parts follow, then the observation parts, then the incident parts; a kind without rows has
 * no part. The last part is the end part with the number of rows of each kind, so an importer can
 * prove that it read the whole export.
 *
 * Each row is an array in the manifest's column order. Timestamps are UTC ISO 8601 strings with
 * microseconds (`2026-11-28T10:00:00.123456Z`) or null; IDs and versions are UUID strings; the other
 * columns are strings, integers, booleans or null as the built-in tables hold them. Policies are
 * ordered by ID, observations by policy ID, check time and ID, incidents by policy ID, start time
 * and ID, and parts are filled in that order up to the part byte limit. All rows come from one
 * database snapshot, so the same retained state yields the same parts and the same digest, also
 * for a begin repeated after an abort.
 *
 * Platform-internal values stay out: leases, the configuration proofs a probe compared and the
 * platform user who saved a policy.
 *
 * An open incident has a null `closedReason`. After commit an app continues it without a second
 * outage notice by opening an app incident whose key is the incident ID and whose resource is the
 * policy's `proxyHostId`: the platform hands the outage notices it already sent over to that
 * incident once, and the app's resolve sends the recovery notice.
 */
export type HostMonitoringHandoffRowKind = keyof typeof HOST_MONITORING_HANDOFF.columns

export type HostMonitoringHandoffValue = string | number | boolean | null

export interface HostMonitoringHandoffManifest {
    format: typeof HOST_MONITORING_HANDOFF.format
    version: typeof HOST_MONITORING_HANDOFF.version
    kind: 'manifest'
    columns: Record<HostMonitoringHandoffRowKind, string[]>
}

export interface HostMonitoringHandoffRowPart {
    kind: HostMonitoringHandoffRowKind
    rows: HostMonitoringHandoffValue[][]
}

export interface HostMonitoringHandoffEnd {
    kind: 'end'
    counts: Record<HostMonitoringHandoffRowKind, number>
}

export type HostMonitoringHandoffPart =
    HostMonitoringHandoffManifest | HostMonitoringHandoffRowPart | HostMonitoringHandoffEnd
