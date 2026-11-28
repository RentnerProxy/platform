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
 * An open incident has a null `closedReason`. After commit the app must open every exported open
 * incident as an app incident whose key is the incident ID and whose resource is the policy's
 * `proxyHostId`, and then resolve it according to its own next observation, also when the host
 * recovered during the handoff. Only that ends the built-in outage with a recovery notice; one the
 * app never continues is dropped without one 24 hours after commit. Only an incident that was still
 * open at commit, on its own host, becomes a continuation; continuations do not count against the
 * ordinary open incident limit, any other key does. A continuation keeps its host and category:
 * opening its key with another one is refused with 409 `incidentContinuationConflict`.
 *
 * A host that no longer exists cannot be continued: opening its incident answers 404 like any
 * uncovered host, and the app skips it while it still continues every other exported incident.
 * Its built-in outage ends without a recovery notice, because nothing can observe that host
 * recover. When a continued host goes away later, the platform closes the continuation with the
 * resolution `resourceUnavailable` and the built-in outage ends silently with it. A host with a
 * monitoring policy cannot be deleted while the handoff is open, so the export never loses rows.
 *
 * Every notification channel hears of each outage once and of its end once, whatever it subscribes
 * to; the handoff migrates no subscription. A channel that accepts the continuation (the
 * `app_incident` event and the app's category) moves to it: an outage notice it already got counts
 * as the continuation's, otherwise the continuation announces the outage, and the app's resolve
 * sends its recovery notice. Every other channel that got the built-in outage notice, such as one
 * subscribed only to `host_availability`, gets the built-in recovery notice when the app resolves
 * the continuation, also after the host was edited meanwhile. From commit on, built-in outages
 * announce themselves to no further channel.
 *
 * Delivery history belongs to a channel revision, so the guarantee holds for every channel left
 * unchanged since it was told. Editing a channel starts a new revision without that history: the
 * built-in outage owes the revised channel no recovery, while a continuation it accepts announces
 * the outage to it once and later sends its recovery.
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
