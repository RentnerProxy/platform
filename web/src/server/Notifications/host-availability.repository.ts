// oxlint-disable-next-line import/no-unassigned-import -- Host incident admission is a privileged transaction boundary.
import '@tanstack/react-start/server-only'

import { randomUUID } from 'node:crypto'
import { and, eq, inArray } from 'drizzle-orm'
import { HOST_AVAILABILITY_HANDOVER_MS } from '@/config/notifications.config.ts'
import { hostCheckPolicies, hostDomains, proxyHosts } from '@/db/schema.ts'
import type { HostMonitoringContext } from '@/lib/HostMonitoring/Types/host-monitoring.types.ts'
import type { AuthTransaction } from '@/server/Auth/Core/Types/database.types.ts'
import type { HostMonitoringPolicy } from '@/server/HostMonitoring/Types/host-monitoring.repository.types.ts'
import { readLegacyFeatureCommittedAtInTransaction } from '@/server/LegacyHandoff/ownership.server.ts'
import { readHostMonitoringContextInTransaction } from '@/server/RuntimeDiagnostics/domain-diagnostics-data.ts'
import { DomainDiagnosticsError } from '@/server/RuntimeDiagnostics/domain-diagnostics.errors.ts'
import {
    cancelHostAvailabilityIncidents,
    freezeHostAvailabilityIncidents,
    observeHostAvailabilityTransition,
} from './host-availability.ts'
import { findHostAvailabilityContinuation } from './incident-engine.ts'
import { resolveEffectiveNotificationConfigurationInTransaction } from './notification-access.ts'
import {
    lockNotificationConfiguration,
    lockNotificationRuntime,
    readNotificationConfiguration,
    readNotificationRuntime,
    writeNotificationRuntime,
} from './notification-storage.ts'
import type {
    HostAvailabilityIncidentSource,
    NotificationDeliveryClaim,
} from './Types/notification-internal.types.ts'
import type { NotificationIncident, NotificationState } from './Types/notification-state.types.ts'

/**
 * End the built-in host outages of changed hosts silently. A frozen outage is left alone: after the
 * monitoring handoff its end belongs to the app's continuation, and its notices still in flight and
 * the recoveries it owes stay with it.
 */
export async function cancelHostAvailabilityForHostsInTransaction(
    transaction: AuthTransaction,
    proxyHostIds: readonly string[],
): Promise<void> {
    const ids = new Set(proxyHostIds)
    if (ids.size === 0) return
    const changed = (incident: NotificationIncident) =>
        incident.host !== undefined && incident.frozen !== true && ids.has(incident.resourceId)
    const snapshot = await readNotificationRuntime(transaction)
    if (!snapshot.engine.incidents.some(changed)) return
    await lockNotificationConfiguration(transaction)
    const runtime = await lockNotificationRuntime(transaction)
    const invalid = new Set(runtime.engine.incidents.filter(changed).map((incident) => incident.id))
    const engine = cancelHostAvailabilityIncidents(runtime.engine, invalid, Date.now())
    if (engine !== runtime.engine)
        await writeNotificationRuntime(transaction, { ...runtime, engine })
}

/**
 * Stop built-in host outages from announcing themselves anew; the monitoring handoff commit calls
 * it. Notices admitted before stay deliverable, and so does the recovery owed for them.
 */
export async function freezeHostAvailabilityNotificationsInTransaction(
    transaction: AuthTransaction,
): Promise<void> {
    const snapshot = await readNotificationRuntime(transaction)
    if (
        !snapshot.engine.incidents.some(
            (incident) =>
                incident.category === 'host_availability' && incident.recoveredAt === null,
        )
    )
        return
    await lockNotificationConfiguration(transaction)
    const runtime = await lockNotificationRuntime(transaction)
    const engine = freezeHostAvailabilityIncidents(runtime.engine)
    if (engine !== runtime.engine)
        await writeNotificationRuntime(transaction, { ...runtime, engine })
}

export async function recordHostAvailabilityTransitionInTransaction(
    transaction: AuthTransaction,
    policy: HostMonitoringPolicy,
    context: HostMonitoringContext,
    incident: HostAvailabilityIncidentSource,
    kind: 'outage' | 'recovery',
): Promise<void> {
    const snapshot = await readNotificationConfiguration(transaction)
    if (
        kind === 'outage' &&
        (!snapshot.enabled ||
            snapshot.pausedAfterRestore ||
            !snapshot.channels.some(
                (channel) => channel.enabled && channel.events.includes('host_availability'),
            ))
    )
        return
    if (kind === 'recovery') {
        const previous = await readNotificationRuntime(transaction)
        if (!previous.engine.incidents.some((candidate) => candidate.id === incident.id)) return
    }
    // Monitoring already holds runtime settings and its own lock. Notification operations
    // only read monitoring data, preserving this configuration-before-runtime lock order.
    const configuration = await resolveEffectiveNotificationConfigurationInTransaction(
        transaction,
        await lockNotificationConfiguration(transaction),
    )
    const runtime = await lockNotificationRuntime(transaction)
    const occurredAt = kind === 'recovery' ? incident.recoveredAt : incident.detectedAt
    if (!occurredAt) return
    const engine = observeHostAvailabilityTransition(
        runtime.engine,
        configuration,
        {
            kind,
            incidentId: incident.id,
            proxyHostId: policy.proxyHostId,
            startedAt: incident.startedAt.getTime(),
            occurredAt: occurredAt.getTime(),
            failures: policy.failureThreshold,
            host: {
                policyId: policy.id,
                policyVersion: policy.version,
                contextProof: context.proof,
                contextRevision: context.revision,
                domain: policy.domain,
                failureCode: incident.failureCode,
                detectedAt: incident.detectedAt.toISOString(),
                recoveryStartedAt: incident.recoveryStartedAt?.toISOString() ?? null,
                managementPath: '/proxy-hosts',
            },
        },
        Math.max(Date.now(), occurredAt.getTime()),
        randomUUID,
    )
    if (engine !== runtime.engine)
        await writeNotificationRuntime(transaction, { ...runtime, engine })
}

export async function reconcileHostAvailabilityInTransaction(
    transaction: AuthTransaction,
    state: NotificationState,
    now: number,
): Promise<NotificationState> {
    const incidents = state.incidents.filter((incident) => incident.host)
    if (incidents.length === 0) return state
    // Built-in outages wait for the monitoring app only for a bounded time after its commit.
    const committedAt = await readLegacyFeatureCommittedAtInTransaction(transaction, 'monitoring')
    const handoverEnded =
        committedAt !== null && now - committedAt.getTime() >= HOST_AVAILABILITY_HANDOVER_MS
    // An outage the app continues ends with its continuation, whenever the app resolves it.
    const continued = (incident: NotificationIncident) =>
        findHostAvailabilityContinuation(state, incident)?.recoveredAt === null
    const frozen = incidents.filter((incident) => incident.frozen === true)
    const existing =
        frozen.length === 0
            ? new Set<string>()
            : new Set(
                  (
                      await transaction
                          .select({ id: proxyHosts.id })
                          .from(proxyHosts)
                          .where(
                              inArray(proxyHosts.id, [
                                  ...new Set(frozen.map((incident) => incident.resourceId)),
                              ]),
                          )
                  ).map(({ id }) => id),
              )
    const policies = await transaction
        .select({ policy: hostCheckPolicies })
        .from(hostCheckPolicies)
        .innerJoin(proxyHosts, eq(proxyHosts.id, hostCheckPolicies.proxyHostId))
        .innerJoin(
            hostDomains,
            and(
                eq(hostDomains.proxyHostId, proxyHosts.id),
                eq(hostDomains.domain, hostCheckPolicies.domain),
            ),
        )
        .where(
            and(
                inArray(hostCheckPolicies.id, [
                    ...new Set(incidents.map((incident) => incident.host!.policyId)),
                ]),
                eq(hostCheckPolicies.enabled, true),
                eq(proxyHosts.enabled, true),
            ),
        )
    const current = new Map(policies.map(({ policy }) => [policy.id, policy]))
    const invalid = new Set(
        incidents
            .filter((incident) => {
                // A frozen outage no longer follows the retired policy: it ends with its
                // continuation, or silently when nothing continues it and its host is gone or the
                // handover window passed.
                if (incident.frozen === true)
                    return (
                        incident.recoveredAt === null &&
                        !continued(incident) &&
                        (handoverEnded || !existing.has(incident.resourceId))
                    )
                const host = incident.host!
                const policy = current.get(host.policyId)
                return (
                    (handoverEnded && incident.recoveredAt === null && !continued(incident)) ||
                    !policy ||
                    policy.proxyHostId !== incident.resourceId ||
                    policy.version !== host.policyVersion ||
                    policy.domain !== host.domain ||
                    policy.contextProof !== host.contextProof ||
                    policy.contextRevision !== host.contextRevision
                )
            })
            .map((incident) => incident.id),
    )
    return cancelHostAvailabilityIncidents(state, invalid, now)
}

export async function authorizeHostAvailabilityDeliveryInTransaction(
    transaction: AuthTransaction,
    claim: NotificationDeliveryClaim,
): Promise<boolean> {
    if (claim.payload.category !== 'host_availability' || claim.payload.type === 'test') return true
    const runtime = await readNotificationRuntime(transaction)
    const incident = runtime.engine.incidents.find(
        (candidate) =>
            candidate.id === claim.payload.incidentId &&
            candidate.resourceId === claim.payload.resourceId,
    )
    const host = incident?.host
    if (!host) return false
    const currentState = await reconcileHostAvailabilityInTransaction(
        transaction,
        runtime.engine,
        Date.now(),
    )
    if (!currentState.incidents.some((candidate) => candidate.id === incident.id)) return false
    // A frozen outage's notices describe the host as it was announced; the host must still exist.
    if (incident.frozen === true) {
        const [exists] = await transaction
            .select({ id: proxyHosts.id })
            .from(proxyHosts)
            .where(eq(proxyHosts.id, incident.resourceId))
            .limit(1)
        return exists !== undefined
    }
    try {
        const current = await readHostMonitoringContextInTransaction(transaction, {
            hostType: 'proxy',
            hostId: incident.resourceId,
            domain: host.domain,
        })
        return (
            current.enabled &&
            current.availability.proof === host.contextProof &&
            current.availability.revision === host.contextRevision
        )
    } catch (error) {
        if (error instanceof DomainDiagnosticsError && error.code === 'invalid_input') return false
        throw error
    }
}
