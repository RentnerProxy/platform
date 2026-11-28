import { createHash } from 'node:crypto'
import { NOTIFICATION_LIMITS } from '@/config/notifications.config.ts'
import { selectNotificationDelivery } from './notification-scheduling.ts'
import {
    channelAcceptsIncident,
    deferredHostFailure,
    notificationAdmissionOrder,
    pendingNotificationAdmission,
} from './notification-admission.ts'
import type {
    AppIncidentNotification,
    NotificationDeliveryResult,
    NotificationObservation,
    NotificationPayload,
    NotificationStatus,
} from '@/lib/Notifications/Types/notifications.types.ts'
import type {
    NotificationIncident,
    NotificationClaimedDelivery,
    NotificationEngineConfiguration,
    NotificationQueuedDelivery,
    NotificationState,
} from './Types/notification-state.types.ts'

function recoveryOwed(
    incident: NotificationIncident,
    configuration: NotificationEngineConfiguration,
) {
    return (
        configuration.channels.some((channel) => deferredHostFailure(incident, channel)) ||
        (incident.recoveredAt !== null &&
            incident.channels.some(
                (marker) =>
                    (marker.failure === 'succeeded' || marker.notified === true) &&
                    marker.recovery === null &&
                    configuration.channels.some(
                        (channel) =>
                            channel.id === marker.channelId &&
                            channel.revision === marker.channelRevision &&
                            channel.enabled &&
                            channelAcceptsIncident(channel, incident) &&
                            channel.recovery,
                    ),
            ))
    )
}

export function createNotificationState(): NotificationState {
    return {
        version: 1,
        proxyApplyPending: null,
        incidents: [],
        deliveries: [],
        deferredCount: 0,
        saturationCount: 0,
    }
}

function deliveryLifetimeStartedAt(delivery: NotificationQueuedDelivery) {
    return delivery.payload.category === 'backup'
        ? (delivery.backupAvailableAt ?? delivery.createdAt)
        : delivery.createdAt
}

/** The channel's events, and for an app incident its category subscription, admit the delivery. */
function channelAcceptsDelivery(
    state: NotificationState,
    delivery: NotificationQueuedDelivery,
    channel: NotificationEngineConfiguration['channels'][number],
) {
    if (!channel.events.includes(delivery.payload.category)) return false
    if (delivery.payload.category !== 'app_incident' || delivery.payload.type === 'test')
        return true
    const incident = state.incidents.find((item) => item.id === delivery.payload.incidentId)
    return incident !== undefined && channelAcceptsIncident(channel, incident)
}

function isActive(delivery: NotificationQueuedDelivery) {
    return delivery.status === 'pending' || delivery.status === 'inflight'
}

function markTerminal(state: NotificationState, delivery: NotificationQueuedDelivery) {
    if (delivery.payload.type === 'test') return
    const incident = state.incidents.find((item) => item.id === delivery.payload.incidentId)
    const marker = incident?.channels.find(
        (item) =>
            item.channelId === delivery.channelId &&
            item.channelRevision === delivery.channelRevision,
    )
    if (!marker) return
    const status = delivery.status === 'succeeded' ? 'succeeded' : 'failed'
    if (delivery.payload.type !== 'incident') {
        marker.recovery = status
        return
    }
    marker.failure = status
    if (status !== 'succeeded') return
    marker.notified = true
    // An app incident's baseline is the severity the channel was told, also after a pending
    // notice was raised before it was sent.
    const { severity } = delivery.payload
    if (marker.severity !== undefined && severity !== 'info') marker.severity = severity
}

function terminate(
    state: NotificationState,
    delivery: NotificationQueuedDelivery,
    status: 'failed' | 'cancelled',
    nowMs: number,
) {
    const leaseLost = delivery.status === 'inflight'
    delivery.status = status
    delivery.error =
        status === 'cancelled' ? 'cancelled' : leaseLost ? 'timeout' : (delivery.error ?? 'timeout')
    delivery.updatedAt = nowMs
    delivery.leaseToken = null
    delivery.leaseExpiresAt = null
    markTerminal(state, delivery)
}

function isSupersededManualDelivery(
    state: NotificationState,
    delivery: NotificationQueuedDelivery,
): boolean {
    if (delivery.payload.code !== 'certificate_renewal_manual_dns_required') return false
    const incident = state.incidents.find((item) => item.id === delivery.payload.incidentId)
    if (!incident || incident.recoveredAt === null) return false
    return incident.channels.some(
        (marker) =>
            marker.channelId === delivery.channelId &&
            marker.channelRevision === delivery.channelRevision &&
            marker.recovery === 'failed',
    )
}

function reconcile(
    state: NotificationState,
    configuration: NotificationEngineConfiguration,
    nowMs: number,
) {
    state.deferredCount = 0
    for (const delivery of state.deliveries) {
        if (!isActive(delivery)) continue
        const allowed =
            configuration.enabled &&
            !configuration.pausedAfterRestore &&
            configuration.channels.some(
                (channel) =>
                    channel.enabled &&
                    channel.id === delivery.channelId &&
                    channel.revision === delivery.channelRevision &&
                    channelAcceptsDelivery(state, delivery, channel),
            )
        // An admitted network attempt may finish, but cannot be claimed again after policy revocation.
        if (
            delivery.status === 'inflight' &&
            delivery.leaseExpiresAt !== null &&
            delivery.leaseExpiresAt > nowMs
        )
            continue
        if (!allowed || isSupersededManualDelivery(state, delivery)) {
            terminate(state, delivery, 'cancelled', nowMs)
        } else if (delivery.payload.type === 'test') {
            // A manual test is one attempt, never a delayed background send after a crash.
            terminate(state, delivery, 'failed', nowMs)
        } else if (
            nowMs - deliveryLifetimeStartedAt(delivery) >= NOTIFICATION_LIMITS.deliveryLifetimeMs ||
            delivery.attempts >= NOTIFICATION_LIMITS.attempts
        ) {
            terminate(state, delivery, 'failed', nowMs)
        } else if (delivery.status === 'inflight') {
            delivery.status = 'pending'
            delivery.leaseToken = null
            delivery.leaseExpiresAt = null
            delivery.nextAttemptAt = nowMs + retryDelay(delivery.attempts, delivery.id)
            delivery.updatedAt = nowMs
        }
    }
    // Markers live with their incident, independently of the bounded delivery history.
    for (const incident of state.incidents) {
        incident.channels = incident.channels.filter((marker) =>
            configuration.channels.some(
                (channel) =>
                    channel.id === marker.channelId && channel.revision === marker.channelRevision,
            ),
        )
    }
    state.deliveries = state.deliveries.filter(
        (delivery) =>
            isActive(delivery) || nowMs - delivery.updatedAt < NOTIFICATION_LIMITS.retentionMs,
    )
    state.incidents = state.incidents.filter(
        (incident) =>
            incident.recoveredAt === null ||
            nowMs - incident.recoveredAt < NOTIFICATION_LIMITS.retentionMs ||
            recoveryOwed(incident, configuration) ||
            state.deliveries.some(
                (delivery) => isActive(delivery) && delivery.payload.incidentId === incident.id,
            ),
    )
}

function retryDelay(attempts: number, key: string) {
    // Stable per-delivery jitter survives restarts and is independent of receipt timing.
    const fraction =
        createHash('sha256').update(`${key}:${attempts}`).digest().readUInt32BE() / 0xffff_ffff
    return Math.ceil(
        Math.min(
            NOTIFICATION_LIMITS.retryMaximumMs,
            NOTIFICATION_LIMITS.retryInitialMs *
                2 ** Math.max(0, attempts - 1) *
                (1 + fraction * NOTIFICATION_LIMITS.retryJitterRatio),
        ),
    )
}

export function reserveNotificationDeliverySlot(state: NotificationState) {
    if (state.deliveries.length < NOTIFICATION_LIMITS.deliveries) return true
    const oldestTerminal = state.deliveries.findIndex((delivery) => !isActive(delivery))
    if (oldestTerminal < 0) return false
    state.deliveries.splice(oldestTerminal, 1)
    return true
}

function defer(state: NotificationState) {
    state.deferredCount += 1
    state.saturationCount = Math.min(Number.MAX_SAFE_INTEGER, state.saturationCount + 1)
}

function withinStateLimit(state: NotificationState) {
    // Reserve room for persisted leases, terminal errors, and counters after admission.
    return (
        new TextEncoder().encode(JSON.stringify(state)).byteLength <=
        NOTIFICATION_LIMITS.stateBytes -
            NOTIFICATION_LIMITS.deliveries * 512 -
            NOTIFICATION_LIMITS.globalRate * 256
    )
}

export function appendNotificationIncident(
    state: NotificationState,
    configuration: NotificationEngineConfiguration,
    incident: NotificationIncident,
): boolean {
    if (state.incidents.length >= NOTIFICATION_LIMITS.incidents) {
        const resolved = state.incidents.findIndex(
            (candidate) =>
                candidate.recoveredAt !== null &&
                !recoveryOwed(candidate, configuration) &&
                !state.deliveries.some(
                    (delivery) =>
                        isActive(delivery) && delivery.payload.incidentId === candidate.id,
                ),
        )
        if (resolved < 0) {
            defer(state)
            return false
        }
        state.incidents.splice(resolved, 1)
    }
    state.incidents.push(incident)
    if (!withinStateLimit(state)) {
        state.incidents.pop()
        defer(state)
        return false
    }
    return true
}

function payloadCode(
    incident: NotificationIncident,
    recovery: boolean,
): NotificationPayload['code'] {
    if (recovery) return 'operation_recovered'
    switch (incident.category) {
        case 'certificate_renewal':
            return incident.code ?? 'certificate_renewal_failed'
        case 'ddns':
            return 'ddns_update_failed'
        case 'host_availability':
            return 'host_unavailable'
        case 'app_incident':
            return 'app_incident'
        default:
            return 'proxy_apply_failed'
    }
}

/**
 * What a delivery shows of an app incident. The platform renders the host name when it sends. A
 * recovery the platform caused names no host, because the app can no longer see it.
 */
function appPayload(
    app: NonNullable<NotificationIncident['app']>,
    recovery: boolean,
): AppIncidentNotification {
    const platformResolved = recovery && app.resolution !== undefined
    return {
        appName: app.appName ?? app.appId,
        categoryName: app.categoryName,
        title: app.title,
        message: app.message,
        ...(app.resource && !platformResolved ? { resource: { type: 'proxyHost' as const } } : {}),
        ...(platformResolved ? { resolution: app.resolution } : {}),
    }
}

export function admitNotificationIncidents(
    state: NotificationState,
    configuration: NotificationEngineConfiguration,
    nowMs: number,
    makeId: () => string,
    incidentId?: string,
) {
    if (!configuration.enabled || configuration.pausedAfterRestore) return
    for (const [incident, channel] of notificationAdmissionOrder(
        incidentId
            ? state.incidents.filter((candidate) => candidate.id === incidentId)
            : state.incidents,
        configuration,
    )) {
        const admission = pendingNotificationAdmission(incident, channel, nowMs)
        if (!admission) continue
        let marker = incident.channels.find(
            (item) => item.channelId === channel.id && item.channelRevision === channel.revision,
        )
        const recovery = admission === 'recovery'
        if (!reserveNotificationDeliverySlot(state)) {
            defer(state)
            continue
        }
        const id = makeId()
        const payload: NotificationPayload = {
            schemaVersion: 1,
            id,
            incidentId: incident.id,
            type: recovery ? 'recovery' : 'incident',
            category: incident.category,
            severity: recovery ? 'info' : incident.severity,
            resourceId: incident.resourceId,
            code: payloadCode(incident, recovery),
            occurredAt: new Date(
                recovery ? incident.recoveredAt! : incident.observedAt,
            ).toISOString(),
            startedAt: new Date(incident.startedAt).toISOString(),
            failures: incident.failures,
            ...(incident.host
                ? {
                      host: {
                          domain: incident.host.domain,
                          failureCode: incident.host.failureCode,
                          detectedAt: incident.host.detectedAt,
                          recoveryStartedAt: recovery ? incident.host.recoveryStartedAt : null,
                          managementPath: incident.host.managementPath,
                      },
                  }
                : {}),
            ...(incident.app ? { app: appPayload(incident.app, recovery) } : {}),
        }
        if (
            new TextEncoder().encode(JSON.stringify(payload)).byteLength >
            NOTIFICATION_LIMITS.payloadBytes
        ) {
            defer(state)
            continue
        }
        const existingMarker = marker
        const previous = marker && {
            failure: marker.failure,
            recovery: marker.recovery,
            severity: marker.severity,
        }
        if (marker && recovery) marker.recovery = 'pending'
        else if (marker) {
            // A severity rise notifies a channel again.
            marker.failure = 'pending'
            marker.severity = incident.severity
        } else {
            marker = {
                channelId: channel.id,
                channelRevision: channel.revision,
                failure: 'pending',
                recovery: null,
                ...(incident.app ? { severity: incident.severity } : {}),
            }
            incident.channels.push(marker)
        }
        state.deliveries.push({
            id,
            channelId: channel.id,
            channelRevision: channel.revision,
            payload,
            status: 'pending',
            attempts: 0,
            createdAt: nowMs,
            updatedAt: nowMs,
            nextAttemptAt: nowMs,
            leaseToken: null,
            leaseExpiresAt: null,
            error: null,
        })
        if (!withinStateLimit(state)) {
            state.deliveries.pop()
            if (existingMarker && previous) {
                existingMarker.failure = previous.failure
                existingMarker.recovery = previous.recovery
                if (previous.severity === undefined) delete existingMarker.severity
                else existingMarker.severity = previous.severity
            } else incident.channels.pop()
            defer(state)
        }
    }
}

export function observeNotificationSignals(
    state: NotificationState,
    configuration: NotificationEngineConfiguration,
    observations: readonly NotificationObservation[],
    nowMs: number,
    makeId: () => string,
): NotificationState {
    const next = structuredClone(state)
    reconcile(next, configuration, nowMs)
    for (const observation of observations.toSorted(
        (left, right) => Date.parse(left.occurredAt) - Date.parse(right.occurredAt),
    )) {
        const observedAt = Date.parse(observation.occurredAt)
        if (
            !Number.isSafeInteger(observedAt) ||
            observedAt < 0 ||
            observedAt > nowMs ||
            (observation.source === 'event' &&
                nowMs - observedAt >= NOTIFICATION_LIMITS.retentionMs) ||
            observation.resourceId.length === 0 ||
            observation.resourceId.length > 512 ||
            observation.evidence.length > 512 ||
            !Number.isSafeInteger(observation.failures) ||
            observation.failures < 0
        )
            continue
        const matching = next.incidents.filter(
            (incident) =>
                incident.category === observation.category &&
                incident.resourceId === observation.resourceId,
        )
        let current = matching.find((incident) => incident.recoveredAt === null)
        const lastObservedAt = Math.max(
            -1,
            ...matching.map((incident) => incident.recoveredAt ?? incident.observedAt),
        )
        if (observedAt < lastObservedAt) continue
        let health = observation.health
        let startedAt = observedAt
        if (observation.category === 'proxy_configuration') {
            const pending = next.proxyApplyPending
            if (pending && observedAt < pending.observedAt) continue
            if (health === 'pending') {
                if (!observation.desiredRevision || observation.desiredRevision.length > 128)
                    continue
                if (!pending || pending.desiredRevision !== observation.desiredRevision) {
                    next.proxyApplyPending = {
                        desiredRevision: observation.desiredRevision,
                        since: observedAt,
                        observedAt,
                    }
                    continue
                }
                pending.observedAt = observedAt
                if (observedAt - pending.since < NOTIFICATION_LIMITS.proxyApplyGraceMs) continue
                health = 'failing'
                startedAt = pending.since
            } else if (health === 'healthy') next.proxyApplyPending = null
        }
        if (health === 'pending') continue
        const evidence = createHash('sha256').update(observation.evidence).digest('hex')
        if (health === 'healthy' && current?.evidence === evidence) continue
        // Only an equal source timestamp can be a replay of a closed transition. The same
        // runtime state at a later time may be a new outage after a real recovery.
        if (
            !current &&
            observedAt === lastObservedAt &&
            matching.some(
                (incident) =>
                    (incident.recoveredAt ?? incident.observedAt) === observedAt &&
                    (incident.evidence === evidence || incident.recoveryEvidence === evidence),
            )
        )
            continue
        if (health === 'healthy') {
            if (current) {
                current.recoveredAt = observedAt
                current.recoveryEvidence = evidence
            }
            continue
        }
        if (
            current &&
            (current.code !== observation.code ||
                (observation.code === 'certificate_renewal_manual_dns_required' &&
                    current.evidence !== evidence))
        ) {
            // A new TXT request or a terminal failure is a distinct actionable condition.
            // Preserve an elapsed threshold when the same renewal moves from waiting to failure.
            // Supersession is silent; only an activated certificate reports recovery.
            if (
                current.code === 'certificate_renewal_manual_dns_required' &&
                observation.code === undefined
            )
                startedAt = current.startedAt
            current.recoveredAt = observedAt
            current.recoveryEvidence = evidence
            for (const delivery of next.deliveries) {
                if (delivery.payload.incidentId === current.id && delivery.status === 'pending')
                    terminate(next, delivery, 'cancelled', nowMs)
            }
            for (const marker of current.channels) marker.recovery ??= 'failed'
            current = undefined
        }
        if (current) {
            if (observation.code === undefined) delete current.code
            else current.code = observation.code
            if (current.evidence !== evidence)
                current.failures = Math.min(
                    Number.MAX_SAFE_INTEGER,
                    Math.max(current.failures + 1, observation.failures),
                )
            current.evidence = evidence
            current.observedAt = observedAt
            current.severity = observation.severity
            continue
        }
        appendNotificationIncident(next, configuration, {
            id: makeId(),
            category: observation.category,
            resourceId: observation.resourceId,
            severity: observation.severity,
            startedAt,
            observedAt,
            evidence,
            failures: Math.max(1, observation.failures),
            recoveredAt: null,
            recoveryEvidence: null,
            ...(observation.code ? { code: observation.code } : {}),
            channels: [],
        })
    }
    admitNotificationIncidents(next, configuration, nowMs, makeId)
    return next
}

export function claimNotificationDelivery(
    state: NotificationState,
    configuration: NotificationEngineConfiguration,
    nowMs: number,
    makeId: () => string,
): { state: NotificationState; delivery: NotificationClaimedDelivery | null } {
    const next = structuredClone(state)
    reconcile(next, configuration, nowMs)
    admitNotificationIncidents(next, configuration, nowMs, makeId)
    if (!configuration.enabled || configuration.pausedAfterRestore)
        return { state: next, delivery: null }
    const delivery = selectNotificationDelivery(next, configuration, nowMs)
    if (!delivery) return { state: next, delivery: null }
    const leaseToken = makeId()
    delivery.status = 'inflight'
    delivery.attempts += 1
    delivery.updatedAt = nowMs
    delivery.leaseToken = leaseToken
    delivery.leaseExpiresAt = nowMs + NOTIFICATION_LIMITS.leaseMs
    return {
        state: next,
        delivery: {
            id: delivery.id,
            channelId: delivery.channelId,
            channelRevision: delivery.channelRevision,
            payload: structuredClone(delivery.payload),
            leaseToken,
        },
    }
}

export function finishNotificationDelivery(
    state: NotificationState,
    configuration: NotificationEngineConfiguration,
    leaseToken: string,
    result: NotificationDeliveryResult,
    nowMs: number,
): NotificationState {
    const next = structuredClone(state)
    const delivery = next.deliveries.find(
        (item) =>
            item.status === 'inflight' &&
            item.leaseToken === leaseToken &&
            item.leaseExpiresAt !== null &&
            item.leaseExpiresAt > nowMs,
    )
    if (delivery) {
        delivery.updatedAt = nowMs
        delivery.leaseToken = null
        delivery.leaseExpiresAt = null
        if (result.success) {
            delivery.status = 'succeeded'
            delivery.error = null
            markTerminal(next, delivery)
        } else if (isSupersededManualDelivery(next, delivery)) {
            terminate(next, delivery, 'cancelled', nowMs)
        } else {
            delivery.error = result.code
            const channelAllowed =
                configuration.enabled &&
                !configuration.pausedAfterRestore &&
                configuration.channels.some(
                    (channel) =>
                        channel.enabled &&
                        channel.id === delivery.channelId &&
                        channel.revision === delivery.channelRevision &&
                        channelAcceptsDelivery(next, delivery, channel),
                )
            const terminalCode = [
                'destination_blocked',
                'redirect_denied',
                'payload_limit',
                'configuration_unavailable',
            ].includes(result.code)
            if (
                result.retryable &&
                delivery.payload.type !== 'test' &&
                !terminalCode &&
                channelAllowed &&
                delivery.attempts < NOTIFICATION_LIMITS.attempts &&
                nowMs - deliveryLifetimeStartedAt(delivery) < NOTIFICATION_LIMITS.deliveryLifetimeMs
            ) {
                delivery.status = 'pending'
                const retryAfter =
                    result.retryAfterMs !== undefined && Number.isFinite(result.retryAfterMs)
                        ? Math.max(0, result.retryAfterMs)
                        : 0
                delivery.nextAttemptAt =
                    nowMs +
                    Math.min(
                        NOTIFICATION_LIMITS.retryMaximumMs,
                        Math.max(retryDelay(delivery.attempts, delivery.id), retryAfter),
                    )
            } else {
                delivery.status = 'failed'
                markTerminal(next, delivery)
            }
        }
    }
    reconcile(next, configuration, nowMs)
    return next
}

/** An app incident's resource ID names the installation, so the status shows its incident ID. */
function visibleResourceId(
    category: NotificationIncident['category'],
    resourceId: string,
    incidentId: string,
) {
    return category === 'app_incident' ? incidentId : resourceId
}

export function summarizeNotificationState(
    state: NotificationState,
    nowMs = Date.now(),
): NotificationStatus {
    return {
        incidents: state.incidents.map(
            ({
                evidence: _evidence,
                recoveryEvidence: _recoveryEvidence,
                channels: _channels,
                // App text and installation IDs stay out of the status that channel owners read.
                app: _app,
                ...incident
            }) => {
                incident.resourceId = visibleResourceId(
                    incident.category,
                    incident.resourceId,
                    incident.id,
                )
                return incident
            },
        ),
        deliveries: state.deliveries.slice(-50).map((delivery) => ({
            id: delivery.id,
            incidentId: delivery.payload.incidentId,
            channelId: delivery.channelId,
            channelRevision: delivery.channelRevision,
            type: delivery.payload.type,
            category: delivery.payload.category,
            resourceId: visibleResourceId(
                delivery.payload.category,
                delivery.payload.resourceId,
                delivery.payload.incidentId,
            ),
            status: delivery.status,
            attempts: delivery.attempts,
            updatedAt: delivery.updatedAt,
            error: delivery.error,
        })),
        deferredCount: state.deferredCount,
        saturationCount: state.saturationCount,
        pendingCount: state.deliveries.filter(isActive).length,
        activeCount: state.deliveries.filter((delivery) => delivery.status === 'inflight').length,
        exhaustedCount: state.deliveries.filter(
            (delivery) =>
                delivery.status === 'failed' && delivery.attempts >= NOTIFICATION_LIMITS.attempts,
        ).length,
        terminalCount: state.deliveries.filter((delivery) => !isActive(delivery)).length,
        oldestPendingAgeMs: state.deliveries.some(isActive)
            ? Math.max(
                  0,
                  nowMs -
                      Math.min(
                          ...state.deliveries
                              .filter(isActive)
                              .map((delivery) => delivery.createdAt),
                      ),
              )
            : null,
    }
}
