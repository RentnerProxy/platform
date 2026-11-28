import { createHash } from 'node:crypto'
import { NotificationDomainError } from './notification.errors.ts'
import { channelAcceptsIncident } from './notification-admission.ts'
import {
    appendNotificationIncident,
    admitNotificationIncidents,
    observeNotificationSignals,
} from './incident-engine.ts'
import type {
    AppIncidentContext,
    HostAvailabilityNotificationTransition,
    NotificationEngineConfiguration,
    NotificationIncident,
    NotificationState,
} from './Types/notification-state.types.ts'

export function cancelHostAvailabilityIncidents(
    state: NotificationState,
    incidentIds: ReadonlySet<string>,
    now: number,
): NotificationState {
    if (incidentIds.size === 0) return state
    const next = structuredClone(state)
    next.incidents = next.incidents.filter(
        (incident) => incident.category !== 'host_availability' || !incidentIds.has(incident.id),
    )
    for (const delivery of next.deliveries) {
        if (
            delivery.payload.category === 'host_availability' &&
            incidentIds.has(delivery.payload.incidentId) &&
            (delivery.status === 'pending' || delivery.status === 'inflight')
        ) {
            delivery.status = 'cancelled'
            delivery.error = 'cancelled'
            delivery.updatedAt = now
            delivery.leaseToken = null
            delivery.leaseExpiresAt = null
        }
    }
    return next
}

/**
 * The open built-in host outage an app incident continues after the monitoring handoff: its key is
 * the exported incident ID and it names the same host.
 */
export function findContinuedHostAvailabilityIncident(
    state: NotificationState,
    app: Pick<AppIncidentContext, 'key' | 'resource'>,
): NotificationIncident | undefined {
    const proxyHostId = app.resource?.proxyHostId
    if (proxyHostId === undefined) return undefined
    return state.incidents.find(
        (candidate) =>
            candidate.category === 'host_availability' &&
            candidate.id === app.key &&
            candidate.resourceId === proxyHostId &&
            candidate.recoveredAt === null,
    )
}

type Channel = NotificationEngineConfiguration['channels'][number]

const sameChannel =
    (channel: { id: string; revision: number }) =>
    (item: { channelId: string; channelRevision: number }) =>
        item.channelId === channel.id && item.channelRevision === channel.revision

/** Block every notice of the outage to a channel it never admitted, and owe that channel nothing. */
type FrozenChannel = Pick<Channel, 'id' | 'revision' | 'events' | 'appCategories'>

function blockUnadmitted(incident: NotificationIncident, channels: readonly FrozenChannel[]) {
    let changed = false
    for (const channel of channels) {
        if (
            !channelAcceptsIncident(channel, incident) ||
            incident.channels.some(sameChannel(channel))
        )
            continue
        incident.channels.push({
            channelId: channel.id,
            channelRevision: channel.revision,
            failure: 'failed',
            recovery: 'failed',
        })
        changed = true
    }
    return changed
}

/**
 * Stop built-in host outages from announcing themselves anew once an app committed monitoring. An
 * open outage keeps the notices it already admitted, sent or not, and the recovery it owes for them;
 * a channel it never admitted hears of the outage only from the app's continuation.
 */
export function freezeHostAvailabilityIncidents(
    state: NotificationState,
    channels: readonly FrozenChannel[],
): NotificationState {
    const next = structuredClone(state)
    let changed = false
    for (const incident of next.incidents)
        if (incident.category === 'host_availability' && incident.recoveredAt === null)
            changed = blockUnadmitted(incident, channels) || changed
    return changed ? next : state
}

/**
 * Hand an open built-in host outage over to the app incident that continues it after the monitoring
 * handoff, so every channel hears of the outage once and of its end once.
 *
 * A channel that accepts the continuation (the app incident event and its category) moves to it. A
 * delivered outage notice counts as the continuation's failure notice. A notice still in flight
 * leaves a pending placeholder that blocks the continuation's own notice until the send settles:
 * a success completes it, a final failure removes it so the continuation announces the outage. Any
 * unsent notice is cancelled and the continuation announces the outage instead. The built-in
 * incident keeps a marker for the channel that blocks notices of its own and owes it no recovery.
 *
 * Every other channel that got or is getting the outage notice stays with the built-in incident. It
 * stays open for them, and for notices still in flight, until the app resolves the continuation,
 * and then sends them its normal recovery notice. Without such a channel it ends silently at once.
 */
export function handOverHostAvailabilityIncident(
    state: NotificationState,
    configuration: NotificationEngineConfiguration,
    app: AppIncidentContext,
    now: number,
): {
    readonly state: NotificationState
    readonly startedAt: number
    readonly channels: NotificationIncident['channels']
} | null {
    const found = findContinuedHostAvailabilityIncident(state, app)
    if (!found) return null
    const next = structuredClone(state)
    const incident = next.incidents.find((candidate) => candidate.id === found.id)!
    const continuation = { category: 'app_incident' as const, app }
    const channels: NotificationIncident['channels'] = []
    let sendingToContinuation = false
    for (const channel of configuration.channels) {
        if (!channelAcceptsIncident(channel, continuation)) continue
        const deliveries = next.deliveries.filter(
            (delivery) =>
                delivery.payload.incidentId === incident.id && sameChannel(channel)(delivery),
        )
        const sending = deliveries.some(
            (delivery) => delivery.payload.type === 'incident' && delivery.status === 'inflight',
        )
        const marker = incident.channels.find(sameChannel(channel))
        // A marker that already owes no recovery was handed over before; its channel heard the end.
        if (marker && marker.recovery === null) {
            if (marker.failure === 'succeeded' || marker.notified === true)
                channels.push({
                    channelId: channel.id,
                    channelRevision: channel.revision,
                    failure: 'succeeded',
                    recovery: null,
                    severity: incident.severity,
                    notified: true,
                })
            else if (sending) {
                channels.push({
                    channelId: channel.id,
                    channelRevision: channel.revision,
                    failure: 'pending',
                    recovery: null,
                    severity: incident.severity,
                })
                sendingToContinuation = true
            }
        }
        for (const delivery of deliveries) {
            if (delivery.status !== 'pending') continue
            delivery.status = 'cancelled'
            delivery.error = 'cancelled'
            delivery.updatedAt = now
        }
        if (marker) {
            if (marker.failure === 'pending' && !sending) marker.failure = 'failed'
            marker.recovery = 'failed'
        }
    }
    // Nothing new starts from the built-in incident after the handover either.
    blockUnadmitted(incident, configuration.channels)
    const owesOthers = incident.channels.some(
        (marker) =>
            marker.recovery === null && (marker.failure !== 'failed' || marker.notified === true),
    )
    return {
        state:
            owesOthers || sendingToContinuation
                ? next
                : cancelHostAvailabilityIncidents(next, new Set([incident.id]), now),
        startedAt: incident.startedAt,
        channels,
    }
}

/**
 * End the built-in outage an app resolved through its continuation, with the built-in recovery
 * notice for the channels that stayed with it. The caller admits the notices afterwards.
 */
export function recoverContinuedHostAvailabilityIncident(
    state: NotificationState,
    app: Pick<AppIncidentContext, 'key' | 'resource'>,
    now: number,
): void {
    const incident = findContinuedHostAvailabilityIncident(state, app)
    if (!incident?.host) return
    incident.recoveredAt = Math.max(now, incident.observedAt)
    incident.recoveryEvidence = createHash('sha256')
        .update(`${incident.id}:recovered`)
        .digest('hex')
    incident.host = {
        ...incident.host,
        recoveryStartedAt: new Date(incident.recoveredAt).toISOString(),
    }
}

export function observeHostAvailabilityTransition(
    state: NotificationState,
    configuration: NotificationEngineConfiguration,
    transition: HostAvailabilityNotificationTransition,
    now: number,
    makeId: () => string,
): NotificationState {
    if (
        transition.kind === 'outage' &&
        (!configuration.enabled || configuration.pausedAfterRestore)
    )
        return state
    let next = structuredClone(state)
    if (transition.kind === 'outage') {
        if (next.incidents.some((incident) => incident.id === transition.incidentId)) return state
        next = cancelHostAvailabilityIncidents(
            next,
            new Set(
                next.incidents
                    .filter(
                        (incident) =>
                            incident.category === 'host_availability' &&
                            incident.resourceId === transition.proxyHostId &&
                            incident.recoveredAt === null,
                    )
                    .map((incident) => incident.id),
            ),
            now,
        )
        const admitted = appendNotificationIncident(next, configuration, {
            id: transition.incidentId,
            category: 'host_availability',
            resourceId: transition.proxyHostId,
            severity: 'error',
            startedAt: transition.startedAt,
            observedAt: transition.occurredAt,
            evidence: transition.incidentId,
            failures: transition.failures,
            recoveredAt: null,
            recoveryEvidence: null,
            channels: [],
            host: {
                ...transition.host,
                subscriptions: configuration.channels
                    .filter(
                        (channel) =>
                            channel.enabled && channel.events.includes('host_availability'),
                    )
                    .map((channel) => ({
                        channelId: channel.id,
                        channelRevision: channel.revision,
                    })),
            },
        })
        if (!admitted) throw new NotificationDomainError('configuration_unavailable')
    } else {
        // Admit a threshold-qualified outage before closing it, even when the sender was offline.
        const incident = next.incidents.find(
            (candidate) => candidate.id === transition.incidentId && candidate.host,
        )
        if (!incident || incident.recoveredAt !== null) return next
        const subscriptions =
            configuration.enabled && !configuration.pausedAfterRestore
                ? (incident.host?.subscriptions ?? []).filter((subscription) =>
                      configuration.channels.some(
                          (channel) =>
                              channel.enabled &&
                              channel.events.includes('host_availability') &&
                              channel.id === subscription.channelId &&
                              channel.revision === subscription.channelRevision,
                      ),
                  )
                : []
        if (!configuration.enabled || configuration.pausedAfterRestore)
            for (const marker of incident.channels) marker.recovery ??= 'failed'
        admitNotificationIncidents(
            next,
            {
                ...configuration,
                channels: configuration.channels.filter((channel) =>
                    subscriptions.some(
                        (subscription) =>
                            subscription.channelId === channel.id &&
                            subscription.channelRevision === channel.revision,
                    ),
                ),
            },
            transition.occurredAt,
            makeId,
            incident.id,
        )
        incident.recoveredAt = transition.occurredAt
        incident.recoveryEvidence = createHash('sha256')
            .update(`${transition.incidentId}:recovered`)
            .digest('hex')
        incident.host = { ...transition.host, subscriptions }
    }
    return observeNotificationSignals(next, configuration, [], now, makeId)
}
