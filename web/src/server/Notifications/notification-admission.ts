import type {
    AppIncidentContext,
    NotificationEngineConfiguration,
    NotificationIncident,
} from './Types/notification-state.types.ts'
import { NOTIFICATION_SEVERITIES } from '@/config/notifications.config.ts'

type Channel = NotificationEngineConfiguration['channels'][number]
type Admission = readonly [NotificationIncident, Channel]

function severityRank(severity: NotificationIncident['severity']) {
    return NOTIFICATION_SEVERITIES.indexOf(severity)
}

/** The qualified key by which a channel subscribes to an app incident category. */
function appIncidentCategoryKey(app: Pick<AppIncidentContext, 'appId' | 'categoryId'>) {
    return `${app.appId}/${app.categoryId}`
}

/**
 * Whether the channel receives the incident's category at all. An app incident also needs the
 * channel's subscription to its qualified category; the other categories need only the event.
 */
export function channelAcceptsIncident(
    channel: Pick<Channel, 'events' | 'appCategories'>,
    incident: Pick<NotificationIncident, 'category' | 'app'>,
) {
    if (!channel.events.includes(incident.category)) return false
    return (
        incident.app === undefined ||
        channel.appCategories?.includes(appIncidentCategoryKey(incident.app)) === true
    )
}

export function deferredHostFailure(incident: NotificationIncident, channel: Channel) {
    return (
        incident.category === 'host_availability' &&
        incident.recoveredAt !== null &&
        incident.host?.subscriptions?.some(
            (subscription) =>
                subscription.channelId === channel.id &&
                subscription.channelRevision === channel.revision,
        ) &&
        !incident.channels.some(
            (marker) =>
                marker.channelId === channel.id && marker.channelRevision === channel.revision,
        ) &&
        channel.enabled &&
        channel.events.includes(incident.category) &&
        NOTIFICATION_SEVERITIES.indexOf(incident.severity) >=
            NOTIFICATION_SEVERITIES.indexOf(channel.minimumSeverity) &&
        incident.recoveredAt - incident.startedAt >= channel.thresholdSeconds * 1000
    )
}

export function pendingNotificationAdmission(
    incident: NotificationIncident,
    channel: Channel,
    now: number,
): 'incident' | 'recovery' | 'escalation' | null {
    if (!channel.enabled || !channelAcceptsIncident(channel, incident)) return null
    const marker = incident.channels.find(
        (item) => item.channelId === channel.id && item.channelRevision === channel.revision,
    )
    // A severity above the last failure notice of an app incident notifies the channel again.
    if (
        incident.app !== undefined &&
        incident.recoveredAt === null &&
        marker !== undefined &&
        marker.failure !== 'pending' &&
        marker.recovery === null &&
        marker.severity !== undefined &&
        severityRank(incident.severity) > severityRank(marker.severity) &&
        severityRank(incident.severity) >= severityRank(channel.minimumSeverity)
    )
        return 'escalation'
    if (incident.recoveredAt !== null && !deferredHostFailure(incident, channel)) {
        // A channel that got a failure notice is owed its recovery, also after a failed escalation.
        return (marker?.failure === 'succeeded' || marker?.notified === true) &&
            marker.recovery === null &&
            channel.recovery
            ? 'recovery'
            : null
    }
    return !marker &&
        NOTIFICATION_SEVERITIES.indexOf(incident.severity) >=
            NOTIFICATION_SEVERITIES.indexOf(channel.minimumSeverity) &&
        (incident.recoveredAt ?? now) - incident.startedAt >= channel.thresholdSeconds * 1000
        ? 'incident'
        : null
}

function* roundRobin<T>(iterators: Generator<T>[]): Generator<T> {
    let remaining = iterators
    while (remaining.length > 0) {
        const next: Generator<T>[] = []
        for (const iterator of remaining) {
            const result = iterator.next()
            if (result.done) continue
            next.push(iterator)
            yield result.value
        }
        remaining = next
    }
}

function* channelAdmissions(
    incidents: readonly NotificationIncident[],
    channel: Channel,
): Generator<Admission> {
    const categories = channel.events.map(function* (category): Generator<Admission> {
        for (const incident of incidents) {
            if (incident.category === category) yield [incident, channel]
        }
    })
    yield* roundRobin(categories)
}

// Interleave owners, their channels and categories before filling the bounded queue.
// Deferred incident markers stay unmodified and are revisited as acknowledgements free capacity.
export function notificationAdmissionOrder(
    incidents: readonly NotificationIncident[],
    configuration: NotificationEngineConfiguration,
): Generator<Admission> {
    const owners = new Map<string | undefined, Channel[]>()
    for (const channel of configuration.channels) {
        if (!channel.enabled) continue
        const channels = owners.get(channel.ownerUserId) ?? []
        channels.push(channel)
        owners.set(channel.ownerUserId, channels)
    }
    return roundRobin(
        [...owners.values()].map((channels) =>
            roundRobin(channels.map((channel) => channelAdmissions(incidents, channel))),
        ),
    )
}
