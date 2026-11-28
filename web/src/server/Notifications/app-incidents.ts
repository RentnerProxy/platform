import { createHash } from 'node:crypto'
import { APP_INCIDENT_LIMITS, NOTIFICATION_SEVERITIES } from '@/config/notifications.config.ts'
import type { AppIncidentResolution } from '@/lib/Notifications/Types/notifications.types.ts'
import {
    cancelHostAvailabilityIncidents,
    findContinuedHostAvailabilityIncident,
    handOverHostAvailabilityIncident,
    recoverContinuedHostAvailabilityIncident,
} from './host-availability.ts'
import { appendNotificationIncident, observeNotificationSignals } from './incident-engine.ts'
import type {
    AppIncidentChange,
    AppIncidentOutcome,
    AppIncidentSubject,
} from './Types/app-incidents.types.ts'
import type {
    AppIncidentContext,
    NotificationEngineConfiguration,
    NotificationIncident,
    NotificationState,
} from './Types/notification-state.types.ts'

type AppNotificationIncident = NotificationIncident & { app: AppIncidentContext }

function isOpenAppIncident(incident: NotificationIncident): incident is AppNotificationIncident {
    return incident.app !== undefined && incident.recoveredAt === null
}

/** The engine dedups on this resource: one open incident per installation and key. */
function dedupKey({ installationId, key }: AppIncidentSubject) {
    return `${installationId}:${key}`
}

function findOpen(state: NotificationState, subject: AppIncidentSubject) {
    const resourceId = dedupKey(subject)
    return state.incidents.find(
        (incident): incident is AppNotificationIncident =>
            isOpenAppIncident(incident) && incident.resourceId === resourceId,
    )
}

function evidenceOf(severity: string, app: AppIncidentContext) {
    return createHash('sha256')
        .update(JSON.stringify([severity, app.categoryId, app.title, app.message, app.resource]))
        .digest('hex')
}

function sameResource(left: AppIncidentContext['resource'], right: AppIncidentContext['resource']) {
    return left?.proxyHostId === right?.proxyHostId
}

function sameContext(left: AppIncidentContext, right: AppIncidentContext) {
    return (
        left.appId === right.appId &&
        left.appName === right.appName &&
        left.categoryId === right.categoryId &&
        left.categoryName === right.categoryName &&
        left.title === right.title &&
        left.message === right.message &&
        sameResource(left.resource, right.resource)
    )
}

/** Remove the incident and every delivery that has not been attempted, as a silent cancel. */
function discard(state: NotificationState, incident: NotificationIncident, now: number) {
    state.incidents = state.incidents.filter((candidate) => candidate.id !== incident.id)
    for (const delivery of state.deliveries) {
        if (delivery.payload.incidentId !== incident.id || delivery.status !== 'pending') continue
        delivery.status = 'cancelled'
        delivery.error = 'cancelled'
        delivery.updatedAt = now
    }
}

/**
 * Close an incident. Admission sends recovery notices to the channels that got the failure notice.
 * A resolution the platform chose is recorded on the incident and shown in that notice. An
 * unavailable resource owes no notice, because the delivery could not show it to anyone.
 */
function close(
    state: NotificationState,
    incident: AppNotificationIncident,
    now: number,
    resolution: AppIncidentResolution | undefined,
) {
    incident.recoveredAt = Math.max(now, incident.observedAt)
    incident.recoveryEvidence = createHash('sha256')
        .update(`${incident.id}:recovered`)
        .digest('hex')
    if (resolution !== undefined) incident.app.resolution = resolution
    if (resolution !== 'resourceUnavailable') return
    for (const marker of incident.channels) marker.recovery ??= 'failed'
    for (const delivery of state.deliveries) {
        if (delivery.payload.incidentId !== incident.id || delivery.status !== 'pending') continue
        delivery.status = 'cancelled'
        delivery.error = 'cancelled'
        delivery.updatedAt = now
    }
}

/** Pending notices of the incident show what the app asserted last. */
function refreshPending(state: NotificationState, incident: AppNotificationIncident) {
    for (const delivery of state.deliveries) {
        const { payload } = delivery
        if (
            payload.incidentId !== incident.id ||
            payload.type !== 'incident' ||
            delivery.status !== 'pending' ||
            payload.app === undefined
        )
            continue
        delivery.payload = {
            ...payload,
            severity: incident.severity,
            occurredAt: new Date(incident.observedAt).toISOString(),
            app: {
                ...payload.app,
                categoryName: incident.app.categoryName,
                title: incident.app.title,
                message: incident.app.message,
            },
        }
    }
}

/** An app asserts that the incident exists. Repeating the state changes nothing. */
function open(
    state: NotificationState,
    configuration: NotificationEngineConfiguration,
    change: Extract<AppIncidentChange, { kind: 'open' }>,
    now: number,
    makeId: () => string,
): AppIncidentOutcome {
    if (!configuration.enabled || configuration.pausedAfterRestore)
        return { state, result: 'unchanged' }
    let next = structuredClone(state)
    const { app, severity } = change
    let current = findOpen(next, app)
    if (current) {
        if (current.severity === severity && sameContext(current.app, app))
            return { state, result: 'unchanged' }
        if (
            current.app.categoryId !== app.categoryId ||
            !sameResource(current.app.resource, app.resource)
        ) {
            // Another category or host is another condition: the old one ends, the new one begins.
            close(next, current, now, undefined)
            current = undefined
        } else {
            const rises =
                NOTIFICATION_SEVERITIES.indexOf(severity) >
                NOTIFICATION_SEVERITIES.indexOf(current.severity)
            // A lower severity lowers what the channels were last told, so a later rise
            // notifies them again.
            if (!rises)
                for (const marker of current.channels)
                    if (
                        marker.severity !== undefined &&
                        NOTIFICATION_SEVERITIES.indexOf(marker.severity) >
                            NOTIFICATION_SEVERITIES.indexOf(severity)
                    )
                        marker.severity = severity
            current.app = { ...app }
            current.severity = severity
            current.evidence = evidenceOf(severity, app)
            current.observedAt = Math.max(now, current.observedAt)
            if (rises) current.failures = Math.min(Number.MAX_SAFE_INTEGER, current.failures + 1)
            refreshPending(next, current)
        }
    }
    if (!current) {
        // Continuations of exported built-in outages have their own bound, so the monitoring app
        // can continue every outage it took over and still raise its ordinary incidents.
        const continuations = new Set(change.continuations)
        const continuing =
            change.continues === app.key &&
            findContinuedHostAvailabilityIncident(next, app) !== undefined
        const own = next.incidents.filter(
            (incident): incident is AppNotificationIncident =>
                isOpenAppIncident(incident) && incident.app.installationId === app.installationId,
        )
        const counted = own.filter(
            (incident) => continuations.has(incident.app.key) === continuing,
        ).length
        if (
            counted >=
            (continuing
                ? APP_INCIDENT_LIMITS.openContinuationsPerInstallation
                : APP_INCIDENT_LIMITS.openPerInstallation)
        )
            return { state, result: 'limit' }
        // A continued built-in outage keeps its start and the notices its channels already got.
        const handover = continuing
            ? handOverHostAvailabilityIncident(next, configuration, app, now)
            : null
        if (handover) next = handover.state
        const admitted = appendNotificationIncident(next, configuration, {
            id: makeId(),
            category: 'app_incident',
            resourceId: dedupKey(app),
            severity,
            startedAt: handover?.startedAt ?? now,
            observedAt: now,
            evidence: evidenceOf(severity, app),
            failures: 1,
            recoveredAt: null,
            recoveryEvidence: null,
            channels: handover ? [...handover.channels] : [],
            app: { ...app },
        })
        if (!admitted) return { state, result: 'saturated' }
    }
    return {
        state: observeNotificationSignals(next, configuration, [], now, makeId),
        result: 'applied',
    }
}

/** The built-in outages the given app incidents continue; they end with their continuation. */
function continuedIds(state: NotificationState, incidents: readonly AppNotificationIncident[]) {
    return new Set(
        incidents.flatMap(({ app }) => {
            const continued = findContinuedHostAvailabilityIncident(state, app)
            return continued ? [continued.id] : []
        }),
    )
}

/** An app asserts that the incident ended. Nothing open means nothing to do. */
function resolve(
    state: NotificationState,
    configuration: NotificationEngineConfiguration,
    change: Extract<AppIncidentChange, { kind: 'resolve' }>,
    now: number,
    makeId: () => string,
): AppIncidentOutcome {
    const { subject } = change
    const current = findOpen(state, subject)
    if (!current) return { state, result: 'unchanged' }
    let next = structuredClone(state)
    const target = findOpen(next, subject)!
    const continues = change.continues === subject.key
    if (!configuration.enabled || configuration.pausedAfterRestore) {
        // Nothing is delivered while notifications are off, and the incident would be stale later.
        discard(next, target, now)
        if (continues)
            next = cancelHostAvailabilityIncidents(next, continuedIds(next, [target]), now)
        return { state: next, result: 'applied' }
    }
    close(next, target, now, undefined)
    // The channels that stayed with a continued built-in outage hear of its end from it.
    if (continues) recoverContinuedHostAvailabilityIncident(next, target.app, now)
    return {
        state: observeNotificationSignals(next, configuration, [], now, makeId),
        result: 'applied',
    }
}

/** Apply what an app asserted about one of its incidents. */
export function observeAppIncident(
    state: NotificationState,
    configuration: NotificationEngineConfiguration,
    change: AppIncidentChange,
    now: number,
    makeId: () => string,
): AppIncidentOutcome {
    return change.kind === 'open'
        ? open(state, configuration, change, now, makeId)
        : resolve(state, configuration, change, now, makeId)
}

/**
 * Close the open app incidents the platform found it cannot keep, with the reason for each. The
 * caller reads the reasons from the app tables; recovery notices follow in the next admission. A
 * built-in outage one of them continued ends silently, like a built-in outage whose monitoring
 * stopped: nothing observed that the host recovered.
 */
export function resolveAppIncidents(
    state: NotificationState,
    resolutions: ReadonlyMap<string, AppIncidentResolution>,
    now: number,
): NotificationState {
    if (resolutions.size === 0) return state
    const next = structuredClone(state)
    const closed: AppNotificationIncident[] = []
    for (const incident of next.incidents) {
        const resolution = resolutions.get(incident.id)
        if (resolution !== undefined && isOpenAppIncident(incident)) {
            close(next, incident, now, resolution)
            closed.push(incident)
        }
    }
    return cancelHostAvailabilityIncidents(next, continuedIds(next, closed), now)
}
