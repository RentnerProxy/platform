import { randomUUID } from 'node:crypto'
import { describe, expect, test } from 'bun:test'
import { observeAppIncident } from '@/server/Notifications/app-incidents.ts'
import {
    handOverHostAvailabilityIncident,
    observeHostAvailabilityTransition,
} from '@/server/Notifications/host-availability.ts'
import {
    claimNotificationDelivery,
    createNotificationState,
    finishNotificationDelivery,
} from '@/server/Notifications/incident-engine.ts'
import { notificationStateSchema } from '@/server/Notifications/notification-state.validation.ts'
import type { AppIncidentChange } from '@/server/Notifications/Types/app-incidents.types.ts'
import type {
    NotificationEngineConfiguration,
    NotificationState,
} from '@/server/Notifications/Types/notification-state.types.ts'

const incidentId = '00000000-0000-4000-8000-000000000301'
const proxyHostId = '00000000-0000-4000-8000-000000000302'
const channel = (id: string) => ({
    id,
    name: 'Host and app incidents ' + id.slice(-1),
    kind: 'webhook' as const,
    revision: 1,
    enabled: true,
    events: ['host_availability' as const, 'app_incident' as const],
    minimumSeverity: 'warning' as const,
    thresholdSeconds: 0,
    recovery: true,
    appCategories: ['acme.monitoring/availability'],
})
const channelIds = [
    '00000000-0000-4000-8000-000000000311',
    '00000000-0000-4000-8000-000000000312',
    '00000000-0000-4000-8000-000000000313',
]
const configuration: NotificationEngineConfiguration = {
    enabled: true,
    pausedAfterRestore: false,
    channels: channelIds.map(channel),
}

function restart(state: NotificationState) {
    return notificationStateSchema.parse(JSON.parse(JSON.stringify(state)))
}

/** A built-in outage whose notice reached one channel, is in flight to one and waits for one. */
function builtInOutage() {
    let state = observeHostAvailabilityTransition(
        createNotificationState(),
        configuration,
        {
            kind: 'outage',
            incidentId,
            proxyHostId,
            startedAt: 1_000,
            occurredAt: 3_000,
            failures: 3,
            host: {
                policyId: '00000000-0000-4000-8000-000000000303',
                policyVersion: '00000000-0000-4000-8000-000000000304',
                contextProof: 'sha256:' + 'a'.repeat(64),
                contextRevision: 'sha256:' + 'b'.repeat(64),
                domain: 'service.example.test',
                failureCode: 'upstream_timeout',
                detectedAt: new Date(3_000).toISOString(),
                recoveryStartedAt: null,
                managementPath: '/proxy-hosts',
            },
        },
        3_000,
        randomUUID,
    )
    expect(state.deliveries.map(({ channelId }) => channelId).toSorted()).toEqual(channelIds)
    const claim = (now: number) => {
        const claimed = claimNotificationDelivery(state, configuration, now, randomUUID)
        state = claimed.state
        return claimed.delivery!
    }
    const delivered = claim(4_000)
    state = finishNotificationDelivery(
        state,
        configuration,
        delivered.leaseToken,
        { success: true },
        4_001,
    )
    const inFlight = claim(4_002)
    const sent = delivered.channelId
    const sending = inFlight.channelId
    const unsent = channelIds.find((id) => id !== sent && id !== sending)!
    return { state: restart(state), sent, sending, unsent }
}

function continuation(continues?: string, resource = proxyHostId): AppIncidentChange {
    return {
        kind: 'open',
        severity: 'error',
        app: {
            installationId: 'installation-one',
            appId: 'acme.monitoring',
            categoryId: 'availability',
            categoryName: 'Host availability',
            key: incidentId,
            title: 'Host unavailable',
            message: 'The upstream did not answer.',
            resource: { type: 'proxyHost', proxyHostId: resource },
        },
        ...(continues === undefined ? {} : { continues }),
    }
}

describe('a built-in host outage handed over to the monitoring app', () => {
    test('keeps every notice already sent or in flight and announces the outage only where none went', () => {
        const { state, sent, sending, unsent } = builtInOutage()
        const outcome = observeAppIncident(
            state,
            configuration,
            continuation(incidentId),
            9_000,
            randomUUID,
        )
        expect(outcome.result).toBe('applied')
        const next = restart(outcome.state)
        expect(next.incidents.some(({ category }) => category === 'host_availability')).toBe(false)
        const app = next.incidents.find(({ category }) => category === 'app_incident')!
        // The outage keeps its start; only the channel whose notice was never attempted hears of it.
        expect(app.startedAt).toBe(1_000)
        expect(app.channels.map(({ channelId }) => channelId).toSorted()).toEqual(channelIds)
        expect(
            app.channels
                .filter(({ notified }) => notified)
                .map(({ channelId }) => channelId)
                .toSorted(),
        ).toEqual([sent, sending].toSorted())
        const active = next.deliveries.filter(({ status }) => status === 'pending')
        expect(active.map(({ channelId, payload }) => [channelId, payload.category])).toEqual([
            [unsent, 'app_incident'],
        ])
        // The built-in incident's unsent notices end with it.
        expect(
            next.deliveries
                .filter(({ payload }) => payload.category === 'host_availability')
                .map(({ channelId, status }) => [channelId, status])
                .toSorted(),
        ).toEqual(
            [
                [sent, 'succeeded'],
                [sending, 'cancelled'],
                [unsent, 'cancelled'],
            ].toSorted(),
        )
    })

    test('needs the exported incident on the same host and is offered only once', () => {
        const { state } = builtInOutage()
        for (const change of [
            continuation(),
            continuation(randomUUID()),
            continuation(incidentId, '00000000-0000-4000-8000-000000000399'),
        ]) {
            const next = observeAppIncident(state, configuration, change, 9_000, randomUUID).state
            // Without a matching handover the app incident is a new outage and the old one stays.
            expect(
                next.incidents.find(({ category }) => category === 'host_availability')?.id,
            ).toBe(incidentId)
            const app = next.incidents.find(({ category }) => category === 'app_incident')!
            expect(app.startedAt).toBe(9_000)
            expect(app.channels).toHaveLength(3)
        }
        const handedOver = handOverHostAvailabilityIncident(state, incidentId, proxyHostId, 9_000)
        expect(handedOver?.startedAt).toBe(1_000)
        expect(
            handOverHostAvailabilityIncident(handedOver!.state, incidentId, proxyHostId, 9_001),
        ).toBeNull()
    })
})
