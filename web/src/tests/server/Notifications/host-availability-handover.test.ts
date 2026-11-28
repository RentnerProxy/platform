import { randomUUID } from 'node:crypto'
import { describe, expect, test } from 'bun:test'
import { observeAppIncident, resolveAppIncidents } from '@/server/Notifications/app-incidents.ts'
import {
    freezeHostAvailabilityIncidents,
    handOverHostAvailabilityIncident,
    observeHostAvailabilityTransition,
} from '@/server/Notifications/host-availability.ts'
import {
    claimNotificationDelivery,
    createNotificationState,
    finishNotificationDelivery,
    observeNotificationSignals,
} from '@/server/Notifications/incident-engine.ts'
import { notificationStateSchema } from '@/server/Notifications/notification-state.validation.ts'
import type { AppIncidentChange } from '@/server/Notifications/Types/app-incidents.types.ts'
import type {
    AppIncidentContext,
    NotificationEngineConfiguration,
    NotificationState,
} from '@/server/Notifications/Types/notification-state.types.ts'

const incidentId = '00000000-0000-4000-8000-000000000301'
const proxyHostId = '00000000-0000-4000-8000-000000000302'
type Events = ('host_availability' | 'app_incident')[]
const channel = (id: string, events: Events = ['host_availability', 'app_incident']) => ({
    id,
    name: 'Channel ' + id.slice(-2),
    kind: 'webhook' as const,
    revision: 1,
    enabled: true,
    events,
    minimumSeverity: 'warning' as const,
    thresholdSeconds: 0,
    recovery: true,
    ...(events.includes('app_incident') ? { appCategories: ['acme.monitoring/availability'] } : {}),
})
const both = [
    '00000000-0000-4000-8000-000000000311',
    '00000000-0000-4000-8000-000000000312',
    '00000000-0000-4000-8000-000000000313',
]
const hostOnly = '00000000-0000-4000-8000-000000000314'
const appOnly = '00000000-0000-4000-8000-000000000315'

function configure(channels: ReturnType<typeof channel>[]): NotificationEngineConfiguration {
    return { enabled: true, pausedAfterRestore: false, channels }
}

function restart(state: NotificationState) {
    return notificationStateSchema.parse(JSON.parse(JSON.stringify(state)))
}

const app: AppIncidentContext = {
    installationId: 'installation-one',
    appId: 'acme.monitoring',
    categoryId: 'availability',
    categoryName: 'Host availability',
    key: incidentId,
    title: 'Host unavailable',
    message: 'The upstream did not answer.',
    resource: { type: 'proxyHost', proxyHostId },
}

function continuation(overrides: Partial<Extract<AppIncidentChange, { kind: 'open' }>> = {}) {
    return { kind: 'open', severity: 'error', app, continues: incidentId, ...overrides } as const
}

const resolution = {
    kind: 'resolve',
    subject: { installationId: app.installationId, key: incidentId },
    continues: incidentId,
} as const

function outage(configuration: NotificationEngineConfiguration) {
    return observeHostAvailabilityTransition(
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
}

function claim(
    state: NotificationState,
    configuration: NotificationEngineConfiguration,
    at: number,
) {
    const claimed = claimNotificationDelivery(state, configuration, at, randomUUID)
    return { state: claimed.state, delivery: claimed.delivery! }
}

/** Claim every due delivery and report the channel, category and type of each. */
function sendAll(
    state: NotificationState,
    configuration: NotificationEngineConfiguration,
    at: number,
) {
    let next = state
    const sent: string[][] = []
    for (let index = 0; ; index += 1) {
        const claimed = claimNotificationDelivery(next, configuration, at + index, randomUUID)
        if (!claimed.delivery) return { state: next, sent }
        const { delivery } = claimed
        sent.push([delivery.channelId, delivery.payload.category, delivery.payload.type])
        next = finishNotificationDelivery(
            claimed.state,
            configuration,
            delivery.leaseToken,
            { success: true },
            at + index,
        )
    }
}

/** Built-in outage notices: one sent, one in flight and one waiting, on channels taking both. */
function partlySentOutage() {
    const configuration = configure(both.map((id) => channel(id)))
    let state = outage(configuration)
    const first = claim(state, configuration, 4_000)
    state = finishNotificationDelivery(
        first.state,
        configuration,
        first.delivery.leaseToken,
        { success: true },
        4_001,
    )
    const second = claim(state, configuration, 4_002)
    const sent = first.delivery.channelId
    const sending = second.delivery.channelId
    const unsent = both.find((id) => id !== sent && id !== sending)!
    return {
        configuration,
        state: restart(second.state),
        sent,
        sending,
        unsent,
        leaseToken: second.delivery.leaseToken,
    }
}

describe('a built-in host outage handed over to the monitoring app', () => {
    test('moves sent notices, waits for one in flight and announces it only where none went', () => {
        const run = partlySentOutage()
        const opened = observeAppIncident(
            run.state,
            run.configuration,
            continuation(),
            9_000,
            randomUUID,
        )
        expect(opened.result).toBe('applied')
        const next = restart(opened.state)
        const continued = next.incidents.find(({ category }) => category === 'app_incident')!
        expect(continued.startedAt).toBe(1_000)
        const marker = (id: string) => continued.channels.find(({ channelId }) => channelId === id)
        expect(marker(run.sent)).toMatchObject({ failure: 'succeeded', notified: true })
        // The in-flight send keeps its delivery and holds a placeholder until it settles.
        expect(marker(run.sending)).toMatchObject({ failure: 'pending' })
        expect(marker(run.sending)?.notified).toBeUndefined()
        expect(
            next.deliveries.find(
                ({ channelId, payload }) =>
                    channelId === run.sending && payload.category === 'host_availability',
            )?.status,
        ).toBe('inflight')
        expect(
            next.deliveries
                .filter(({ status }) => status === 'pending')
                .map(({ channelId, payload }) => [channelId, payload.category]),
        ).toEqual([[run.unsent, 'app_incident']])
        // The built-in incident waits for the in-flight send but owes none of these channels more.
        const builtIn = next.incidents.find(({ category }) => category === 'host_availability')!
        expect(builtIn.channels.every(({ recovery }) => recovery === 'failed')).toBe(true)
    })

    test('an in-flight notice that succeeds counts once, one that fails is announced again', () => {
        for (const success of [true, false]) {
            const run = partlySentOutage()
            const opened = observeAppIncident(
                run.state,
                run.configuration,
                continuation(),
                9_000,
                randomUUID,
            ).state
            const settled = observeNotificationSignals(
                finishNotificationDelivery(
                    opened,
                    run.configuration,
                    run.leaseToken,
                    success
                        ? { success: true }
                        : { success: false, code: 'destination_blocked', retryable: false },
                    9_001,
                ),
                run.configuration,
                [],
                9_002,
                randomUUID,
            )
            const appNotices = (state: NotificationState) =>
                state.deliveries
                    .filter(
                        ({ channelId, payload }) =>
                            channelId === run.sending && payload.category === 'app_incident',
                    )
                    .map(({ payload }) => payload.type)
            const continued = settled.incidents.find(({ category }) => category === 'app_incident')!
            const marker = continued.channels.find(({ channelId }) => channelId === run.sending)
            if (success) {
                expect(marker).toMatchObject({ failure: 'succeeded', notified: true })
                expect(appNotices(settled)).toEqual([])
            } else expect(appNotices(settled)).toEqual(['incident'])
            // Either way the channel hears of the end exactly once, from the continuation.
            const resolved = observeAppIncident(
                restart(sendAll(settled, run.configuration, 9_100).state),
                run.configuration,
                resolution,
                10_000,
                randomUUID,
            )
            const ends = sendAll(resolved.state, run.configuration, 10_100).sent.filter(
                ([id]) => id === run.sending,
            )
            expect(ends).toEqual([[run.sending, 'app_incident', 'recovery']])
        }
    })

    test('a channel without the app subscription keeps the built-in incident until the resolve', () => {
        const configuration = configure([
            channel(hostOnly, ['host_availability']),
            channel(both[0]!),
            channel(appOnly, ['app_incident']),
        ])
        const announced = sendAll(outage(configuration), configuration, 4_000)
        expect(announced.sent.map(([id]) => id).toSorted()).toEqual([hostOnly, both[0]].toSorted())
        const frozen = freezeHostAvailabilityIncidents(announced.state, configuration.channels)
        const opened = observeAppIncident(frozen, configuration, continuation(), 9_000, randomUUID)
        // Only the channel that never heard of the outage gets the continuation's notice.
        const continued = sendAll(restart(opened.state), configuration, 9_100)
        expect(continued.sent).toEqual([[appOnly, 'app_incident', 'incident']])
        expect(
            continued.state.incidents.find(({ category }) => category === 'host_availability')
                ?.recoveredAt,
        ).toBeNull()
        const resolved = observeAppIncident(
            continued.state,
            configuration,
            resolution,
            10_000,
            randomUUID,
        )
        const ends = sendAll(restart(resolved.state), configuration, 10_100)
        expect(ends.sent.toSorted()).toEqual(
            [
                [hostOnly, 'host_availability', 'recovery'],
                [both[0]!, 'app_incident', 'recovery'],
                [appOnly, 'app_incident', 'recovery'],
            ].toSorted(),
        )
        expect(sendAll(ends.state, configuration, 10_200).sent).toEqual([])
    })

    test('needs the exported incident on the same host and is offered only once', () => {
        const configuration = configure(both.map((id) => channel(id)))
        const state = sendAll(outage(configuration), configuration, 4_000).state
        for (const change of [
            { kind: 'open', severity: 'error', app } as const,
            continuation({ continues: randomUUID() }),
            continuation({
                app: {
                    ...app,
                    resource: {
                        type: 'proxyHost',
                        proxyHostId: '00000000-0000-4000-8000-000000000399',
                    },
                },
            }),
        ]) {
            const next = observeAppIncident(state, configuration, change, 9_000, randomUUID).state
            // Without a matching handover the app incident is a new outage and the old one stays.
            expect(
                next.incidents.find(({ category }) => category === 'host_availability')?.id,
            ).toBe(incidentId)
            expect(
                next.incidents.find(({ category }) => category === 'app_incident')?.startedAt,
            ).toBe(9_000)
        }
        const handedOver = handOverHostAvailabilityIncident(state, configuration, app, 9_000)
        expect(handedOver?.startedAt).toBe(1_000)
        expect(
            handOverHostAvailabilityIncident(handedOver!.state, configuration, app, 9_001),
        ).toBeNull()
    })

    test('a continuation the platform closes ends the built-in outage silently', () => {
        const configuration = configure([
            channel(hostOnly, ['host_availability']),
            channel(both[0]!),
        ])
        const announced = sendAll(outage(configuration), configuration, 4_000).state
        const opened = observeAppIncident(
            announced,
            configuration,
            continuation(),
            9_000,
            randomUUID,
        )
        const continued = opened.state.incidents.find(
            ({ category }) => category === 'app_incident',
        )!
        const closed = resolveAppIncidents(
            opened.state,
            new Map([[continued.id, 'appStopped']]),
            9_500,
        )
        expect(closed.incidents.some(({ category }) => category === 'host_availability')).toBe(
            false,
        )
        const notices = sendAll(
            observeNotificationSignals(closed, configuration, [], 9_600, randomUUID),
            configuration,
            9_700,
        )
        expect(notices.sent).toEqual([[both[0]!, 'app_incident', 'recovery']])
    })

    test('freezing after commit blocks new built-in notices but keeps the ones admitted', () => {
        const later = channel(hostOnly, ['host_availability'])
        const configuration = configure([channel(both[0]!)])
        const state = outage(configuration)
        const widened = configure([channel(both[0]!), later])
        const frozen = freezeHostAvailabilityIncidents(state, widened.channels)
        const sent = sendAll(
            observeNotificationSignals(frozen, widened, [], 5_000, randomUUID),
            widened,
            5_100,
        )
        expect(sent.sent).toEqual([[both[0]!, 'host_availability', 'incident']])
        expect(freezeHostAvailabilityIncidents(frozen, widened.channels)).toBe(frozen)
    })
})
