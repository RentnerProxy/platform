import { randomUUID } from 'node:crypto'
import { APP_INCIDENT_LIMITS } from '@/config/notifications.config.ts'
import { describe, expect, test } from 'bun:test'
import { observeAppIncident, resolveAppIncidents } from '@/server/Notifications/app-incidents.ts'
import {
    claimNotificationDelivery,
    createNotificationState,
    finishNotificationDelivery,
    observeNotificationSignals,
    summarizeNotificationState,
} from '@/server/Notifications/incident-engine.ts'
import { notificationStateSchema } from '@/server/Notifications/notification-state.validation.ts'
import type { AppIncidentChange } from '@/server/Notifications/Types/app-incidents.types.ts'
import type {
    AppIncidentContext,
    NotificationEngineConfiguration,
    NotificationState,
} from '@/server/Notifications/Types/notification-state.types.ts'

const installationId = 'installation-one'
const proxyHostId = '00000000-0000-4000-8000-000000000002'
const channel = {
    id: '00000000-0000-4000-8000-000000000001',
    name: 'App incidents',
    kind: 'webhook' as const,
    revision: 1,
    enabled: true,
    events: ['app_incident' as const],
    minimumSeverity: 'warning' as const,
    thresholdSeconds: 0,
    recovery: true,
    appCategories: ['acme.monitor/disk'],
}
const configuration: NotificationEngineConfiguration = {
    enabled: true,
    pausedAfterRestore: false,
    channels: [channel],
}

function context(overrides: Partial<AppIncidentContext> = {}): AppIncidentContext {
    return {
        installationId,
        appId: 'acme.monitor',
        categoryId: 'disk',
        categoryName: 'Disk space',
        key: 'disk-full',
        title: 'Disk almost full',
        message: 'The data volume has 2% left.',
        resource: null,
        ...overrides,
    }
}

function open(
    severity: 'warning' | 'error' | 'critical' = 'error',
    overrides: Partial<AppIncidentContext> = {},
): AppIncidentChange {
    return { kind: 'open', severity, app: context(overrides) }
}

const resolveChange: AppIncidentChange = {
    kind: 'resolve',
    subject: { installationId, key: 'disk-full' },
}

function restart(state: NotificationState) {
    return notificationStateSchema.parse(JSON.parse(JSON.stringify(state)))
}

function apply(
    state: NotificationState,
    change: AppIncidentChange,
    now: number,
    config = configuration,
) {
    const outcome = observeAppIncident(restart(state), config, change, now, randomUUID)
    return { ...outcome, state: restart(outcome.state) }
}

/** Claim the next delivery and acknowledge it as sent. */
function send(state: NotificationState, now: number, config = configuration) {
    const claimed = claimNotificationDelivery(state, config, now, randomUUID)
    if (!claimed.delivery) return { state: claimed.state, delivery: null }
    return {
        delivery: claimed.delivery,
        state: finishNotificationDelivery(
            claimed.state,
            config,
            claimed.delivery.leaseToken,
            { success: true },
            now + 1,
        ),
    }
}

describe('app incidents in the notification engine', () => {
    test('an open incident is kept once and notifies once with its app text', () => {
        const opened = apply(createNotificationState(), open(), 10_000)
        expect(opened.result).toBe('applied')
        expect(opened.state.incidents).toHaveLength(1)
        expect(opened.state.incidents[0]).toMatchObject({
            category: 'app_incident',
            resourceId: `${installationId}:disk-full`,
            severity: 'error',
            recoveredAt: null,
        })
        expect(opened.state.deliveries).toHaveLength(1)
        expect(opened.state.deliveries[0]?.payload).toMatchObject({
            type: 'incident',
            category: 'app_incident',
            code: 'app_incident',
            severity: 'error',
            app: {
                appName: 'acme.monitor',
                categoryName: 'Disk space',
                title: 'Disk almost full',
                message: 'The data volume has 2% left.',
            },
        })
        expect(opened.state.deliveries[0]?.payload.app).not.toHaveProperty('resource')
    })

    test('repeating the same state creates no incident and no delivery', () => {
        let state = apply(createNotificationState(), open(), 10_000).state
        for (let repeat = 0; repeat < 5; repeat++) {
            const again = observeAppIncident(
                restart(state),
                configuration,
                open(),
                11_000 + repeat,
                randomUUID,
            )
            expect(again.result).toBe('unchanged')
            state = restart(again.state)
        }
        expect(state.incidents).toHaveLength(1)
        expect(state.deliveries).toHaveLength(1)
        const sent = send(state, 12_000)
        const afterSend = apply(sent.state, open(), 13_000)
        expect(afterSend.result).toBe('unchanged')
        expect(afterSend.state.deliveries).toHaveLength(1)
    })

    test('a changed title or message updates the incident in place without notifying again', () => {
        let state = apply(createNotificationState(), open(), 10_000).state
        state = apply(
            state,
            open('error', { title: 'Disk full', message: 'No space left.' }),
            11_000,
        ).state
        expect(state.incidents).toHaveLength(1)
        expect(state.incidents[0]?.app).toMatchObject({ title: 'Disk full' })
        expect(state.deliveries).toHaveLength(1)
        // The unsent notice shows the latest text.
        expect(state.deliveries[0]?.payload.app).toMatchObject({
            title: 'Disk full',
            message: 'No space left.',
        })
        const sent = send(state, 12_000)
        const later = apply(
            sent.state,
            open('error', { title: 'Disk full again', message: 'Still full.' }),
            13_000,
        )
        expect(later.state.deliveries).toHaveLength(1)
        expect(later.state.incidents[0]?.app?.title).toBe('Disk full again')
    })

    test('only a rise in severity notifies a channel again', () => {
        let state = apply(createNotificationState(), open('warning'), 10_000).state
        state = send(state, 11_000).state
        expect(state.deliveries).toHaveLength(1)
        // Falling, and staying at, a severity is quiet.
        const rise = apply(state, open('critical'), 12_000)
        expect(rise.state.deliveries.map((delivery) => delivery.payload.severity)).toEqual([
            'warning',
            'critical',
        ])
        const quiet = apply(send(rise.state, 13_000).state, open('error'), 14_000)
        expect(quiet.state.deliveries).toHaveLength(2)
        const same = apply(quiet.state, open('error'), 15_000)
        expect(same.result).toBe('unchanged')
        expect(same.state.incidents[0]?.severity).toBe('error')
        const second = apply(same.state, open('critical'), 16_000)
        expect(second.state.deliveries).toHaveLength(3)
    })

    test('resolving recovers the incident and notifies only channels that got the failure', () => {
        const quiet = {
            ...channel,
            id: '00000000-0000-4000-8000-000000000009',
            minimumSeverity: 'critical' as const,
        }
        const both = { ...configuration, channels: [channel, quiet] }
        let state = apply(createNotificationState(), open('error'), 10_000, both).state
        expect(state.deliveries.map((delivery) => delivery.channelId)).toEqual([channel.id])
        state = send(state, 11_000, both).state
        const resolved = apply(state, resolveChange, 12_000, both)
        expect(resolved.result).toBe('applied')
        expect(resolved.state.incidents[0]?.recoveredAt).toBe(12_000)
        expect(resolved.state.deliveries.map((delivery) => delivery.payload.type)).toEqual([
            'incident',
            'recovery',
        ])
        expect(resolved.state.deliveries[1]).toMatchObject({ channelId: channel.id })
        expect(resolved.state.deliveries[1]?.payload).toMatchObject({
            code: 'operation_recovered',
            severity: 'info',
            app: { title: 'Disk almost full' },
        })
    })

    test('resolving without an open incident is a no-op, also after a resolution', () => {
        const state = createNotificationState()
        const nothing = observeAppIncident(state, configuration, resolveChange, 1_000, randomUUID)
        expect(nothing.result).toBe('unchanged')
        expect(nothing.state).toBe(state)
        const resolved = apply(apply(state, open(), 2_000).state, resolveChange, 3_000)
        const again = observeAppIncident(
            resolved.state,
            configuration,
            resolveChange,
            4_000,
            randomUUID,
        )
        expect(again.result).toBe('unchanged')
        expect(again.state).toBe(resolved.state)
        // A new opening after the resolution is a new incident.
        const reopened = apply(resolved.state, open(), 5_000)
        expect(
            reopened.state.incidents.filter((incident) => incident.recoveredAt === null),
        ).toHaveLength(1)
        expect(reopened.state.incidents).toHaveLength(2)
    })

    test('a channel receives an app incident only for an event and a subscribed category', () => {
        for (const policy of [
            { ...channel, appCategories: undefined },
            { ...channel, appCategories: [] },
            { ...channel, appCategories: ['acme.monitor/other'] },
            { ...channel, appCategories: ['other.app/disk'] },
            { ...channel, events: ['ddns' as const] },
        ]) {
            const config = { ...configuration, channels: [policy] }
            const state = apply(createNotificationState(), open(), 10_000, config).state
            expect(state.incidents).toHaveLength(1)
            expect(state.deliveries).toHaveLength(0)
        }
    })

    test('an unsubscribed channel loses queued app notices', () => {
        const state = apply(createNotificationState(), open(), 10_000).state
        expect(state.deliveries).toHaveLength(1)
        const unsubscribed = { ...configuration, channels: [{ ...channel, appCategories: [] }] }
        const reconciled = observeNotificationSignals(state, unsubscribed, [], 11_000, randomUUID)
        expect(reconciled.deliveries[0]?.status).toBe('cancelled')
        expect(
            claimNotificationDelivery(state, unsubscribed, 11_000, randomUUID).delivery,
        ).toBeNull()
    })

    test('notifications that are off or paused keep no incident', () => {
        for (const config of [
            { ...configuration, enabled: false },
            { ...configuration, pausedAfterRestore: true },
        ]) {
            const state = createNotificationState()
            const outcome = observeAppIncident(state, config, open(), 10_000, randomUUID)
            expect(outcome.result).toBe('unchanged')
            expect(outcome.state).toBe(state)
        }
        // A resolution still ends what an earlier run kept.
        const kept = apply(createNotificationState(), open(), 10_000).state
        const off = apply(kept, resolveChange, 11_000, { ...configuration, enabled: false })
        expect(off.state.incidents).toHaveLength(0)
        expect(off.state.deliveries.every((delivery) => delivery.status === 'cancelled')).toBeTrue()
    })

    test('another category or host ends the old incident and opens a new one', () => {
        let state = apply(createNotificationState(), open('error'), 10_000).state
        state = apply(
            state,
            open('error', { resource: { type: 'proxyHost', proxyHostId } }),
            11_000,
        ).state
        expect(state.incidents.map((incident) => incident.recoveredAt !== null)).toEqual([
            true,
            false,
        ])
        expect(state.incidents[1]?.app?.resource).toEqual({ type: 'proxyHost', proxyHostId })
    })

    test('an installation keeps a bounded number of open incidents', () => {
        let state = createNotificationState()
        for (let index = 0; index < APP_INCIDENT_LIMITS.openPerInstallation; index++) {
            state = apply(state, open('error', { key: `incident-${index}` }), 10_000 + index).state
        }
        const over = apply(state, open('error', { key: 'one-too-many' }), 20_000)
        expect(over.result).toBe('limit')
        expect(over.state.incidents).toHaveLength(APP_INCIDENT_LIMITS.openPerInstallation)
        // Another installation is unaffected, and an existing key still updates.
        const other = apply(
            state,
            open('error', { installationId: 'installation-two', key: 'disk-full' }),
            20_001,
        )
        expect(other.result).toBe('applied')
        const update = apply(state, open('critical', { key: 'incident-0' }), 20_002)
        expect(update.result).toBe('applied')
    })

    test('the platform resolves with a reason that shows in the recovery notice', () => {
        let state = apply(
            createNotificationState(),
            open('error', { resource: { type: 'proxyHost', proxyHostId } }),
            10_000,
        ).state
        state = send(state, 11_000).state
        const incidentId = state.incidents[0]!.id
        const resolved = observeNotificationSignals(
            resolveAppIncidents(state, new Map([[incidentId, 'appStopped']]), 12_000),
            configuration,
            [],
            12_000,
            randomUUID,
        )
        expect(restart(resolved).incidents[0]?.app?.resolution).toBe('appStopped')
        const recovery = resolved.deliveries.at(-1)?.payload
        expect(recovery).toMatchObject({
            type: 'recovery',
            app: { resolution: 'appStopped' },
        })
        // A recovery the platform caused names no host.
        expect(recovery?.app).not.toHaveProperty('resource')
    })

    test('a host that became unavailable owes no recovery notice', () => {
        let state = apply(
            createNotificationState(),
            open('error', { resource: { type: 'proxyHost', proxyHostId } }),
            10_000,
        ).state
        state = send(state, 11_000).state
        const incidentId = state.incidents[0]!.id
        const resolved = observeNotificationSignals(
            resolveAppIncidents(state, new Map([[incidentId, 'resourceUnavailable']]), 12_000),
            configuration,
            [],
            12_000,
            randomUUID,
        )
        expect(resolved.incidents[0]?.app?.resolution).toBe('resourceUnavailable')
        expect(resolved.deliveries.map((delivery) => delivery.payload.type)).toEqual(['incident'])
    })

    test('the status for channel owners carries no app text or installation ID', () => {
        const state = apply(createNotificationState(), open(), 10_000).state
        const status = JSON.stringify(summarizeNotificationState(state, 11_000))
        expect(status).not.toContain('Disk almost full')
        expect(status).not.toContain('installationId')
        expect(summarizeNotificationState(state, 11_000).incidents[0]).toMatchObject({
            category: 'app_incident',
            severity: 'error',
        })
    })

    test('the state schema keeps app incident context consistent and plain', () => {
        const state = apply(createNotificationState(), open(), 10_000).state
        const incident = state.incidents[0]!
        const delivery = state.deliveries[0]!
        const broken = (change: (draft: NotificationState) => void) => {
            const draft = structuredClone(state)
            change(draft)
            return notificationStateSchema.safeParse(JSON.parse(JSON.stringify(draft))).success
        }
        expect(broken(() => undefined)).toBeTrue()
        expect(broken((draft) => delete draft.incidents[0]!.app)).toBeFalse()
        expect(
            broken((draft) => {
                const { app: _removed, ...bare } = draft.deliveries[0]!.payload
                draft.deliveries[0]!.payload = bare
            }),
        ).toBeFalse()
        expect(
            broken((draft) => {
                draft.incidents[0]!.category = 'ddns'
            }),
        ).toBeFalse()
        for (const text of [
            'x'.repeat(81),
            'see https://evil.example',
            'www.evil.example',
            'a\u0000b',
            'a‮b',
            '',
        ]) {
            expect(
                broken((draft) => {
                    draft.incidents[0]!.app!.title = text
                }),
            ).toBeFalse()
            expect(
                broken((draft) => {
                    draft.deliveries[0]!.payload = {
                        ...delivery.payload,
                        app: { ...delivery.payload.app!, title: text },
                    }
                }),
            ).toBeFalse()
        }
        expect(
            broken((draft) => {
                draft.incidents[0]!.app!.message = 'm'.repeat(401)
            }),
        ).toBeFalse()
        expect(
            broken((draft) => {
                draft.incidents[0]!.resourceId = `${incident.app!.installationId}:other`
            }),
        ).toBeFalse()
    })
})
