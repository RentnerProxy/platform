import { describe, expect, test } from 'bun:test'
import { HOST_MONITORING_APP } from '@/config/host-monitoring.config.ts'
import {
    mapMonitoringSamples,
    type MonitoringSample,
} from '@/server/HostMonitoring/host-monitoring-app.mapping.ts'

const now = Date.parse('2026-11-28T12:00:00.000Z')
const iso = (offsetMs: number) => new Date(now + offsetMs).toISOString()
const platformHost = '0198d98a-0000-7000-8000-000000000001'
const otherHost = '0198d98a-0000-7000-8000-000000000002'
const hosts = new Map([
    [platformHost, platformHost],
    ['app-host-one', platformHost],
    [otherHost, otherHost],
])

function sample(overrides: Partial<MonitoringSample> = {}): MonitoringSample {
    return {
        serviceId: 'service-one',
        observedAt: iso(-1_000),
        healthy: true,
        proxyHostId: platformHost,
        ...overrides,
    }
}

const map = (samples: MonitoringSample[]) => mapMonitoringSamples({ samples, hosts, now })

describe('monitoring sample mapping', () => {
    test('drops samples that name no host', () => {
        const { proxyHostId: _omitted, ...withoutHost } = sample()
        expect(map([withoutHost])).toEqual([])
    })

    test('drops hosts outside the grant or the user visibility', () => {
        expect(map([sample({ proxyHostId: '0198d98a-0000-7000-8000-0000000000ff' })])).toEqual([])
        expect(map([sample({ proxyHostId: 'not-listed' })])).toEqual([])
    })

    test('resolves the app host ID of an owned host to the platform host', () => {
        expect(
            map([sample({ proxyHostId: 'app-host-one' })]).map((row) => row.proxyHostId),
        ).toEqual([platformHost])
    })

    test('keeps only the newest sample per host', () => {
        const rows = map([
            sample({ observedAt: iso(-20_000), healthy: true, latencyMs: 5 }),
            sample({ observedAt: iso(-2_000), healthy: false, state: 'unhealthy', latencyMs: 9 }),
            sample({ proxyHostId: 'app-host-one', observedAt: iso(-10_000), healthy: true }),
        ])
        expect(rows).toEqual([
            {
                proxyHostId: platformHost,
                state: 'unhealthy',
                latencyMs: 9,
                observedAt: iso(-2_000),
            },
        ])
    })

    test('uses healthy when a sample has no state', () => {
        const [healthy] = map([sample({ healthy: true, latencyMs: 12 })])
        const [unhealthy] = map([sample({ healthy: false, latencyMs: null })])
        expect(healthy).toMatchObject({ state: 'healthy', latencyMs: 12 })
        expect(unhealthy).toMatchObject({ state: 'unhealthy', latencyMs: null })
    })

    test('shows unknown when healthy contradicts the state', () => {
        const rows = [
            sample({ healthy: true, state: 'unhealthy', latencyMs: 4 }),
            sample({ healthy: false, state: 'healthy', latencyMs: 4 }),
            sample({ healthy: true, state: 'stale' }),
        ].map((item) => map([item])[0])
        expect(rows.map((row) => row?.state)).toEqual(['unknown', 'unknown', 'unknown'])
        expect(rows.every((row) => row?.latencyMs === null)).toBe(true)
    })

    test('keeps a declared unknown or stale state without a latency', () => {
        expect(map([sample({ healthy: false, state: 'unknown', latencyMs: 3 })])[0]).toMatchObject({
            state: 'unknown',
            latencyMs: null,
        })
        expect(map([sample({ healthy: false, state: 'stale', latencyMs: 3 })])[0]).toMatchObject({
            state: 'stale',
            latencyMs: null,
        })
    })

    test('never shows an old sample as healthy', () => {
        const old = iso(-HOST_MONITORING_APP.staleAfterMs - 1)
        expect(map([sample({ observedAt: old, healthy: true, latencyMs: 8 })])[0]).toMatchObject({
            state: 'stale',
            latencyMs: null,
            observedAt: old,
        })
        expect(map([sample({ observedAt: old, healthy: false })])[0]?.state).toBe('stale')
        const edge = iso(-HOST_MONITORING_APP.staleAfterMs)
        expect(map([sample({ observedAt: edge })])[0]?.state).toBe('healthy')
    })

    test('shows unknown for a timestamp in the future', () => {
        const future = iso(HOST_MONITORING_APP.futureSkewMs + 1)
        expect(map([sample({ observedAt: future, latencyMs: 8 })])).toEqual([
            { proxyHostId: platformHost, state: 'unknown', latencyMs: null, observedAt: null },
        ])
        expect(map([sample({ observedAt: iso(HOST_MONITORING_APP.futureSkewMs) })])[0]?.state).toBe(
            'healthy',
        )
    })
})
