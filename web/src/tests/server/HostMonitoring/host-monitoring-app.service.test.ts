import { describe, expect, test } from 'bun:test'
import { AuthDomainError } from '@/server/Auth/Core/errors.server.ts'
import {
    createMonitoringSampleCache,
    monitoringResultSchema,
} from '@/server/HostMonitoring/host-monitoring-app.provider.server.ts'
import {
    createHostMonitoringAppService,
    type HostMonitoringAppContext,
} from '@/server/HostMonitoring/host-monitoring-app.service.server.ts'
import type { MonitoringSample } from '@/server/HostMonitoring/host-monitoring-app.mapping.ts'

const hostId = '0198d98a-0000-7000-8000-000000000001'
const now = Date.parse('2026-11-28T12:00:00.000Z')
const target = { installationId: 'monitor-app', generation: 3, providerId: 'monitor-main' }
const healthy: MonitoringSample = {
    serviceId: 'service-one',
    observedAt: new Date(now - 1_000).toISOString(),
    healthy: true,
    proxyHostId: hostId,
    latencyMs: 12,
}

const appContext = (overrides: Partial<Extract<HostMonitoringAppContext, { owner: 'app' }>> = {}) =>
    ({
        owner: 'app',
        installationId: target.installationId,
        target,
        limit: 1,
        hosts: new Map([[hostId, hostId]]),
        ...overrides,
    }) satisfies HostMonitoringAppContext

function harness(
    context: HostMonitoringAppContext,
    invoke: (limit: number, signal: AbortSignal) => Promise<readonly MonitoringSample[]>,
    cacheOptions: Parameters<typeof createMonitoringSampleCache>[0] = {},
) {
    const calls: number[] = []
    let clock = now
    const service = createHostMonitoringAppService({
        requireActor: async () => ({ id: 'actor' }),
        readContext: async () => context,
        cache: createMonitoringSampleCache({ now: () => clock, timeoutMs: 50, ...cacheOptions }),
        invoke: async (_target, limit, signal) => {
            calls.push(limit)
            return [...(await invoke(limit, signal))]
        },
        now: () => clock,
    })
    return {
        calls,
        advance: (ms: number) => {
            clock += ms
        },
        read: () => service.getAppSummary({ proxyHostIds: [hostId] }),
    }
}

describe('monitoring app summary', () => {
    test('uses the built-in path until the app owns monitoring', async () => {
        const { read, calls } = harness({ owner: 'platform' }, async () => [healthy])
        await expect(read()).rejects.toMatchObject({ code: 'not_handed_off' })
        expect(calls).toEqual([])
    })

    test('requires the view permission before anything else', async () => {
        let read = 0
        const service = createHostMonitoringAppService({
            requireActor: async () => {
                throw new AuthDomainError('permission_denied', 'Denied')
            },
            readContext: async () => {
                read += 1
                return appContext()
            },
            cache: createMonitoringSampleCache(),
            invoke: async () => [],
            now: () => now,
        })
        await expect(service.getAppSummary({ proxyHostIds: [hostId] })).rejects.toMatchObject({
            code: 'permission_denied',
        })
        expect(read).toBe(0)
    })

    test('reports the app state with the requested limit', async () => {
        const { read, calls } = harness(appContext({ limit: 7 }), async () => [healthy])
        expect(await read()).toEqual({
            status: 'available',
            installationId: target.installationId,
            hosts: [
                {
                    proxyHostId: hostId,
                    state: 'healthy',
                    latencyMs: 12,
                    observedAt: healthy.observedAt,
                },
            ],
        })
        expect(calls).toEqual([7])
    })

    test('is unavailable when the app cannot be called', async () => {
        const { read, calls } = harness(appContext({ target: null }), async () => [healthy])
        expect(await read()).toEqual({ status: 'unavailable' })
        expect(calls).toEqual([])
    })

    test('is unavailable when the provider fails or times out', async () => {
        const failing = harness(appContext(), async () => {
            throw new Error('app stopped')
        })
        expect(await failing.read()).toEqual({ status: 'unavailable' })
        const hanging = harness(appContext(), () => new Promise(() => undefined))
        expect(await hanging.read()).toEqual({ status: 'unavailable' })
    })

    test('does not call the app without a host it may report on', async () => {
        const { read, calls } = harness(appContext({ hosts: new Map() }), async () => [healthy])
        expect(await read()).toEqual({
            status: 'available',
            installationId: target.installationId,
            hosts: [],
        })
        expect(calls).toEqual([])
    })

    test('bounds the calls with a cache and shows nothing old as healthy', async () => {
        const { read, calls, advance } = harness(appContext(), async () => [healthy], {
            ttlMs: 20_000,
        })
        await read()
        advance(19_000)
        const cached = await read()
        expect(calls).toHaveLength(1)
        // The sample was fresh when fetched; the cache does not extend its freshness.
        expect(cached).toMatchObject({ status: 'available' })
        advance(2_000)
        await read()
        expect(calls).toHaveLength(2)
    })

    test('remembers a failure briefly, then asks again', async () => {
        let fail = true
        const { read, calls, advance } = harness(
            appContext(),
            async () => {
                if (fail) throw new Error('app failing')
                return [healthy]
            },
            { failureTtlMs: 5_000 },
        )
        expect(await read()).toEqual({ status: 'unavailable' })
        expect(await read()).toEqual({ status: 'unavailable' })
        expect(calls).toHaveLength(1)
        fail = false
        advance(5_001)
        expect(await read()).toMatchObject({ status: 'available' })
        expect(calls).toHaveLength(2)
    })

    test('lets concurrent requests share one call', async () => {
        const pending = Promise.withResolvers<MonitoringSample[]>()
        const { read, calls } = harness(appContext(), () => pending.promise, { timeoutMs: 1_000 })
        const requests = [read(), read(), read(), read()]
        // The shared call starts after the requests read their context.
        await Bun.sleep(10)
        pending.resolve([healthy])
        const results = await Promise.all(requests)
        expect(calls).toHaveLength(1)
        expect(new Set(results.map((result) => result.status))).toEqual(new Set(['available']))
    })
})

const result = (samples: unknown[]) => ({ profile: 'monitoring', payload: { samples } })

describe('monitoring provider result', () => {
    const sample = {
        serviceId: 'service-one',
        observedAt: '2026-11-28T12:00:00.000Z',
        healthy: true,
    }

    test('accepts the App SDK 1.2 samples and extra fields', () => {
        const parsed = monitoringResultSchema.safeParse({
            ...result([
                sample,
                { ...sample, state: 'healthy', latencyMs: 0, extra: 1 },
                { ...sample, healthy: false, state: 'stale', latencyMs: null },
                { ...sample, healthy: false, state: 'unknown', proxyHostId: 'host-a' },
            ]),
            extra: true,
        })
        expect(parsed.success).toBe(true)
    })

    test('rejects a result that is invalid or contradicts the contract', () => {
        for (const bad of [
            result([{ ...sample, healthy: true, state: 'unhealthy' }]),
            result([{ ...sample, healthy: false, state: 'healthy' }]),
            result([{ ...sample, state: 'degraded' }]),
            result([{ ...sample, latencyMs: -1 }]),
            result([{ ...sample, latencyMs: 600_001 }]),
            result([{ ...sample, observedAt: 'yesterday' }]),
            result([{ ...sample, observedAt: '2026-11-28T12:00:00Z' }]),
            result([{ serviceId: 'service-one' }]),
            result(Array.from({ length: 1_001 }, () => sample)),
            { profile: 'dns', payload: { samples: [] } },
            { profile: 'monitoring', payload: {} },
        ])
            expect(monitoringResultSchema.safeParse(bad).success).toBe(false)
        expect(
            monitoringResultSchema.safeParse(result(Array.from({ length: 1_000 }, () => sample)))
                .success,
        ).toBe(true)
    })
})
