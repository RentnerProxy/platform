import { describe, expect, mock, test } from 'bun:test'

const nativeAppRuntimeJson = mock(
    async (
        _schema: unknown,
        _path: string,
        _signal: AbortSignal,
        _init: RequestInit,
        _limit: number,
    ): Promise<unknown> => ({ profile: 'monitoring', payload: { samples: [] } }),
)
await mock.module('@/server/AppRuntime/ui/transport.server.ts', () => ({
    nativeAppRuntimeJson,
}))

const { invokeMonitoringProvider } =
    await import('@/server/HostMonitoring/host-monitoring-app.provider.server.ts')

const target = { installationId: 'monitoring-app', generation: 7, providerId: 'monitor-main' }

describe('monitoring provider invocation', () => {
    test('names the generation whose grants and hosts the caller read', async () => {
        await invokeMonitoringProvider(target, 5, new AbortController().signal)
        const [, path, , init] = nativeAppRuntimeJson.mock.calls.at(-1)!
        expect(path).toBe('/v1/providers/monitoring-app/monitor-main')
        const headers = new Headers(init.headers)
        expect(headers.get('X-App-Generation')).toBe('7')
        expect(headers.get('Idempotency-Key')).toBeTruthy()
        expect(JSON.parse(String(init.body))).toEqual({
            profile: 'monitoring',
            payload: { limit: 5 },
        })
    })

    test('rejects an answer with more samples than requested', async () => {
        const sample = {
            serviceId: 'edge',
            observedAt: '2026-11-17T10:00:00.000Z',
            healthy: true,
        }
        nativeAppRuntimeJson.mockResolvedValueOnce({
            profile: 'monitoring',
            payload: { samples: [sample, sample] },
        })
        await expect(
            invokeMonitoringProvider(target, 1, new AbortController().signal),
        ).rejects.toThrow()
    })
})
