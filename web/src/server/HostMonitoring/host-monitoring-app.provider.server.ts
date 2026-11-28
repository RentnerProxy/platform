import '@tanstack/react-start/server-only'

import { randomUUID } from 'node:crypto'
import { z } from 'zod'
import { HOST_MONITORING_APP } from '@/config/host-monitoring.config.ts'
import { appRecordId } from '@/server/AppRuntime/contract.ts'
import { nativeAppRuntimeJson } from '@/server/AppRuntime/ui/transport.server.ts'
import type { MonitoringSample } from './host-monitoring-app.mapping.ts'

const timestamp = z.iso.datetime({ precision: 3 })
const latency = z.number().int().min(0).max(600_000).nullable().optional()
const base = { serviceId: appRecordId, observedAt: timestamp, proxyHostId: appRecordId.optional() }

/** The App SDK 1.2 sample: a state must agree with `healthy`; extra fields are allowed. */
const sampleSchema = z.union([
    z.looseObject({
        ...base,
        healthy: z.boolean(),
        state: z.never().optional(),
        latencyMs: latency,
    }),
    z.looseObject({
        ...base,
        healthy: z.literal(true),
        state: z.literal('healthy'),
        latencyMs: latency,
    }),
    z.looseObject({
        ...base,
        healthy: z.literal(false),
        state: z.enum(['unhealthy', 'unknown', 'stale']),
        latencyMs: latency,
    }),
])

export const monitoringResultSchema = z.looseObject({
    profile: z.literal('monitoring'),
    payload: z.looseObject({
        samples: z.array(sampleSchema).max(HOST_MONITORING_APP.providerLimit),
    }),
})

export interface MonitoringProviderTarget {
    readonly installationId: string
    readonly generation: number
    readonly providerId: string
}

/** Invoke the live generation's monitoring provider through core: bounded, keyed, and checked. */
export async function invokeMonitoringProvider(
    target: MonitoringProviderTarget,
    limit: number,
    signal: AbortSignal,
): Promise<MonitoringSample[]> {
    const result = await nativeAppRuntimeJson(
        monitoringResultSchema,
        `/v1/providers/${target.installationId}/${target.providerId}`,
        signal,
        {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'Idempotency-Key': randomUUID() },
            body: JSON.stringify({ profile: 'monitoring', payload: { limit } }),
        },
        HOST_MONITORING_APP.resultLimitBytes,
    )
    // The result must answer the invocation: never more samples than requested.
    if (result.payload.samples.length > limit) throw new TypeError('Too many samples.')
    return result.payload.samples as MonitoringSample[]
}

export type MonitoringSampleResult =
    { readonly ok: true; readonly samples: readonly MonitoringSample[] } | { readonly ok: false }

interface CacheOptions {
    readonly ttlMs: number
    readonly failureTtlMs: number
    readonly timeoutMs: number
    readonly maxEntries: number
    readonly now: () => number
}

const defaultOptions: CacheOptions = {
    ttlMs: HOST_MONITORING_APP.cacheTtlMs,
    failureTtlMs: HOST_MONITORING_APP.failureTtlMs,
    timeoutMs: HOST_MONITORING_APP.timeoutMs,
    maxEntries: HOST_MONITORING_APP.maxCachedInstallations,
    now: Date.now,
}

/**
 * Remember the answer of each provider briefly and let concurrent requests share one call. A
 * failure, including a timeout, is remembered as well, so a failing app is not called for each
 * poll. The call has its own deadline: one requester leaving never cancels it for the others.
 */
export function createMonitoringSampleCache(options: Partial<CacheOptions> = {}) {
    const settings = { ...defaultOptions, ...options }
    const entries = new Map<string, { expiresAt: number; result: MonitoringSampleResult }>()
    const calls = new Map<string, Promise<MonitoringSampleResult>>()

    async function call(
        key: string,
        load: (signal: AbortSignal) => Promise<readonly MonitoringSample[]>,
    ): Promise<MonitoringSampleResult> {
        const controller = new AbortController()
        const timer = setTimeout(() => controller.abort(), settings.timeoutMs)
        const aborted = new Promise<never>((_resolve, reject) =>
            controller.signal.addEventListener('abort', () => reject(new Error('Timed out.')), {
                once: true,
            }),
        )
        let result: MonitoringSampleResult
        try {
            result = { ok: true, samples: await Promise.race([load(controller.signal), aborted]) }
        } catch {
            result = { ok: false }
        } finally {
            clearTimeout(timer)
            controller.abort()
        }
        const now = settings.now()
        for (const [name, entry] of entries) if (entry.expiresAt <= now) entries.delete(name)
        while (entries.size >= settings.maxEntries) {
            const oldest = entries.keys().next().value
            if (oldest === undefined) break
            entries.delete(oldest)
        }
        entries.set(key, {
            expiresAt: now + (result.ok ? settings.ttlMs : settings.failureTtlMs),
            result,
        })
        return result
    }

    return {
        read(
            key: string,
            load: (signal: AbortSignal) => Promise<readonly MonitoringSample[]>,
        ): Promise<MonitoringSampleResult> {
            const cached = entries.get(key)
            if (cached && cached.expiresAt > settings.now()) return Promise.resolve(cached.result)
            const running = calls.get(key)
            if (running) return running
            const started = call(key, load).finally(() => calls.delete(key))
            calls.set(key, started)
            return started
        },
        clear() {
            entries.clear()
        },
    }
}

export const monitoringSampleCache = createMonitoringSampleCache()
