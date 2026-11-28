import { HOST_MONITORING_APP } from '@/config/host-monitoring.config.ts'
import type {
    HostMonitoringAppHost,
    HostMonitoringAppState,
} from '@/lib/HostMonitoring/Types/host-monitoring-app.types.ts'

/** A sample of the monitoring provider profile, as far as the platform reads it. */
export interface MonitoringSample {
    readonly serviceId: string
    readonly observedAt: string
    readonly healthy: boolean
    readonly proxyHostId?: string | undefined
    readonly state?: HostMonitoringAppState | undefined
    readonly latencyMs?: number | null | undefined
}

export interface MapMonitoringSamplesInput {
    readonly samples: readonly MonitoringSample[]
    /** The IDs a sample may name a host by, mapped to the platform host ID. Only hosts the app's grant covers and the user may view belong here. */
    readonly hosts: ReadonlyMap<string, string>
    readonly now: number
}

/**
 * The state of one sample. Freshness is the platform's own rule, so an app can never present an
 * old or future check as healthy; a state contradicting `healthy` is never trusted either.
 */
function resolve(sample: MonitoringSample, now: number, observedAt: number) {
    if (observedAt - now > HOST_MONITORING_APP.futureSkewMs)
        return { state: 'unknown', trusted: false } as const
    if (now - observedAt > HOST_MONITORING_APP.staleAfterMs)
        return { state: 'stale', trusted: false } as const
    const declared = sample.state ?? (sample.healthy ? 'healthy' : 'unhealthy')
    if (sample.state !== undefined && (sample.state === 'healthy') !== sample.healthy)
        return { state: 'unknown', trusted: false } as const
    return { state: declared, trusted: declared === 'healthy' || declared === 'unhealthy' } as const
}

/** One state per host from the samples of the app, conservatively. */
export function mapMonitoringSamples({
    samples,
    hosts,
    now,
}: MapMonitoringSamplesInput): HostMonitoringAppHost[] {
    const newest = new Map<string, { sample: MonitoringSample; observedAt: number }>()
    for (const sample of samples) {
        const hostId = sample.proxyHostId === undefined ? undefined : hosts.get(sample.proxyHostId)
        const observedAt = Date.parse(sample.observedAt)
        if (hostId === undefined || Number.isNaN(observedAt)) continue
        const current = newest.get(hostId)
        if (!current || observedAt > current.observedAt) newest.set(hostId, { sample, observedAt })
    }
    return [...newest].map(([proxyHostId, { sample, observedAt }]) => {
        const { state, trusted } = resolve(sample, now, observedAt)
        const future = observedAt - now > HOST_MONITORING_APP.futureSkewMs
        return {
            proxyHostId,
            state,
            latencyMs: trusted ? (sample.latencyMs ?? null) : null,
            observedAt: future ? null : new Date(observedAt).toISOString(),
        }
    })
}
