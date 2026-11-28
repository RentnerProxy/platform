export type HostMonitoringAppState = 'healthy' | 'unhealthy' | 'unknown' | 'stale'

/** What the monitoring app reports for one proxy host, after the platform's own rules. */
export interface HostMonitoringAppHost {
    readonly proxyHostId: string
    readonly state: HostMonitoringAppState
    /** Only for a fresh healthy or unhealthy sample; null without a response or otherwise. */
    readonly latencyMs: number | null
    /** Null when the app's timestamp cannot be trusted. */
    readonly observedAt: string | null
}

export type HostMonitoringAppSummary =
    | {
          readonly status: 'available'
          /** The app that owns monitoring, for the link to its host tab. */
          readonly installationId: string
          readonly hosts: readonly HostMonitoringAppHost[]
      }
    | { readonly status: 'unavailable' }
