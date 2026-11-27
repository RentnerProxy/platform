/** One probe of a batch: a covered host, one of its domains and the upstream deadline. */
export interface AppUpstreamProbeTarget {
    readonly hostId: string
    readonly domain: string
    readonly timeoutMs: number
}

export interface AppUpstreamProbeBatch {
    readonly probes: readonly AppUpstreamProbeTarget[]
}

/** The first stage that prevented a usable upstream response. */
export interface AppUpstreamProbeFailure {
    readonly stage: 'configuration' | 'tls' | 'upstream'
    readonly code: string
}

/** Why the platform did not run a probe or discarded its result. */
export type AppUpstreamProbeRefusal =
    | 'scopeDenied'
    | 'hostRemoved'
    | 'hostDisabled'
    | 'domainNotFound'
    | 'configurationChanged'
    | 'busy'
    | 'rateLimited'
    | 'unavailable'

export type AppUpstreamProbeOutcome =
    | {
          readonly outcome: 'probed'
          readonly hostId: string
          readonly domain: string
          /** Equals the listing's probe revision when the probe ran. */
          readonly probeRevision: string
          readonly durationMs: number
          readonly httpStatus: number | null
          readonly failure: AppUpstreamProbeFailure | null
      }
    | {
          readonly outcome: AppUpstreamProbeRefusal
          readonly hostId: string
          readonly domain: string
      }

export interface AppUpstreamProbeBatchResult {
    readonly results: readonly AppUpstreamProbeOutcome[]
}
