export interface AppProxyHostQuery {
    readonly limit: number
    readonly cursor?: string | undefined
}

export interface AppProxyHost {
    readonly id: string
    readonly revision: string
    readonly hostname: string
}

export interface AppProxyHostPage {
    readonly hosts: AppProxyHost[]
    readonly nextCursor?: string
}

export type AppOwnedProxyHostChange =
    | {
          readonly action: 'upsert'
          readonly hostId: string
          readonly expectedRevision: string | null
          readonly hostname: string
          readonly upstream: {
              readonly scheme: 'http' | 'https'
              readonly address: string
              readonly port: number
          }
      }
    | {
          readonly action: 'remove'
          readonly hostId: string
          readonly expectedRevision: string
      }

export interface AppUpstreamProbe {
    readonly hostId: string
    readonly timeoutMs: number
}

export type AppUpstreamProbeResult =
    | { readonly outcome: 'reachable'; readonly durationMs: number }
    | { readonly outcome: 'unreachable' | 'timedOut' }
