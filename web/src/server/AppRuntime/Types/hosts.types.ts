import type { ProxyUpstreamPool } from '@/lib/ProxyRuntime/Types/upstream-pool.types.ts'

export interface AppProxyHostQuery {
    readonly limit: number
    readonly cursor?: string | undefined
}

/** Where a host forwards requests, as an app may see it. */
export interface AppProxyHostUpstream {
    readonly scheme: 'http' | 'https'
    readonly targets: ReadonlyArray<{ readonly address: string; readonly port: number }>
    /** The failover pool's selection policy and health settings, or null without a pool. */
    readonly pool: Pick<ProxyUpstreamPool, 'policy' | 'failover'> | null
}

/** A host as app-owned operation results name it. */
export interface AppProxyHostReference {
    readonly id: string
    /** Changes with any stored host setting; app-owned changes compare against it. */
    readonly revision: string
    /** The first domain. */
    readonly hostname: string
}

export interface AppProxyHost extends AppProxyHostReference {
    /** The platform ID of a host the app owns and names by its own ID. */
    readonly platformHostId?: string
    readonly enabled: boolean
    readonly domains: readonly string[]
    readonly upstream: AppProxyHostUpstream
    /** Changes only when something an upstream probe observes changes. */
    readonly probeRevision: string
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
