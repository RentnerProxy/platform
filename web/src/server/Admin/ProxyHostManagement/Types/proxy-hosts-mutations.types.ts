import type { ProxyUpstreamPool } from '@/lib/ProxyRuntime/Types/upstream-pool.types.ts'
import type { PermissionKey } from '@/config/Types/permissions-config.types.ts'

export type ProxyHostMutationActor =
    | string
    | {
          readonly userId: string | null
          readonly operationId: string
          readonly proxyHostId?: string
          readonly authorize: (permission: PermissionKey) => void
      }

export type ProxyHostRow = {
    upstreamPool?: ProxyUpstreamPool | null | undefined

    id: string
    forwardScheme: 'http' | 'https'
    forwardHost: string
    forwardPort: number
    enabled: boolean
    certificateId: string | null
    forceHttps: boolean
    verifyUpstreamTls: boolean
    upstreamTlsServerName: string | null
    trustedCaId: string | null
    accessPolicyId?: string | null
    createdAt: Date
    updatedAt: Date
}
