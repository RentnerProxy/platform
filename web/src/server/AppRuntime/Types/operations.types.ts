import type { AppOwnedProxyHostChange, AppProxyHost } from './hosts.types.ts'

export type AppOperationStatus = 'accepted' | 'running' | 'cancelled' | 'succeeded' | 'failed'

export interface AppOperationFailure {
    readonly code: string
    readonly title: string
    readonly status: number
}

export interface AppOperationHost extends AppProxyHost {
    readonly platformHostId: string
}

export type AppOperationResult =
    | { readonly action: 'upsert'; readonly host: AppOperationHost }
    | { readonly action: 'remove'; readonly hostId: string }

export type AppOperation =
    | {
          readonly id: string
          readonly status: Exclude<AppOperationStatus, 'failed'>
          readonly result?: AppOperationResult
      }
    | {
          readonly id: string
          readonly status: 'failed'
          readonly problem: AppOperationFailure & {
              readonly type: string
              readonly requestId: string
          }
      }

export type AppOperationPayload = AppOwnedProxyHostChange

export interface AppOperationWorkerClaim {
    readonly id: string
    readonly leaseToken: string
    readonly acceptedAt: Date
}
