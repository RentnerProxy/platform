import type { AppRuntimeCredentials } from './authority.types.ts'

export type AppRuntimeOperation =
    | 'context'
    | 'authorization'
    | 'listHosts'
    | 'updateHost'
    | 'probe'
    | 'notification'
    | 'audit'
    | 'secret'
    | 'provider'
    | 'operation'
    | 'cancelOperation'
    | 'events'
    | LegacyHandoffOperation

export type LegacyHandoffOperation =
    'getLegacyHandoff' | 'beginLegacyHandoff' | 'readLegacyHandoffPart' | 'commitLegacyHandoff'

export interface AppRuntimeCall {
    readonly operation: AppRuntimeOperation
    readonly credentials: AppRuntimeCredentials
    readonly requestId: string
    readonly signal: AbortSignal
    readonly streamSignal: AbortSignal
    readonly resourceId?: string
    readonly idempotencyKey?: string
    readonly cursor?: string
    readonly body?: unknown
}
