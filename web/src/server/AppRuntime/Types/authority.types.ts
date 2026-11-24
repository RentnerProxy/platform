import type { PermissionKey } from '@/config/Types/permissions-config.types.ts'
import type { AuthenticatedUser } from '@/lib/Auth/Types/auth.types.ts'

export interface AppRuntimeIdentity {
    readonly appId: string
    readonly installationId: string
    readonly generation: number
    readonly uid: number
}

export interface AppRuntimeCredentials {
    readonly identity: AppRuntimeIdentity
    readonly delegation?: string
}

export interface AppRuntimeCapability {
    readonly id: string
    readonly scope: string
}

export interface AppRuntimeGrant {
    readonly capability: AppRuntimeCapability
    readonly resourceId: string
    readonly allowService: boolean
    readonly permissionKey?: string
}

export interface AppRuntimeProviderRegistration {
    readonly id: string
    readonly profile: string
    readonly version: string
}

export interface AppRuntimeRegistration {
    readonly identity: AppRuntimeIdentity
    readonly leaseExpiresAt: Date
    readonly capabilities: readonly AppRuntimeCapability[]
    readonly providerProfiles?: readonly string[]
    readonly permissionKeys?: readonly string[]
    readonly hasUi?: boolean
}

interface AppRuntimePrincipalBase {
    readonly identity: AppRuntimeIdentity
    readonly expiresAt: Date
    readonly authorizationEpoch: bigint
    readonly permissions: readonly PermissionKey[]
    readonly appPermissions: readonly string[]
    readonly grants: readonly AppRuntimeGrant[]
}

export type AppRuntimePrincipal = AppRuntimePrincipalBase &
    (
        | {
              readonly kind: 'service'
              readonly user: null
              readonly sessionId: null
              readonly delegationId: null
          }
        | {
              readonly kind: 'user'
              readonly user: AuthenticatedUser
              readonly sessionId: string
              readonly delegationId: string
          }
    )

type AppRuntimeAuthorityErrorCode =
    'unauthorized' | 'forbidden' | 'not_found' | 'conflict' | 'cursor_expired' | 'invalid_input'

export class AppRuntimeAuthorityError extends Error {
    constructor(readonly code: AppRuntimeAuthorityErrorCode) {
        super(code)
        this.name = 'AppRuntimeAuthorityError'
    }
}

export type AppRuntimeJsonValue =
    | string
    | number
    | boolean
    | null
    | AppRuntimeJsonValue[]
    | { [key: string]: AppRuntimeJsonValue }

export interface AppRuntimeEventInput {
    readonly installationId: string
    readonly type: string
    readonly capability: AppRuntimeCapability
    readonly resourceId: string
    readonly revision?: string
    readonly payload?: Readonly<Record<string, AppRuntimeJsonValue | undefined>>
}

export interface AppRuntimeEvent {
    readonly id: string
    readonly cursor: string
    readonly type: string
    readonly occurredAt: string
    readonly resourceId?: string
    readonly revision?: string
    readonly payload?: Record<string, unknown>
}
