import type { appProviderProfiles } from '@/server/AppRuntime/contract.ts'
import type { AppRuntimeJsonValue } from '@/server/AppRuntime/Types/authority.types.ts'
import type { AuthTransaction } from '@/server/Auth/Core/Types/database.types.ts'

/** Built-in feature domains that official apps may take over; they match the provider profiles. */
export type LegacyFeatureDomain = (typeof appProviderProfiles)[number]

export interface LegacyFeatureInspection {
    /** Whether platform still holds state an app would have to take over. */
    readonly configured: boolean
    /** Number of platform records (hosts, policies, connections) that depend on the domain. */
    readonly references: number
}

/**
 * A built-in feature's migration into the framework. Every platform writer of the domain must run
 * through `withPlatformOwnedLegacyFeature`, so an export sees state that no platform worker changes.
 */
export interface LegacyFeatureHandoffSource {
    readonly domain: LegacyFeatureDomain
    inspect(transaction: AuthTransaction): Promise<LegacyFeatureInspection>
    /** Emit the fenced platform state in a deterministic order as bounded JSON parts. */
    export(
        transaction: AuthTransaction,
        emit: (part: AppRuntimeJsonValue) => Promise<void>,
    ): Promise<void>
    /**
     * Retire the platform-owned state after the app committed the exact export: remove it, or leave
     * it inert for a later removal step. Make every change through the supplied transaction: a
     * failed commit rolls them back and a retry calls `retire` again, while a committed handoff
     * never calls it a second time.
     */
    retire(transaction: AuthTransaction): Promise<void>
}

export type LegacyFeatureOwner =
    | { readonly owner: 'platform' }
    | {
          readonly owner: 'handoff'
          readonly installationId: string
          readonly digest: string
          readonly partCount: number
      }
    | { readonly owner: 'app'; readonly installationId: string; readonly digest: string }

export interface LegacyFeatureStatus {
    readonly domain: LegacyFeatureDomain
    readonly ownership: LegacyFeatureOwner
    /** Present while platform owns the domain and a source is registered for it. */
    readonly inspection?: LegacyFeatureInspection
}

export type PlatformOwnedResult<T> =
    { readonly owned: true; readonly value: T } | { readonly owned: false }

type LegacyFeatureHandoffErrorCode = 'not_found' | 'conflict' | 'invalid_export' | 'corrupt'

export class LegacyFeatureHandoffError extends Error {
    constructor(readonly code: LegacyFeatureHandoffErrorCode) {
        super(code)
        this.name = 'LegacyFeatureHandoffError'
    }
}
