import type { AppRuntimeJsonValue } from '@/server/AppRuntime/Types/authority.types.ts'
import type { LegacyHandoffOperation } from '@/server/AppRuntime/Types/gateway.types.ts'
import type { LegacyFeatureDomain, LegacyFeatureHandoffSource } from './legacy-handoff.types.ts'

/** Handoff sources by domain; a domain without one cannot begin a handoff. */
export type LegacyFeatureHandoffSources = Readonly<
    Partial<Record<LegacyFeatureDomain, LegacyFeatureHandoffSource>>
>

/** App API v1 `LegacyHandoffStatus`: another holder is a conflict, never a state. */
export type LegacyHandoffStatus =
    | { readonly domain: LegacyFeatureDomain; readonly state: 'platform' }
    | {
          readonly domain: LegacyFeatureDomain
          readonly state: 'exported'
          readonly digest: string
          readonly partCount: number
      }
    | { readonly domain: LegacyFeatureDomain; readonly state: 'committed'; readonly digest: string }

/** App API v1 `LegacyHandoffPart`. */
export interface LegacyHandoffPart {
    readonly sequence: number
    readonly part: AppRuntimeJsonValue
}

export type LegacyHandoffRequest =
    | {
          readonly operation: Extract<
              LegacyHandoffOperation,
              'getLegacyHandoff' | 'beginLegacyHandoff'
          >
          readonly domain: LegacyFeatureDomain
      }
    | {
          readonly operation: 'readLegacyHandoffPart'
          readonly domain: LegacyFeatureDomain
          readonly digest: string
          readonly sequence: number
      }
    | {
          readonly operation: 'commitLegacyHandoff'
          readonly domain: LegacyFeatureDomain
          readonly digest: string
      }
