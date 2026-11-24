import type { AppRuntimeJsonValue } from '@/server/AppRuntime/Types/authority.types.ts'
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
    | { readonly operation: 'getLegacyHandoff'; readonly domain: LegacyFeatureDomain }
    | {
          readonly operation: 'beginLegacyHandoff'
          readonly domain: LegacyFeatureDomain
          /** The idempotency key, bound to the domain once begin succeeds. */
          readonly key: string
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
          /** The idempotency key, bound to the domain and digest once commit succeeds. */
          readonly key: string
      }
