import type {
    AppRuntimeEnvironment,
    BuiltInFeatureDomain,
    BuiltInFeatureTransition,
    BuiltInFeatureTransitionStatus,
} from '@/lib/ApplicationVersion/Types/app-requirements.types.ts'

export type ReleaseChannel = 'alpha' | 'beta' | 'stable'

export type UpdateImageStatus =
    'verified' | 'pending' | 'unavailable' | 'unsupported-platform' | 'invalid'

export interface ApplicationUpdate {
    readonly version: string
    readonly tag: string
    readonly channel: ReleaseChannel
    readonly url: string
    readonly notes: string | null
    readonly image: {
        readonly status: UpdateImageStatus
        readonly reference: string | null
        readonly digest: string | null
        readonly platform: string
    }
    readonly compatibility: {
        readonly status: 'supported' | 'requires-beta1' | 'unsupported'
        readonly minimumVersion: string | null
        readonly intermediateVersion: string | null
    }
    /** The target's app runtime and built-in feature plan from its app requirements asset. */
    readonly appRequirements: {
        readonly status: 'verified' | 'pending' | 'invalid' | 'unavailable'
        readonly environment: AppRuntimeEnvironment | null
        readonly features: readonly BuiltInFeatureTransition[]
    }
}

export interface ApplicationUpdateResult {
    readonly status: 'disabled' | 'current' | 'available' | 'unavailable'
    readonly checkedAt: string | null
    readonly currentChannel: ReleaseChannel | null
    readonly latest: ApplicationUpdate | null
}

/** How the target release treats an installed app, checked by the Rust app manager. */
export type UpgradeAppSupport = 'compatible' | 'incompatible' | 'unknown'

export interface UpgradePreviewApp {
    readonly installationId: string
    readonly appId: string
    readonly version: string
    readonly state: 'running' | 'disabled' | 'recoveryRequired'
    /** Provider profiles of the installed release; `null` when the catalog no longer lists it. */
    readonly providers: readonly BuiltInFeatureDomain[] | null
    readonly target: UpgradeAppSupport
}

export interface UpgradePreviewFeature {
    readonly domain: BuiltInFeatureDomain
    readonly target: BuiltInFeatureTransitionStatus
    /** Official apps the target names for this feature. */
    readonly apps: readonly string[]
    readonly owner: 'platform' | 'handoff' | 'app'
    /** `null` while no handoff source can inspect the built-in feature. */
    readonly configured: boolean | null
    readonly references: number | null
    /** Installed apps offering the feature that the target can run; `null` if apps are unknown. */
    readonly providers: readonly string[] | null
}

/** Combinations the target cannot run. Each one hides the copyable image reference. */
export type UpgradePreviewIssue =
    | {
          readonly kind: 'app-incompatible'
          readonly installationId: string
          readonly appId: string
          readonly version: string
      }
    | {
          readonly kind: 'feature-retired-without-app'
          readonly domain: BuiltInFeatureDomain
          readonly apps: readonly string[]
      }
    | { readonly kind: 'feature-handoff-pending'; readonly domain: BuiltInFeatureDomain }

export type ApplicationUpgradePreview =
    | { readonly status: 'forbidden' | 'unavailable' }
    | {
          /** `incomplete`: no issue was found, but installed apps could not all be checked. */
          readonly status: 'ready' | 'blocked' | 'incomplete'
          readonly features: readonly UpgradePreviewFeature[]
          /** `null` while the app runtime is unavailable. */
          readonly apps: readonly UpgradePreviewApp[] | null
          readonly issues: readonly UpgradePreviewIssue[]
      }
