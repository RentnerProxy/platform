import type { ReleaseChannel } from '@/features/ApplicationVersion/Types/application-update.types.ts'
import type { appProviderProfiles } from '../../AppUi/identifiers.ts'

/** A built-in feature that official apps may take over; it matches an app provider profile. */
export type BuiltInFeatureDomain = (typeof appProviderProfiles)[number]

/** `built-in`: the release still runs the feature. `retired`: only an app provides it. */
export type BuiltInFeatureTransitionStatus = 'built-in' | 'retired'

export interface BuiltInFeatureTransition {
    readonly domain: BuiltInFeatureDomain
    readonly status: BuiltInFeatureTransitionStatus
    /** Official apps that provide the feature's profile. */
    readonly apps: readonly string[]
}

/** The app runtime a platform release offers to installed packages. */
export interface AppRuntimeEnvironment {
    readonly runtimeProfile: string
    readonly platformApi: string
    readonly appProtocol: string
    readonly uiBridge: string | null
    readonly engineCapabilities: readonly string[]
}

/** The `rentnerproxy-app-requirements.json` release asset. */
export interface ReleaseAppRequirements {
    readonly schemaVersion: 1
    readonly releaseId: number
    readonly tag: string
    readonly channel: ReleaseChannel
    readonly publishedAt: string
    readonly revision: string
    readonly environment: AppRuntimeEnvironment
    readonly features: readonly BuiltInFeatureTransition[]
}
