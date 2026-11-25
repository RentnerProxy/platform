import type {
    ApplicationUpdateResult,
    ReleaseChannel,
} from '@/features/ApplicationVersion/Types/application-update.types.ts'

export interface PublishedUpdateRelease {
    readonly id: number
    readonly tag: string
    readonly version: string
    readonly channel: ReleaseChannel
    readonly publishedAt: string
    readonly notes: string | null
    readonly readinessAssetId: number | null
    readonly appRequirementsAssetId: number | null
}

/** The release fields a control asset must repeat exactly. */
export type ReleaseIdentity = Pick<PublishedUpdateRelease, 'id' | 'tag' | 'channel' | 'publishedAt'>

export type ControlAssetStatus = 'pending' | 'invalid' | 'unavailable'

export type LoadedReleaseAsset =
    { readonly status: 'loaded'; readonly raw: unknown } | { readonly status: ControlAssetStatus }

export interface UpdateCheckerDependencies {
    readonly fetcher?: typeof fetch
    readonly now?: () => number
    readonly platform?: string
}

export interface CachedUpdate {
    readonly version: string
    readonly result: ApplicationUpdateResult
    readonly expiresAt: number
}
