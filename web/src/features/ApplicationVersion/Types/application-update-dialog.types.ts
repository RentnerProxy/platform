import type {
    ApplicationUpdate,
    ApplicationUpdateResult,
    ApplicationUpgradePreview,
} from './application-update.types.ts'

/** The on-demand local preview of the target release; `preview` is absent until it loads. */
export interface ApplicationUpgradePreviewQuery {
    readonly preview: ApplicationUpgradePreview | undefined
    readonly loading: boolean
}

export interface ApplicationUpdateDialogProps {
    readonly data: ApplicationUpdateResult | undefined
    readonly preview?: ApplicationUpgradePreviewQuery | undefined
    readonly open: boolean
    readonly onOpenChange: (open: boolean) => void
}

export interface ApplicationUpdateDialogLogicResult {
    readonly state: {
        readonly currentVersion: string
        readonly releaseUrl: string
        readonly canCopy: boolean
    }
    readonly handler: { readonly handleCopy: () => void }
}

export interface UpgradePreviewSectionProps {
    readonly requirements: ApplicationUpdate['appRequirements']
    readonly preview: ApplicationUpgradePreview | undefined
    readonly loading: boolean
}
