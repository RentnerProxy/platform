import type {
    ApplicationUpdateResult,
    UpgradePreviewApp,
} from '@/features/ApplicationVersion/Types/application-update.types.ts'
import type { AppRuntimeEnvironment } from '@/lib/ApplicationVersion/Types/app-requirements.types.ts'
import type { LocalBuiltInFeature } from '@/lib/ApplicationVersion/upgradePreview.ts'

export interface UpgradePreviewDependencies {
    readonly update: (currentVersion: string) => Promise<ApplicationUpdateResult>
    readonly inspectFeatures: () => Promise<readonly LocalBuiltInFeature[]>
    /** `null` when this deployment runs without the native app runtime. */
    readonly checkTarget: (
        environment: AppRuntimeEnvironment,
        signal: AbortSignal,
    ) => Promise<readonly UpgradePreviewApp[] | null>
}
