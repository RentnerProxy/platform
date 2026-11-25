import '@tanstack/react-start/server-only'

import type {
    ApplicationUpdateResult,
    ApplicationUpgradePreview,
} from '@/features/ApplicationVersion/Types/application-update.types.ts'
import type { AppRuntimeEnvironment } from '@/lib/ApplicationVersion/Types/app-requirements.types.ts'
import {
    evaluateUpgradePreview,
    type LocalBuiltInFeature,
} from '@/lib/ApplicationVersion/upgradePreview.ts'
import { nativeCatalogTargetCheck } from '@/server/AppRuntime/catalog/transport.server.ts'
import { appUiEnabled } from '@/server/AppRuntime/ui/transport.server.ts'
import { getAuthDatabase } from '@/server/Auth/Core/database.server.ts'
import { inspectLegacyFeaturesInTransaction } from '@/server/LegacyHandoff/journal.server.ts'
import { legacyFeatureHandoffSources } from '@/server/LegacyHandoff/sources.server.ts'
import type { UpgradePreviewDependencies } from './Types/upgrade-preview.types.ts'
import { getAvailableUpdateService } from './releases.service.ts'

const defaultDependencies: UpgradePreviewDependencies = {
    update: getAvailableUpdateService,
    // The same source registry as the App API, so the preview and a handoff agree on domains.
    inspectFeatures: () =>
        getAuthDatabase().transaction(
            (transaction) =>
                inspectLegacyFeaturesInTransaction(transaction, legacyFeatureHandoffSources),
            { accessMode: 'read only' },
        ),
    checkTarget: async (environment: AppRuntimeEnvironment, signal: AbortSignal) => {
        // Without the native app runtime no app can be installed, so none can provide a feature.
        if (!appUiEnabled()) return []
        const { installations } = await nativeCatalogTargetCheck(environment, signal)
        return installations.map(
            ({ installationId, appId, version, state, providers, target }) => ({
                installationId,
                appId,
                version,
                state,
                providers,
                target,
            }),
        )
    },
}

/**
 * Preview the verified target release against this installation: built-in feature ownership from
 * the handoff journal and each installed app checked by the Rust app manager. Only verified
 * release data reaches the target check; the browser names the release tag it shows, never an
 * environment, and a different current target yields no preview.
 */
export async function getUpgradePreviewService(
    currentVersion: string,
    tag: string,
    signal: AbortSignal,
    dependencies: UpgradePreviewDependencies = defaultDependencies,
): Promise<ApplicationUpgradePreview> {
    const update: ApplicationUpdateResult = await dependencies.update(currentVersion)
    const requirements = update.latest?.tag === tag ? update.latest.appRequirements : undefined
    if (requirements?.status !== 'verified' || !requirements.environment)
        return { status: 'unavailable' }
    let features: readonly LocalBuiltInFeature[]
    try {
        features = await dependencies.inspectFeatures()
    } catch {
        return { status: 'unavailable' }
    }
    const apps = await dependencies.checkTarget(requirements.environment, signal).catch(() => null)
    return evaluateUpgradePreview(requirements.features, features, apps)
}
