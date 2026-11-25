import type {
    ApplicationUpgradePreview,
    UpgradePreviewApp,
    UpgradePreviewFeature,
    UpgradePreviewIssue,
} from '../../features/ApplicationVersion/Types/application-update.types.ts'
import type {
    BuiltInFeatureDomain,
    BuiltInFeatureTransition,
} from './Types/app-requirements.types.ts'

/** A built-in feature as the local handoff journal reports it. */
export interface LocalBuiltInFeature {
    readonly domain: BuiltInFeatureDomain
    readonly ownership: { readonly owner: UpgradePreviewFeature['owner'] }
    readonly inspection?: { readonly configured: boolean; readonly references: number }
}

/**
 * Combine the target's feature plan with local ownership and the Rust target check.
 *
 * Blocking: an installed app the target would not run, and a feature the target retires while
 * platform may still hold its state (configured, referenced or not inspectable). That state needs
 * an installed providing app and a committed handoff before the image changes.
 */
export function evaluateUpgradePreview(
    transitions: readonly BuiltInFeatureTransition[],
    local: readonly LocalBuiltInFeature[],
    apps: readonly UpgradePreviewApp[] | null,
): Exclude<ApplicationUpgradePreview, { readonly status: 'forbidden' | 'unavailable' }> {
    const issues: UpgradePreviewIssue[] = []
    let undecided = apps === null || apps.some((app) => app.target === 'unknown')
    for (const app of apps ?? []) {
        if (app.target === 'incompatible')
            issues.push({
                kind: 'app-incompatible',
                installationId: app.installationId,
                appId: app.appId,
                version: app.version,
            })
    }
    const features = transitions.map((transition): UpgradePreviewFeature => {
        const state = local.find((feature) => feature.domain === transition.domain)
        const owner = state?.ownership.owner ?? 'platform'
        const providers =
            apps?.flatMap((app) =>
                app.target !== 'incompatible' && app.providers?.includes(transition.domain)
                    ? [app.appId]
                    : [],
            ) ?? null
        const feature: UpgradePreviewFeature = {
            domain: transition.domain,
            target: transition.status,
            apps: transition.apps,
            owner,
            configured: state?.inspection?.configured ?? null,
            references: state?.inspection?.references ?? null,
            providers,
        }
        const unused = feature.configured === false && feature.references === 0
        if (transition.status === 'retired' && owner !== 'app' && !unused) {
            if (providers === null) undecided = true
            else if (providers.length === 0)
                issues.push({
                    kind: 'feature-retired-without-app',
                    domain: transition.domain,
                    apps: transition.apps,
                })
            else issues.push({ kind: 'feature-handoff-pending', domain: transition.domain })
        }
        return feature
    })
    return {
        status: issues.length > 0 ? 'blocked' : undecided ? 'incomplete' : 'ready',
        features,
        apps,
        issues,
    }
}
