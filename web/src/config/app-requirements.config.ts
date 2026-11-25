import type { BuiltInFeatureTransition } from '../lib/ApplicationVersion/Types/app-requirements.types.ts'

/**
 * Release asset that tells an older platform which app runtime and built-in features a release
 * has. Readers of `rentnerproxy-update.json` match asset names exactly, so they ignore it.
 */
export const APP_REQUIREMENTS_ASSET = 'rentnerproxy-app-requirements.json'
export const APP_REQUIREMENTS_MAX_BYTES = 16_384

/**
 * The app runtime this release offers. The Rust core checks packages against the same values
 * (`RUNTIME_PROFILE` and `PROTOCOL_VERSION` in `core/src/app_install.rs`); engine capabilities
 * come from the bundled installer configuration.
 */
export const APP_RUNTIME_ENVIRONMENT = {
    runtimeProfile: 'rentnerproxy-linux-v1',
    platformApi: '1.0.0',
    appProtocol: '1.0.0',
    uiBridge: '1.0.0',
} as const
export const BUNDLED_INSTALLER_CONFIG = 'docker/production/apps/catalog/installer.json'

/**
 * What this release does with each built-in feature, in provider profile order. Mark a feature
 * `retired` only in the release that stops running it, and list the official apps that take it
 * over; older platforms then require such an app and a completed handoff before updating.
 */
export const BUILT_IN_FEATURE_TRANSITIONS: readonly BuiltInFeatureTransition[] = [
    { domain: 'monitoring', status: 'built-in', apps: [] },
    { domain: 'docker-discovery', status: 'built-in', apps: [] },
    { domain: 'load-balancer', status: 'built-in', apps: [] },
    { domain: 'dns', status: 'built-in', apps: [] },
    { domain: 'oidc', status: 'built-in', apps: [] },
    { domain: 'crowdsec', status: 'built-in', apps: [] },
]
