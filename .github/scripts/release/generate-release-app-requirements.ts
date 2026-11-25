import { readFile } from 'node:fs/promises'
import { join, resolve } from 'node:path'

import { z } from 'zod'

import {
    APP_REQUIREMENTS_ASSET,
    APP_REQUIREMENTS_MAX_BYTES,
    APP_RUNTIME_ENVIRONMENT,
    BUILT_IN_FEATURE_TRANSITIONS,
    BUNDLED_INSTALLER_CONFIG,
} from '../../../web/src/config/app-requirements.config.ts'
import type { ReleaseAppRequirements } from '../../../web/src/lib/ApplicationVersion/Types/app-requirements.types.ts'
import { releaseAppRequirementsSchema } from '../../../web/src/server/Updates/app-requirements.ts'
import { parseReleaseReadinessInput } from './generate-release-readiness.ts'
import type { ReleaseReadinessInput } from './Types/release-readiness.types.ts'

// The appliance image ships this file as its installer configuration; only its engine list matters.
const installerSchema = z.object({ engineCapabilities: z.array(z.string()) })

/**
 * Describe the release's app runtime and built-in feature plan for older platforms. The asset
 * binds to the same release identity as `rentnerproxy-update.json` and must pass the reader's own
 * schema, so a release never publishes requirements its readers would reject.
 */
export function buildReleaseAppRequirements(
    input: ReleaseReadinessInput,
    installerConfig: unknown,
): ReleaseAppRequirements {
    const validated = parseReleaseReadinessInput(input)
    const installer = installerSchema.parse(installerConfig)
    const requirements = releaseAppRequirementsSchema.parse({
        schemaVersion: 1,
        releaseId: validated.releaseId,
        tag: validated.tag,
        channel: validated.channel,
        publishedAt: validated.publishedAt,
        revision: validated.revision,
        environment: {
            ...APP_RUNTIME_ENVIRONMENT,
            engineCapabilities: installer.engineCapabilities,
        },
        features: BUILT_IN_FEATURE_TRANSITIONS,
    })
    if (
        Buffer.byteLength(serializeReleaseAppRequirements(requirements)) >
        APP_REQUIREMENTS_MAX_BYTES
    )
        throw new Error('App requirements exceed the reader size limit')
    return requirements
}

export function serializeReleaseAppRequirements(requirements: ReleaseAppRequirements): string {
    return JSON.stringify(requirements, null, 4) + '\n'
}

if (import.meta.main) {
    const env = process.env
    if (!env.RUNNER_TEMP) throw new Error('Runner temporary directory is required')
    const installer: unknown = JSON.parse(
        await readFile(resolve(import.meta.dir, '../../..', BUNDLED_INSTALLER_CONFIG), 'utf8'),
    )
    const requirements = buildReleaseAppRequirements(
        {
            repository: env.GITHUB_REPOSITORY ?? '',
            releaseId: env.RELEASE_ID ?? '',
            tag: env.RELEASE_TAG ?? '',
            channel: env.RELEASE_CHANNEL ?? '',
            prerelease: env.RELEASE_PRERELEASE ?? '',
            publishedAt: env.RELEASE_PUBLISHED_AT ?? '',
            revision: env.RELEASE_REVISION ?? '',
            image: env.RELEASE_IMAGE ?? '',
            digest: env.RELEASE_DIGEST ?? '',
            platforms: env.RELEASE_PLATFORMS ?? '',
        },
        installer,
    )
    await Bun.write(
        join(env.RUNNER_TEMP, 'rentnerproxy-release', APP_REQUIREMENTS_ASSET),
        serializeReleaseAppRequirements(requirements),
    )
}
