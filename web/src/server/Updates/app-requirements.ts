import { z } from 'zod'

import type { ReleaseAppRequirements } from '../../lib/ApplicationVersion/Types/app-requirements.types.ts'
import type { ReleaseReadiness } from '../../lib/ApplicationVersion/Types/release-readiness.types.ts'
import { appIdSchema, appProviderProfiles } from '../../lib/AppUi/identifiers.ts'
import { parseReleaseVersion } from '../../lib/ApplicationVersion/releaseVersion.ts'
import type { ReleaseIdentity } from './Types/releases.types.ts'

const protocolVersion = z
    .string()
    .regex(/^(?:0|[1-9][0-9]{0,5})\.(?:0|[1-9][0-9]{0,5})\.(?:0|[1-9][0-9]{0,5})$/u)
const distinct = (values: readonly string[]) => new Set(values).size === values.length

/** Bounds shared with the Rust target check (`app_install::TargetEnvironment::valid`). */
export const appRuntimeEnvironmentSchema = z.strictObject({
    runtimeProfile: z.string().regex(/^[a-z0-9][a-z0-9-]{0,63}$/u),
    platformApi: protocolVersion,
    appProtocol: protocolVersion,
    uiBridge: protocolVersion.nullable(),
    engineCapabilities: z
        .array(
            z
                .string()
                .max(64)
                .regex(/^[a-z0-9][a-z0-9-]*(?:\.[a-z0-9][a-z0-9-]*)+$/u),
        )
        .max(16)
        .refine(distinct),
})

const transitionSchema = z
    .strictObject({
        domain: z.enum(appProviderProfiles),
        status: z.enum(['built-in', 'retired']),
        apps: z.array(appIdSchema).max(4).refine(distinct),
    })
    // A retired feature without an app would leave no way to keep using it.
    .refine((transition) => transition.status === 'built-in' || transition.apps.length > 0)

export const releaseAppRequirementsSchema = z.strictObject({
    schemaVersion: z.literal(1),
    releaseId: z.number().int().positive().safe(),
    tag: z.string().max(128),
    channel: z.enum(['alpha', 'beta', 'stable']),
    publishedAt: z.iso.datetime(),
    revision: z.string().regex(/^[a-f0-9]{40}$/u),
    environment: appRuntimeEnvironmentSchema,
    features: z
        .array(transitionSchema)
        .length(appProviderProfiles.length)
        .refine((features) =>
            features.every((feature, index) => feature.domain === appProviderProfiles[index]),
        ),
})

/** Accept the asset only for the exact release and source revision its readiness describes. */
export function parseReleaseAppRequirements(
    raw: unknown,
    release: ReleaseIdentity,
    readiness: ReleaseReadiness,
): ReleaseAppRequirements | null {
    const parsed = releaseAppRequirementsSchema.safeParse(raw)
    if (!parsed.success) return null
    const data = parsed.data
    const target = parseReleaseVersion(data.tag)
    if (
        data.releaseId !== release.id ||
        data.tag !== release.tag ||
        data.channel !== release.channel ||
        data.publishedAt !== release.publishedAt ||
        data.revision !== readiness.revision ||
        target?.channel !== data.channel
    )
        return null
    return data
}
