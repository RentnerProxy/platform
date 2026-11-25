import { z } from 'zod'
import { appIdSchema, appProviderProfilesSchema, appRecordId } from '@/lib/AppUi/identifiers.ts'

export const APP_CATALOG_INSTALL_PATH = '/api/v1/app-catalog/install'
export const APP_CATALOG_LIFECYCLE_PATH = '/api/v1/app-catalog/lifecycle'

const versionComponent = '(?:0|[1-9][0-9]{0,5})'
const prereleaseComponent = '(?:0|[1-9][0-9]*|[0-9]*[a-zA-Z-][0-9a-zA-Z-]*)'
const versionPattern = new RegExp(
    `^${versionComponent}\\.${versionComponent}\\.${versionComponent}(?:-${prereleaseComponent}(?:\\.${prereleaseComponent})*)?$`,
    'u',
)
const displayText = (length: number) =>
    z.string().regex(new RegExp(`^[^\\p{Cc}\\p{Cs}]{1,${length}}$`, 'u'))

const releaseSchema = z.strictObject({
    version: z.string().max(64).regex(versionPattern),
    archiveSha256: z.string().regex(/^[a-f0-9]{64}$/u),
})

export const catalogSelectorSchema = releaseSchema.extend({ appId: appIdSchema })

const catalogEntrySchema = catalogSelectorSchema.extend({
    name: displayText(80),
    summary: displayText(400),
    publisher: displayText(80),
    hasUi: z.boolean(),
    providers: appProviderProfilesSchema,
    availability: z.enum(['available', 'incompatible', 'grantsRequired']),
})

export const catalogInstallSchema = z.discriminatedUnion('status', [
    catalogSelectorSchema.extend({ status: z.literal('installing') }),
    catalogSelectorSchema.extend({ status: z.literal('installed'), installationId: appRecordId }),
    catalogSelectorSchema.extend({
        status: z.literal('failed'),
        error: z.enum(['conflict', 'unavailable', 'installFailed']).optional(),
    }),
])

const installedReleaseSchema = releaseSchema.extend({
    generation: z.number().int().min(1).max(Number.MAX_SAFE_INTEGER),
})

const installationSchema = installedReleaseSchema.extend({
    installationId: appRecordId,
    appId: appIdSchema,
    state: z.enum(['running', 'disabled', 'recoveryRequired', 'removing', 'removed', 'purging']),
    providers: appProviderProfilesSchema.nullable(),
    update: releaseSchema.nullable(),
    previous: releaseSchema.nullable(),
})

/** One installation the Rust app manager checked against a target platform release. */
const targetInstallationSchema = releaseSchema.extend({
    installationId: appRecordId,
    appId: appIdSchema,
    state: z.enum(['running', 'disabled', 'recoveryRequired']),
    providers: appProviderProfilesSchema.nullable(),
    target: z.enum(['compatible', 'incompatible', 'unknown']),
})

export const catalogTargetCheckSchema = z.strictObject({
    installations: z
        .array(targetInstallationSchema)
        .max(256)
        .refine(
            (rows) => new Set(rows.map(({ installationId }) => installationId)).size === rows.length,
        ),
})

const lifecycleInput = z.strictObject({
    action: z.enum([
        'update',
        'deactivate',
        'reactivate',
        'uninstall',
        'recover',
        'rollback',
        'purge',
        'reinstall',
    ]),
    installationId: appRecordId,
    expected: installedReleaseSchema,
    target: releaseSchema.optional(),
})

function hasExpectedLifecycleTarget({ action, target }: z.infer<typeof lifecycleInput>) {
    return (
        (action === 'update' || action === 'rollback' || action === 'reinstall') ===
        (target !== undefined)
    )
}

export const catalogLifecycleInputSchema = lifecycleInput.refine(hasExpectedLifecycleTarget)
export const catalogLifecycleSchema = z
    .discriminatedUnion('status', [
        lifecycleInput.extend({ status: z.literal('pending') }),
        lifecycleInput.extend({ status: z.literal('succeeded') }),
        lifecycleInput.extend({
            status: z.literal('failed'),
            error: z.enum(['conflict', 'unavailable', 'incompatibleData', 'operationFailed']),
        }),
    ])
    .refine(hasExpectedLifecycleTarget)

export const catalogSnapshotSchema = z.strictObject({
    state: z.enum(['loading', 'ready', 'stale', 'unavailable']),
    entries: z.array(catalogEntrySchema).max(4_096),
    install: catalogInstallSchema.nullable(),
    installations: z.array(installationSchema).max(4_096),
    lifecycle: catalogLifecycleSchema.nullable(),
})

export type CatalogSelector = z.infer<typeof catalogSelectorSchema>
export type CatalogEntry = z.infer<typeof catalogEntrySchema>
export type CatalogInstall = z.infer<typeof catalogInstallSchema>
export type CatalogRelease = z.infer<typeof releaseSchema>
export type CatalogInstallation = z.infer<typeof installationSchema>
export type CatalogLifecycleInput = z.infer<typeof catalogLifecycleInputSchema>
export type CatalogLifecycle = z.infer<typeof catalogLifecycleSchema>
export type CatalogSnapshot = z.infer<typeof catalogSnapshotSchema>

export function sameCatalogRelease(left: CatalogSelector, right: CatalogSelector): boolean {
    return (
        left.appId === right.appId &&
        left.version === right.version &&
        left.archiveSha256 === right.archiveSha256
    )
}

export function sameCatalogLifecycle(left: CatalogLifecycleInput, right: CatalogLifecycleInput) {
    return (
        left.action === right.action &&
        left.installationId === right.installationId &&
        left.expected.generation === right.expected.generation &&
        left.expected.version === right.expected.version &&
        left.expected.archiveSha256 === right.expected.archiveSha256 &&
        left.target?.version === right.target?.version &&
        left.target?.archiveSha256 === right.target?.archiveSha256
    )
}
