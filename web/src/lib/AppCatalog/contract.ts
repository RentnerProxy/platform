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

/** The most grants one approval or revocation holds; the Rust app manager enforces the same. */
export const APP_CATALOG_MAX_GRANTS = 128

const grantCapabilitySchema = z.strictObject({
    id: z
        .string()
        .max(64)
        .regex(/^[a-z][a-z0-9-]*(?:\.[a-z0-9-]+)+$/u),
    scope: z
        .string()
        .max(32)
        .regex(/^[a-z][A-Za-z]*$/u),
})
const permissionKeySchema = z.string().regex(/^[a-z][a-z0-9-]{0,31}$/u)

/** A grant the signed manifest requests. Selectable scopes have no resource; the Owner picks. */
const requestedGrantSchema = z.strictObject({
    capability: grantCapabilitySchema,
    resourceId: appRecordId.optional(),
    allowService: z.boolean(),
})

/** A grant the Rust app manager recorded for an installed release. */
const grantSchema = z.strictObject({
    capability: grantCapabilitySchema,
    resourceId: appRecordId,
    allowService: z.boolean(),
    permissionKey: permissionKeySchema.optional(),
})

/** The Owner's decision for one requested grant. The core fills the installation itself. */
const approvedGrantSchema = z.strictObject({
    capability: grantCapabilitySchema,
    resourceId: appRecordId.optional(),
    allowService: z.boolean(),
    permissionKey: permissionKeySchema.optional(),
})
const approvalSchema = z.array(approvedGrantSchema).max(APP_CATALOG_MAX_GRANTS)

const revokedGrantSchema = z.strictObject({
    capability: grantCapabilitySchema,
    resourceId: appRecordId,
})

/** An install request; the approval must match exactly what the release requests. */
export const catalogInstallInputSchema = catalogSelectorSchema.extend({
    approval: approvalSchema.optional(),
})

const catalogEntrySchema = catalogSelectorSchema.extend({
    name: displayText(80),
    summary: displayText(400),
    publisher: displayText(80),
    hasUi: z.boolean(),
    providers: appProviderProfilesSchema,
    /** The grants the signed manifest requests, for the Owner to approve. */
    grants: z.array(requestedGrantSchema).max(32),
    /** The app-owned permission keys an approved grant may name. */
    permissionKeys: z.array(permissionKeySchema).max(64),
    /** `grantsRequired`: the release requests a capability this appliance cannot grant. */
    availability: z.enum(['available', 'incompatible', 'grantsRequired']),
    /** The package store holds this archive, so installing needs no package download. */
    cached: z.boolean(),
})

/** Which remote source an installation or update could not reach. */
const sourceOutages = [
    'catalogUnavailable',
    'packageSourceUnavailable',
    'networkUnavailable',
] as const

export const catalogInstallSchema = z.discriminatedUnion('status', [
    catalogSelectorSchema.extend({ status: z.literal('installing') }),
    catalogSelectorSchema.extend({ status: z.literal('installed'), installationId: appRecordId }),
    catalogSelectorSchema.extend({
        status: z.literal('failed'),
        error: z
            .enum([
                'conflict',
                'approvalRequired',
                'unavailable',
                ...sourceOutages,
                'installFailed',
            ])
            .optional(),
    }),
])

const installedReleaseSchema = releaseSchema.extend({
    generation: z.number().int().min(1).max(Number.MAX_SAFE_INTEGER),
})

const installationSchema = installedReleaseSchema.extend({
    installationId: appRecordId,
    appId: appIdSchema,
    state: z.enum(['running', 'disabled', 'recoveryRequired', 'removing', 'removed', 'purging']),
    /** Display name from the verified manifest of the installed release, when known. */
    name: displayText(80).nullable(),
    providers: appProviderProfilesSchema.nullable(),
    /** The grants approved for this exact release; null if it predates recorded approvals. */
    grants: z.array(grantSchema).max(APP_CATALOG_MAX_GRANTS).nullable(),
    update: releaseSchema.nullable(),
    /** The offered update requests grants that the current approval does not cover. */
    updateRequiresApproval: z.boolean(),
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
            (rows) =>
                new Set(rows.map(({ installationId }) => installationId)).size === rows.length,
        ),
})

const lifecycleReceipt = z.strictObject({
    action: z.enum([
        'update',
        'deactivate',
        'reactivate',
        'uninstall',
        'recover',
        'rollback',
        'purge',
        'reinstall',
        'revoke',
    ]),
    installationId: appRecordId,
    expected: installedReleaseSchema,
    target: releaseSchema.optional(),
})
/** Receipts never repeat an approval or the revoked grants. */
const lifecycleInput = lifecycleReceipt.extend({
    approval: approvalSchema.optional(),
    grants: z.array(revokedGrantSchema).min(1).max(APP_CATALOG_MAX_GRANTS).optional(),
})

function hasExpectedLifecycleTarget({ action, target }: z.infer<typeof lifecycleReceipt>) {
    return (
        (action === 'update' || action === 'rollback' || action === 'reinstall') ===
        (target !== undefined)
    )
}

function hasExpectedLifecycleGrants({ action, approval, grants }: z.infer<typeof lifecycleInput>) {
    return (
        (approval === undefined || action === 'update' || action === 'reinstall') &&
        (action === 'revoke') === (grants !== undefined) &&
        (grants === undefined ||
            new Set(grants.map((grant) => JSON.stringify(grant))).size === grants.length)
    )
}

export const catalogLifecycleInputSchema = lifecycleInput.refine(
    (input) => hasExpectedLifecycleTarget(input) && hasExpectedLifecycleGrants(input),
)
export const catalogLifecycleSchema = z
    .discriminatedUnion('status', [
        lifecycleReceipt.extend({ status: z.literal('pending') }),
        lifecycleReceipt.extend({ status: z.literal('succeeded') }),
        lifecycleReceipt.extend({
            status: z.literal('failed'),
            error: z.enum([
                'conflict',
                'approvalRequired',
                'dependencyBlocked',
                'unavailable',
                ...sourceOutages,
                'incompatibleData',
                'revokedAppStopped',
                'operationFailed',
            ]),
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
export type CatalogInstallInput = z.infer<typeof catalogInstallInputSchema>
export type CatalogEntry = z.infer<typeof catalogEntrySchema>
export type CatalogInstall = z.infer<typeof catalogInstallSchema>
export type CatalogRelease = z.infer<typeof releaseSchema>
export type CatalogInstallation = z.infer<typeof installationSchema>
export type CatalogLifecycleInput = z.infer<typeof catalogLifecycleInputSchema>
export type CatalogLifecycle = z.infer<typeof catalogLifecycleSchema>
export type CatalogSnapshot = z.infer<typeof catalogSnapshotSchema>
export type CatalogRequestedGrant = z.infer<typeof requestedGrantSchema>
export type CatalogGrant = z.infer<typeof grantSchema>
export type CatalogApprovedGrant = z.infer<typeof approvedGrantSchema>
export type CatalogGrantCapability = z.infer<typeof grantCapabilitySchema>

/** Whether an operation failed because the package source, or every source, was unreachable. */
export function isPackageSourceOutage(error: string | undefined): boolean {
    return error === 'packageSourceUnavailable' || error === 'networkUnavailable'
}

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
