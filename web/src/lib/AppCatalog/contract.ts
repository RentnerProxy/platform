import { z } from 'zod'
import { appIdSchema, appRecordId } from '@/lib/AppUi/identifiers.ts'

export const APP_CATALOG_INSTALL_PATH = '/api/v1/app-catalog/install'

const versionComponent = '(?:0|[1-9][0-9]{0,5})'
const prereleaseComponent = '(?:0|[1-9][0-9]*|[0-9]*[a-zA-Z-][0-9a-zA-Z-]*)'
const versionPattern = new RegExp(
    `^${versionComponent}\\.${versionComponent}\\.${versionComponent}(?:-${prereleaseComponent}(?:\\.${prereleaseComponent})*)?$`,
    'u',
)
const displayText = (length: number) =>
    z.string().regex(new RegExp(`^[^\\p{Cc}\\p{Cs}]{1,${length}}$`, 'u'))

export const catalogSelectorSchema = z.strictObject({
    appId: appIdSchema,
    version: z.string().max(64).regex(versionPattern),
    archiveSha256: z.string().regex(/^[a-f0-9]{64}$/u),
})

const catalogEntrySchema = catalogSelectorSchema.extend({
    name: displayText(80),
    summary: displayText(400),
    publisher: displayText(80),
    hasUi: z.boolean(),
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

export const catalogSnapshotSchema = z.strictObject({
    state: z.enum(['loading', 'ready', 'stale', 'unavailable']),
    entries: z.array(catalogEntrySchema).max(4_096),
    install: catalogInstallSchema.nullable(),
})

export type CatalogSelector = z.infer<typeof catalogSelectorSchema>
export type CatalogInstall = z.infer<typeof catalogInstallSchema>
export type CatalogSnapshot = z.infer<typeof catalogSnapshotSchema>

export function sameCatalogRelease(left: CatalogSelector, right: CatalogSelector): boolean {
    return (
        left.appId === right.appId &&
        left.version === right.version &&
        left.archiveSha256 === right.archiveSha256
    )
}
