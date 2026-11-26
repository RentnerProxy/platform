import type { CatalogInstallation, CatalogLifecycleInput } from '@/lib/AppCatalog/contract.ts'

export type CatalogInstallationView = {
    installation: CatalogInstallation
    name: string
    publisher: string | undefined
    canOpen: boolean
    actions: CatalogLifecycleInput[]
    /** The offered update is not stored locally while its package source is unreachable. */
    updateRequiresSource: boolean
}

export type CatalogConfirmation = {
    name: string
    request: CatalogLifecycleInput
}
