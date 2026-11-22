import type { CatalogInstallation, CatalogLifecycleInput } from '@/lib/AppCatalog/contract.ts'

export type CatalogInstallationView = {
    installation: CatalogInstallation
    name: string
    publisher: string | undefined
    canOpen: boolean
    actions: CatalogLifecycleInput[]
}

export type CatalogConfirmation = {
    name: string
    request: CatalogLifecycleInput
}
