import type { CatalogInstallation, CatalogLifecycleInput } from '@/lib/AppCatalog/contract.ts'
import type { CatalogBlockedRelease } from '@/lib/AppCatalog/installationActions.ts'

export type CatalogInstallationView = {
    installation: CatalogInstallation
    name: string
    publisher: string | undefined
    canOpen: boolean
    actions: CatalogLifecycleInput[]
    /** The newest listed release the appliance cannot offer, with the reason. */
    blockedRelease: CatalogBlockedRelease | undefined
}

export type CatalogConfirmation = {
    name: string
    request: CatalogLifecycleInput
}
