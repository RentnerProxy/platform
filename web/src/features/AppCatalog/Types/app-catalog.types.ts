import type {
    CatalogApprovedGrant,
    CatalogGrant,
    CatalogInstallation,
    CatalogLifecycleInput,
    CatalogRequestedGrant,
} from '@/lib/AppCatalog/contract.ts'
import type { CatalogBlockedRelease } from '@/lib/AppCatalog/installationActions.ts'

export type CatalogInstallationView = {
    installation: CatalogInstallation
    name: string
    publisher: string | undefined
    canOpen: boolean
    actions: CatalogLifecycleInput[]
    /** The newest listed release the appliance cannot offer, with the reason. */
    blockedRelease: CatalogBlockedRelease | undefined
    /** The offered update is not stored locally while its package source is unreachable. */
    updateRequiresSource: boolean
}

export type CatalogConfirmation = {
    name: string
    request: CatalogLifecycleInput
    /** The access a revocation withdraws, as shown to the Owner. */
    grant?: string
}

/** What the approval dialog asks the Owner to approve, and where the decision goes. */
export type CatalogApprovalRequest = {
    kind: 'install' | 'update' | 'reinstall'
    name: string
    version: string
    requested: readonly CatalogRequestedGrant[]
    permissionKeys: readonly string[]
    /** The installation's current or retained approval, which preselects the decision. */
    previous: readonly CatalogGrant[] | null
    submit: (approval: CatalogApprovedGrant[]) => void
}
