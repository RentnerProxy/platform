import {
    APP_CATALOG_MAX_GRANTS,
    type CatalogApprovedGrant,
    type CatalogGrant,
    type CatalogGrantCapability,
    type CatalogInstallation,
    type CatalogLifecycleInput,
    type CatalogRequestedGrant,
} from './contract.ts'

/** Scopes whose resources the Owner selects. Every other scope names a fixed resource. */
const selectableScopes: ReadonlySet<string> = new Set(['proxyHosts'])

const grantNames = {
    'proxy.hosts.read.v1': 'proxyHostsRead',
    'diagnostics.upstream.probe.v1': 'upstreamProbe',
    'notifications.publish.v1': 'notificationsPublish',
    'app.audit.record': 'auditRecord',
    'app.events.subscribe': 'eventsSubscribe',
    'app.provider.register': 'providerRegister',
    'app.secret.read': 'secretRead',
} as const

const grantScopes = {
    installation: 'installation',
    proxyHosts: 'proxyHosts',
    providerProfiles: 'providerProfiles',
    secretReferences: 'secretReferences',
} as const

export type GrantNameKey = (typeof grantNames)[keyof typeof grantNames] | 'unknown'
export type GrantScopeKey = (typeof grantScopes)[keyof typeof grantScopes] | 'unknown'

/** A platform proxy host the Owner can select for an approval. */
export type CatalogProxyHost = { id: string; hostname: string; enabled: boolean }

/** The Owner's decision for one requested grant while the approval dialog is open. */
export type GrantDraftItem = {
    capability: CatalogGrantCapability
    /** A fixed resource such as a provider profile; the core fills in the installation itself. */
    resourceId: string | undefined
    /** The Owner selects the resources, at least one. */
    selectable: boolean
    /** The release requests background access, which the Owner may only narrow. */
    serviceRequested: boolean
    allowService: boolean
    permissionKey: string | undefined
    /** The selected resources of a selectable scope. */
    resources: string[]
}

export type GrantDraft = readonly GrantDraftItem[]

function sameCapability(left: CatalogGrantCapability, right: CatalogGrantCapability) {
    return left.id === right.id && left.scope === right.scope
}

/** The translation key of a capability, or `unknown` for one this appliance does not name. */
export function grantNameKey(capability: CatalogGrantCapability): GrantNameKey {
    return Object.hasOwn(grantNames, capability.id)
        ? grantNames[capability.id as keyof typeof grantNames]
        : 'unknown'
}

export function grantScopeKey(capability: CatalogGrantCapability): GrantScopeKey {
    return Object.hasOwn(grantScopes, capability.scope)
        ? grantScopes[capability.scope as keyof typeof grantScopes]
        : 'unknown'
}

/** Support grants the platform derives for every app with capabilities. */
export function isSupportGrant(capability: CatalogGrantCapability): boolean {
    return capability.id.startsWith('app.')
}

/** Whether the Owner selects the resources of this capability. */
export function isSelectableGrant(capability: CatalogGrantCapability): boolean {
    return selectableScopes.has(capability.scope)
}

/**
 * Start the Owner's decision from what the release requests. A previous approval of the same
 * installation preselects its resources, service access and declared permission keys.
 */
export function grantDraft(
    requested: readonly CatalogRequestedGrant[],
    permissionKeys: readonly string[],
    previous: readonly CatalogGrant[] | null = null,
): GrantDraft {
    return requested.map(({ capability, resourceId, allowService }) => {
        const selectable = isSelectableGrant(capability)
        const prior = (previous ?? []).filter(
            (grant) =>
                sameCapability(grant.capability, capability) &&
                (resourceId === undefined || grant.resourceId === resourceId),
        )
        const key = prior.find((grant) => grant.permissionKey !== undefined)?.permissionKey
        return {
            capability,
            resourceId,
            selectable,
            serviceRequested: allowService,
            allowService:
                allowService && (prior.length === 0 || prior.some((grant) => grant.allowService)),
            permissionKey: key !== undefined && permissionKeys.includes(key) ? key : undefined,
            resources: selectable ? [...new Set(prior.map((grant) => grant.resourceId))] : [],
        }
    })
}

/** Every selected resource counts unless the caller knows which resources still exist. */
const anyResource = () => true

/**
 * The approval the core receives: one grant per fixed item and per selected resource that
 * `exists` accepts. A preselected resource that no longer exists is never approved.
 */
export function grantApproval(
    draft: GrantDraft,
    exists: (resourceId: string) => boolean = anyResource,
): CatalogApprovedGrant[] {
    return draft.flatMap((item) => {
        const grant = (resourceId: string | undefined): CatalogApprovedGrant => ({
            capability: item.capability,
            ...(resourceId !== undefined && { resourceId }),
            allowService: item.serviceRequested && item.allowService,
            ...(item.permissionKey !== undefined && { permissionKey: item.permissionKey }),
        })
        return item.selectable ? item.resources.filter(exists).map(grant) : [grant(item.resourceId)]
    })
}

/** Whether every selectable item has an existing resource and the approval fits one request. */
export function grantDraftComplete(
    draft: GrantDraft,
    exists: (resourceId: string) => boolean = anyResource,
): boolean {
    return (
        draft.every((item) => !item.selectable || item.resources.some(exists)) &&
        grantApproval(draft, exists).length <= APP_CATALOG_MAX_GRANTS
    )
}

export function updateGrantDraft(
    draft: GrantDraft,
    index: number,
    change: Partial<Pick<GrantDraftItem, 'allowService' | 'permissionKey' | 'resources'>>,
): GrantDraft {
    return draft.map((item, position) => {
        if (position !== index) return item
        const next = { ...item, ...change }
        return { ...next, allowService: next.serviceRequested && next.allowService }
    })
}

/** A stable identity of one recorded grant. */
export function grantIdentity({ capability, resourceId }: CatalogGrant): string {
    return `${capability.id}\u0000${capability.scope}\u0000${resourceId}`
}

/** Whether the core accepts a revocation for an installation in this state. */
export function canRevokeGrants(installation: CatalogInstallation): boolean {
    return (
        installation.state === 'running' ||
        installation.state === 'disabled' ||
        installation.state === 'recoveryRequired'
    )
}

/** Revoke one recorded grant of the installed release. */
export function revokeGrantRequest(
    installation: CatalogInstallation,
    grant: CatalogGrant,
): CatalogLifecycleInput {
    const { installationId, generation, version, archiveSha256 } = installation
    return {
        action: 'revoke',
        installationId,
        expected: { generation, version, archiveSha256 },
        grants: [{ capability: grant.capability, resourceId: grant.resourceId }],
    }
}
