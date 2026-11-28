import '@tanstack/react-start/server-only'

import { PERMISSIONS } from '@/config/permissions.config.ts'
import type { PermissionKey } from '@/config/Types/permissions-config.types.ts'
import {
    ALL_PROXY_HOSTS_RESOURCE,
    appGrantCapabilitySchema,
    appProviderProfileSchema,
    appRecordId,
} from './contract.ts'
import {
    AppRuntimeAuthorityError,
    type AppRuntimeCapability,
    type AppRuntimeGrant,
    type AppRuntimePrincipal,
} from './Types/authority.types.ts'

type AppRuntimeAuthorizationSubject = Pick<
    AppRuntimePrincipal,
    'kind' | 'identity' | 'expiresAt' | 'permissions' | 'appPermissions' | 'grants'
>

export const APP_RUNTIME_SUPPORT_CAPABILITIES = {
    audit: { id: 'app.audit.record', scope: 'installation' },
    secret: { id: 'app.secret.read', scope: 'secretReferences' },
    events: { id: 'app.events.subscribe', scope: 'installation' },
    provider: { id: 'app.provider.register', scope: 'providerProfiles' },
} as const satisfies Record<string, AppRuntimeCapability>

const platformPermissions: Readonly<Partial<Record<string, readonly PermissionKey[]>>> = {
    'proxy.hosts.read.v1': [PERMISSIONS.PROXY_HOSTS_VIEW],
    'proxy.hosts.manage-owned.v1': [
        PERMISSIONS.PROXY_HOSTS_CREATE,
        PERMISSIONS.PROXY_HOSTS_UPDATE,
        PERMISSIONS.PROXY_HOSTS_DELETE,
    ],
    'diagnostics.upstream.probe.v1': [PERMISSIONS.PROXY_HOSTS_VIEW],
    'diagnostics.upstream.probe.v2': [PERMISSIONS.PROXY_HOSTS_VIEW],
    'notifications.publish.v1': [PERMISSIONS.NOTIFICATIONS_MANAGE],
    'notifications.incidents.manage.v1': [PERMISSIONS.NOTIFICATIONS_MANAGE],
    'docker.inventory.observe.v1': [PERMISSIONS.DOCKER_DISCOVERY_VIEW],
    'dns.challenge.manage.v1': [PERMISSIONS.DNS_CONNECTIONS_MANAGE],
    'security.enforcement.contribute.v1': [PERMISSIONS.CROWDSEC_UPDATE],
    'access.logs.read.v1': [PERMISSIONS.PROXY_ACCESS_LOGS_VIEW],
    'app.audit.record': [PERMISSIONS.APP_ACCESS],
    'app.events.subscribe': [PERMISSIONS.APP_ACCESS],
    'app.provider.register': [PERMISSIONS.APP_ACCESS],
}

export function sameAppRuntimeCapability(
    left: AppRuntimeCapability,
    right: AppRuntimeCapability,
): boolean {
    return left.id === right.id && left.scope === right.scope
}

export function isAppRuntimeSupportCapability(capability: AppRuntimeCapability): boolean {
    return Object.values(APP_RUNTIME_SUPPORT_CAPABILITIES).some((entry) =>
        sameAppRuntimeCapability(capability, entry),
    )
}

export function isAppRuntimeGrantTarget(
    capability: AppRuntimeCapability,
    resourceId: string,
    installationId: string,
): boolean {
    return (
        appRecordId.safeParse(resourceId).success &&
        (capability.scope !== 'installation' || resourceId === installationId) &&
        (!sameAppRuntimeCapability(capability, APP_RUNTIME_SUPPORT_CAPABILITIES.provider) ||
            appProviderProfileSchema.safeParse(resourceId).success) &&
        // A grant for all proxy hosts names no host, only the fixed resource.
        (capability.scope !== 'allProxyHosts' || resourceId === ALL_PROXY_HOSTS_RESOURCE) &&
        (isAppRuntimeSupportCapability(capability) ||
            appGrantCapabilitySchema.safeParse(capability).success)
    )
}

export function isLocalAppRuntimePermissionKey(key: string): boolean {
    return /^[a-z][a-z0-9-]{0,31}$/.test(key)
}

export function qualifyAppRuntimePermission(appId: string, permissionKey: string): string {
    return `app:${appId}:${permissionKey}`
}

export function isAppRuntimeGrantAuthorized(
    principal: AppRuntimeAuthorizationSubject,
    grant: AppRuntimeGrant,
    extraPermissions: readonly PermissionKey[] = [],
): boolean {
    if (
        principal.expiresAt.getTime() <= Date.now() ||
        !isAppRuntimeGrantTarget(
            grant.capability,
            grant.resourceId,
            principal.identity.installationId,
        )
    )
        return false
    if (principal.kind === 'service') return grant.allowService

    const hasAppPermission =
        grant.permissionKey !== undefined &&
        principal.appPermissions.includes(
            qualifyAppRuntimePermission(principal.identity.appId, grant.permissionKey),
        )
    if (grant.permissionKey !== undefined && !hasAppPermission) return false
    if (!extraPermissions.every((permission) => principal.permissions.includes(permission)))
        return false
    if (grant.capability.id === 'proxy.hosts.manage-owned.v1' && extraPermissions.length > 0)
        return true

    const required = platformPermissions[grant.capability.id]
    return required
        ? required.some((permission) => principal.permissions.includes(permission))
        : hasAppPermission
}

/** Whether a grant for all proxy hosts covers `capability` for selected proxy hosts. */
export function coversAllProxyHosts(
    grant: AppRuntimeGrant,
    capability: AppRuntimeCapability,
): boolean {
    return (
        capability.scope === 'proxyHosts' &&
        grant.capability.id === capability.id &&
        grant.capability.scope === 'allProxyHosts' &&
        grant.resourceId === ALL_PROXY_HOSTS_RESOURCE &&
        appGrantCapabilitySchema.safeParse(grant.capability).success
    )
}

export function isAppRuntimeAuthorized(
    principal: AppRuntimeAuthorizationSubject,
    capability: AppRuntimeCapability,
    resourceId: string,
    extraPermissions: readonly PermissionKey[] = [],
): boolean {
    return principal.grants.some(
        (grant) =>
            (coversAllProxyHosts(grant, capability) ||
                (grant.resourceId === resourceId &&
                    sameAppRuntimeCapability(grant.capability, capability))) &&
            isAppRuntimeGrantAuthorized(principal, grant, extraPermissions),
    )
}

export function requireAppRuntimeAuthorization(
    principal: AppRuntimeAuthorizationSubject,
    capability: AppRuntimeCapability,
    resourceId: string,
    extraPermissions: readonly PermissionKey[] = [],
): void {
    if (!isAppRuntimeAuthorized(principal, capability, resourceId, extraPermissions))
        throw new AppRuntimeAuthorityError('forbidden')
}

export function requireAppRuntimePermission(
    principal: AppRuntimeAuthorizationSubject,
    permissionKey: string,
): void {
    if (
        principal.kind !== 'user' ||
        principal.expiresAt.getTime() <= Date.now() ||
        !isLocalAppRuntimePermissionKey(permissionKey) ||
        !principal.appPermissions.includes(
            qualifyAppRuntimePermission(principal.identity.appId, permissionKey),
        )
    )
        throw new AppRuntimeAuthorityError('forbidden')
}
