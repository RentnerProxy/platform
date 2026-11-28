import { proxyUpstreamPoolSchema } from '@/lib/ProxyRuntime/upstreamPool.ts'
import {
    readResponseCacheSettingsMap,
    writeResponseCacheSettings,
} from '@/server/ProxyRuntime/proxy-runtime-settings.ts'
import type { ResponseCacheSettings } from '@/lib/ResponseCache/Types/response-cache.types.ts'
import type { ProxyHostMutationActor, ProxyHostRow } from './Types/proxy-hosts-mutations.types.ts'
import type { PermissionKey } from '@/config/Types/permissions-config.types.ts'
import '@tanstack/react-start/server-only'
import { assignHostTagsInTransaction } from '@/server/Admin/HostTags/host-tags.storage.server.ts'

import { and, eq, inArray, isNotNull, ne, or, sql } from 'drizzle-orm'
import { proxyHostSummaryColumns } from './proxy-hosts.storage.server.ts'

import { PERMISSIONS } from '@/config/permissions.config.ts'
import { accessPolicies, hostDomains, proxyHosts } from '@/db/schema.ts'
import type { ProxyHostSummary } from '@/lib/Admin/ProxyHostManagement/Types/proxy-hosts.types.ts'
import {
    lockProxyRuntimeSettings,
    readProxyHostHttpSettings,
    writeProxyHostHttpSettings,
} from '@/server/ProxyRuntime/proxy-runtime-settings.ts'
import { requirePermissionInTransaction } from '@/server/Auth/Access/rbac.service.ts'
import type { AuthTransaction } from '@/server/Auth/Core/Types/database.types.ts'
import {
    createProxyHostInputSchema,
    updateProxyHostInputSchema,
} from '@/features/Admin/ProxyHostManagement/validation.ts'
import type {
    CreateProxyHostInput,
    UpdateProxyHostInput,
} from '@/features/Admin/ProxyHostManagement/Types/validation.types.ts'
import { ProxyHostDomainError } from './proxy-hosts.errors.ts'
import { normalizeUpstreamTlsSettings } from './upstream-tls.service.ts'
import { assertDiscoveryHostEditable } from '@/server/Admin/DockerDiscovery/discovery-storage.server.ts'
import { validateTrustedCaAssignmentInTransaction } from '@/server/Admin/TrustedCaManagement/trusted-cas.service.ts'
import { validateCertificateAssignmentInTransaction } from '@/server/Admin/CertificateManagement/certificates.service.ts'
import { appendAuditEventInTransactionService } from '@/server/Audit/audit.service.ts'
import {
    invalidateHostMonitoringForHostsInTransaction,
    isHostMonitoringHandoffOpenInTransaction,
} from '@/server/HostMonitoring/host-monitoring.repository.ts'
import {
    proxyHostChange,
    recordProxyHostEventsInTransaction,
} from '@/server/AppRuntime/host-events.server.ts'

function invalidInput(): ProxyHostDomainError {
    return new ProxyHostDomainError('invalid_input', 'Proxy host input is invalid.')
}

/** Existing administration callers keep their transaction-local RBAC checks. */
async function authorizeProxyHostMutation(
    transaction: AuthTransaction,
    actor: ProxyHostMutationActor,
    permission: PermissionKey,
): Promise<readonly PermissionKey[]> {
    if (typeof actor === 'string')
        return (await requirePermissionInTransaction(transaction, actor, permission)).permissions
    actor.authorize(permission)
    return []
}

function mutationAuditActor(actor: ProxyHostMutationActor) {
    return {
        actorUserId: typeof actor === 'string' ? actor : actor.userId,
        actorKind:
            typeof actor === 'string' || actor.userId !== null
                ? ('user' as const)
                : ('system' as const),
    }
}

function mutationAuditMetadata(actor: ProxyHostMutationActor) {
    return typeof actor === 'string' ? {} : { operationId: actor.operationId }
}

/**
 * Projects stored routing state while retaining the complete ordered pool.
 * SQL-null pools stay absent in legacy summaries rather than adding a new field.
 */
export function toProxyHostSummary(
    proxyHost: ProxyHostRow,
    domains: ReadonlyArray<string>,
): ProxyHostSummary {
    return {
        createdAt: proxyHost.createdAt,
        domains: domains.toSorted(),
        enabled: proxyHost.enabled,
        certificateId: proxyHost.certificateId,
        forceHttps: proxyHost.forceHttps,
        verifyUpstreamTls: proxyHost.verifyUpstreamTls,
        upstreamTlsServerName: proxyHost.upstreamTlsServerName,
        trustedCaId: proxyHost.trustedCaId,
        accessPolicyId: proxyHost.accessPolicyId ?? null,
        forwardHost: proxyHost.forwardHost,
        forwardPort: proxyHost.forwardPort,
        ...(proxyHost.upstreamPool ? { upstreamPool: proxyHost.upstreamPool } : {}),
        forwardScheme: proxyHost.forwardScheme,
        id: proxyHost.id,
        updatedAt: proxyHost.updatedAt,
    }
}

export async function loadProxyHostForUpdate(
    transaction: AuthTransaction,
    proxyHostId: string,
): Promise<ProxyHostRow | null> {
    const rows = await transaction
        .select(proxyHostSummaryColumns)
        .from(proxyHosts)
        .where(eq(proxyHosts.id, proxyHostId))
        .limit(1)
        .for('update')

    return rows.at(0) ?? null
}

async function assertDomainsAvailableInTransaction(
    transaction: AuthTransaction,
    domains: ReadonlyArray<string>,
    currentProxyHostId?: string,
): Promise<void> {
    const condition = currentProxyHostId
        ? and(
              inArray(hostDomains.domain, domains),
              or(
                  isNotNull(hostDomains.redirectHostId),
                  and(
                      isNotNull(hostDomains.proxyHostId),
                      ne(hostDomains.proxyHostId, currentProxyHostId),
                  ),
              ),
          )
        : inArray(hostDomains.domain, domains)
    const conflicts = await transaction
        .select({ domain: hostDomains.domain })
        .from(hostDomains)
        .where(condition)
        .limit(1)

    if (conflicts.length > 0) {
        throw new ProxyHostDomainError('domain_conflict', 'A proxy host domain is already in use.')
    }
}

async function replaceDomainsInTransaction(
    transaction: AuthTransaction,
    proxyHostId: string,
    domains: ReadonlyArray<string>,
): Promise<void> {
    await transaction.delete(hostDomains).where(eq(hostDomains.proxyHostId, proxyHostId))
    await transaction
        .insert(hostDomains)
        .values(domains.toSorted().map((domain) => ({ domain, proxyHostId })))
}

export function parseCreateProxyHostInput(input: CreateProxyHostInput) {
    const parsed = createProxyHostInputSchema.safeParse(input)

    if (!parsed.success) {
        throw invalidInput()
    }

    return parsed.data
}

export function parseUpdateProxyHostInput(input: UpdateProxyHostInput) {
    const parsed = updateProxyHostInputSchema.safeParse(input)

    if (!parsed.success) {
        throw invalidInput()
    }

    return parsed.data
}

/**
 * Validates, authorizes and persists a host within the supplied transaction.
 * Ordered pools share the host's scheme and TLS policy; absent or null pools
 * retain single-target behavior. Native JSONB binding stores pools as objects.
 */
/** The installation that changes a host through its own owned-host operation. */
function actingInstallation(actor: ProxyHostMutationActor): string | undefined {
    return typeof actor === 'string' ? undefined : actor.installationId
}

export async function createProxyHostInTransaction(
    transaction: AuthTransaction,
    actor: ProxyHostMutationActor,
    input: CreateProxyHostInput,
): Promise<ProxyHostSummary> {
    const parsedInput = parseCreateProxyHostInput(input)
    const domains = parsedInput.domains.toSorted()
    await lockProxyRuntimeSettings(transaction)
    const permissions = await authorizeProxyHostMutation(
        transaction,
        actor,
        PERMISSIONS.PROXY_HOSTS_CREATE,
    )
    if (parsedInput.browserCache !== undefined)
        await authorizeProxyHostMutation(transaction, actor, PERMISSIONS.PROXY_HOSTS_APPLY)
    if (parsedInput.tagIds !== undefined)
        await authorizeProxyHostMutation(transaction, actor, PERMISSIONS.PROXY_HOSTS_VIEW)
    if (parsedInput.responseCompression != null)
        await authorizeProxyHostMutation(transaction, actor, PERMISSIONS.PROXY_HOSTS_APPLY)
    await assertDomainsAvailableInTransaction(transaction, domains)
    const certificateId = parsedInput.certificateId?.toLowerCase() ?? null
    const forceHttps = parsedInput.forceHttps ?? false
    const upstreamTls = normalizeUpstreamTlsSettings(parsedInput)
    const accessPolicyId = parsedInput.accessPolicyId?.toLowerCase() ?? null
    if (accessPolicyId) {
        await authorizeProxyHostMutation(transaction, actor, PERMISSIONS.ACCESS_POLICIES_ASSIGN)
        const policy = await transaction
            .select({ id: accessPolicies.id })
            .from(accessPolicies)
            .where(eq(accessPolicies.id, accessPolicyId))
            .limit(1)
        if (!policy.at(0)) {
            throw new ProxyHostDomainError('invalid_input', 'Access policy was not found.')
        }
    }
    await validateTrustedCaAssignmentInTransaction(transaction, upstreamTls.trustedCaId)
    await validateCertificateAssignmentInTransaction(
        transaction,
        certificateId,
        forceHttps,
        domains,
    )
    const rows = await transaction
        .insert(proxyHosts)
        .values({
            ...(typeof actor !== 'string' && actor.proxyHostId ? { id: actor.proxyHostId } : {}),
            enabled: parsedInput.enabled,
            certificateId,
            forceHttps,
            ...upstreamTls,
            accessPolicyId,
            forwardHost: parsedInput.forwardHost,
            forwardPort: parsedInput.forwardPort,
            // Bun SQL encodes the object; bypass the Drizzle JSON string encoder.
            upstreamPool: parsedInput.upstreamPool ? sql`${parsedInput.upstreamPool}` : null,
            forwardScheme: parsedInput.forwardScheme,
        })
        .returning(proxyHostSummaryColumns)
    const proxyHost = rows.at(0)

    if (!proxyHost) {
        throw new ProxyHostDomainError('invalid_input', 'Proxy host could not be created.')
    }

    await writeProxyHostHttpSettings(
        transaction,
        proxyHost.id,
        parsedInput.responseCompression
            ? { responseCompression: parsedInput.responseCompression }
            : {},
    )
    await transaction
        .insert(hostDomains)
        .values(domains.map((domain) => ({ domain, proxyHostId: proxyHost.id })))
    if (parsedInput.responseCache !== undefined)
        await writeAuthorizedResponseCacheSettings(
            transaction,
            actor,
            proxyHost.id,
            parsedInput.responseCache,
        )
    const tags =
        parsedInput.tagIds !== undefined || permissions.includes(PERMISSIONS.PROXY_HOSTS_VIEW)
            ? await assignHostTagsInTransaction(
                  transaction,
                  'proxy',
                  proxyHost.id,
                  parsedInput.tagIds,
              )
            : undefined

    if (parsedInput.browserCache !== undefined) {
        const settings = await readProxyHostHttpSettings(transaction, proxyHost.id)
        await writeProxyHostHttpSettings(transaction, proxyHost.id, {
            ...settings,
            browserCache: parsedInput.browserCache,
        })
    }
    await recordProxyHostEventsInTransaction(
        transaction,
        [{ proxyHostId: proxyHost.id, type: 'proxyHostCreated' }],
        actingInstallation(actor),
    )
    await appendAuditEventInTransactionService(transaction, {
        ...mutationAuditActor(actor),
        action: 'create',
        resource: 'proxy-host',
        targetId: proxyHost.id,
        result: 'success',
        ...(typeof actor === 'string' &&
        parsedInput.responseCompression == null &&
        parsedInput.browserCache === undefined
            ? {}
            : {
                  metadata: {
                      ...mutationAuditMetadata(actor),
                      changedFields: [
                          ...(parsedInput.responseCompression == null
                              ? []
                              : ['responseCompression' as const]),
                          ...(parsedInput.browserCache === undefined
                              ? []
                              : ['browserCache' as const]),
                      ],
                  },
              }),
    })

    return {
        ...toProxyHostSummary(proxyHost, domains),
        responseCompression: parsedInput.responseCompression ?? null,
        ...(parsedInput.browserCache ? { browserCache: parsedInput.browserCache } : {}),
        ...(parsedInput.responseCache === undefined
            ? {}
            : { responseCache: parsedInput.responseCache }),
        ...(tags ? { tags } : {}),
    }
}

/**
 * Updates authorized desired state while preserving an omitted pool and clearing
 * an explicitly null pool. Replacement and retained pools must match the scalar
 * primary target; member order and shared TLS policy remain part of routing state.
 * Stored JSONB is canonicalized before comparison so key ordering cannot erase
 * monitoring observations on an unchanged save; meaningful routing changes still
 * invalidate them.
 */
export async function updateProxyHostInTransaction(
    transaction: AuthTransaction,
    actor: ProxyHostMutationActor,
    input: UpdateProxyHostInput,
    discoveryKey?: string,
): Promise<ProxyHostSummary> {
    const parsedInput = parseUpdateProxyHostInput(input)
    const domains = parsedInput.domains.toSorted()
    await lockProxyRuntimeSettings(transaction)
    const permissions = await authorizeProxyHostMutation(
        transaction,
        actor,
        PERMISSIONS.PROXY_HOSTS_UPDATE,
    )
    if (parsedInput.browserCache !== undefined)
        await authorizeProxyHostMutation(transaction, actor, PERMISSIONS.PROXY_HOSTS_APPLY)
    if (parsedInput.tagIds !== undefined)
        await authorizeProxyHostMutation(transaction, actor, PERMISSIONS.PROXY_HOSTS_VIEW)
    await assertDiscoveryHostEditable(transaction, parsedInput.proxyHostId, discoveryKey)
    const proxyHost = await loadProxyHostForUpdate(transaction, parsedInput.proxyHostId)

    if (!proxyHost) {
        throw new ProxyHostDomainError('proxy_host_not_found', 'Proxy host was not found.')
    }

    if (parsedInput.enabled !== proxyHost.enabled) {
        await authorizeProxyHostMutation(
            transaction,
            actor,
            parsedInput.enabled ? PERMISSIONS.PROXY_HOSTS_ENABLE : PERMISSIONS.PROXY_HOSTS_DISABLE,
        )
    }

    await assertDomainsAvailableInTransaction(transaction, domains, proxyHost.id)
    const certificateId =
        parsedInput.certificateId === undefined
            ? proxyHost.certificateId
            : (parsedInput.certificateId?.toLowerCase() ?? null)
    const forceHttps = parsedInput.forceHttps ?? proxyHost.forceHttps
    const existingUpstreamPool = proxyHost.upstreamPool
        ? proxyUpstreamPoolSchema.parse(proxyHost.upstreamPool)
        : null
    const upstreamPool =
        parsedInput.upstreamPool === undefined ? existingUpstreamPool : parsedInput.upstreamPool
    const firstMember = upstreamPool?.members[0]
    if (
        firstMember &&
        (firstMember.host !== parsedInput.forwardHost ||
            firstMember.port !== parsedInput.forwardPort)
    )
        throw invalidInput()
    const upstreamTls = normalizeUpstreamTlsSettings({ ...parsedInput, upstreamPool }, proxyHost)
    const accessPolicyId =
        parsedInput.accessPolicyId === undefined
            ? proxyHost.accessPolicyId
            : (parsedInput.accessPolicyId?.toLowerCase() ?? null)
    if (accessPolicyId) {
        if (accessPolicyId !== proxyHost.accessPolicyId) {
            await authorizeProxyHostMutation(transaction, actor, PERMISSIONS.ACCESS_POLICIES_ASSIGN)
        }
        const policy = await transaction
            .select({ id: accessPolicies.id })
            .from(accessPolicies)
            .where(eq(accessPolicies.id, accessPolicyId))
            .limit(1)
        if (!policy.at(0)) {
            throw new ProxyHostDomainError('invalid_input', 'Access policy was not found.')
        }
    } else if (parsedInput.accessPolicyId !== undefined && proxyHost.accessPolicyId !== null) {
        await authorizeProxyHostMutation(transaction, actor, PERMISSIONS.ACCESS_POLICIES_ASSIGN)
    }
    await validateTrustedCaAssignmentInTransaction(transaction, upstreamTls.trustedCaId)
    await validateCertificateAssignmentInTransaction(
        transaction,
        certificateId,
        forceHttps,
        domains,
    )
    const previousDomains = await transaction
        .select({ domain: hostDomains.domain })
        .from(hostDomains)
        .where(eq(hostDomains.proxyHostId, proxyHost.id))
    const availabilityChanged =
        parsedInput.enabled !== proxyHost.enabled ||
        parsedInput.forwardScheme !== proxyHost.forwardScheme ||
        parsedInput.forwardHost !== proxyHost.forwardHost ||
        parsedInput.forwardPort !== proxyHost.forwardPort ||
        JSON.stringify(upstreamPool) !== JSON.stringify(existingUpstreamPool) ||
        JSON.stringify(previousDomains.map(({ domain }) => domain).toSorted()) !==
            JSON.stringify(domains) ||
        (parsedInput.forwardScheme === 'https' &&
            (upstreamTls.verifyUpstreamTls !== proxyHost.verifyUpstreamTls ||
                upstreamTls.upstreamTlsServerName !== proxyHost.upstreamTlsServerName ||
                upstreamTls.trustedCaId !== proxyHost.trustedCaId))
    const rows = await transaction
        .update(proxyHosts)
        .set({
            enabled: parsedInput.enabled,
            certificateId,
            forceHttps,
            ...upstreamTls,
            accessPolicyId,
            forwardHost: parsedInput.forwardHost,
            forwardPort: parsedInput.forwardPort,
            upstreamPool: upstreamPool ? sql`${upstreamPool}` : null,
            forwardScheme: parsedInput.forwardScheme,
            updatedAt: new Date(),
        })
        .where(eq(proxyHosts.id, proxyHost.id))
        .returning(proxyHostSummaryColumns)
    const updatedProxyHost = rows.at(0)

    if (!updatedProxyHost) {
        throw new ProxyHostDomainError('proxy_host_not_found', 'Proxy host was not found.')
    }

    const httpSettings = { ...(await readProxyHostHttpSettings(transaction, proxyHost.id)) }
    const previousCompression = httpSettings.responseCompression ?? null
    const browserCacheChanged =
        parsedInput.browserCache !== undefined &&
        JSON.stringify(parsedInput.browserCache) !== JSON.stringify(httpSettings.browserCache)
    if (parsedInput.responseCompression !== undefined) {
        if (parsedInput.responseCompression !== previousCompression)
            await authorizeProxyHostMutation(transaction, actor, PERMISSIONS.PROXY_HOSTS_APPLY)
        if (parsedInput.responseCompression === null) delete httpSettings.responseCompression
        else httpSettings.responseCompression = parsedInput.responseCompression
        await writeProxyHostHttpSettings(transaction, proxyHost.id, httpSettings)
    }
    await replaceDomainsInTransaction(transaction, proxyHost.id, domains)
    if (availabilityChanged)
        await invalidateHostMonitoringForHostsInTransaction(
            transaction,
            [proxyHost.id],
            !parsedInput.enabled && proxyHost.enabled ? 'monitoring_disabled' : 'policy_changed',
        )
    if (parsedInput.responseCache !== undefined)
        await writeAuthorizedResponseCacheSettings(
            transaction,
            actor,
            proxyHost.id,
            parsedInput.responseCache,
        )
    const tags =
        parsedInput.tagIds !== undefined || permissions.includes(PERMISSIONS.PROXY_HOSTS_VIEW)
            ? await assignHostTagsInTransaction(
                  transaction,
                  'proxy',
                  proxyHost.id,
                  parsedInput.tagIds,
              )
            : undefined

    if (parsedInput.browserCache !== undefined && browserCacheChanged) {
        const settings = await readProxyHostHttpSettings(transaction, proxyHost.id)
        await writeProxyHostHttpSettings(transaction, proxyHost.id, {
            ...settings,
            browserCache: parsedInput.browserCache,
        })
    }
    const change = proxyHostChange(
        toProxyHostSummary(
            proxyHost,
            previousDomains.map(({ domain }) => domain),
        ),
        toProxyHostSummary(updatedProxyHost, domains),
    )
    if (change)
        await recordProxyHostEventsInTransaction(
            transaction,
            [{ proxyHostId: proxyHost.id, type: change }],
            actingInstallation(actor),
        )
    await appendAuditEventInTransactionService(transaction, {
        ...mutationAuditActor(actor),
        action: 'update',
        resource: 'proxy-host',
        targetId: proxyHost.id,
        result: 'success',
        metadata: {
            ...mutationAuditMetadata(actor),
            changedFields: [
                'domains',
                'upstream',
                'tls',
                ...(parsedInput.responseCompression === undefined ||
                parsedInput.responseCompression === previousCompression
                    ? []
                    : ['responseCompression' as const]),
                ...(browserCacheChanged ? (['browserCache'] as const) : []),
                ...(parsedInput.tagIds ? ['tags' as const] : []),
                ...(parsedInput.certificateId === undefined ? [] : (['certificate'] as const)),
                ...(parsedInput.trustedCaId === undefined ? [] : (['trustedCa'] as const)),
                ...(parsedInput.enabled === proxyHost.enabled ? [] : (['status'] as const)),
                ...(accessPolicyId === proxyHost.accessPolicyId ? [] : (['accessPolicy'] as const)),
            ],
            ...(accessPolicyId === proxyHost.accessPolicyId
                ? {}
                : {
                      assigned: accessPolicyId !== null,
                      previousId: proxyHost.accessPolicyId,
                      nextId: accessPolicyId,
                  }),
        },
    })

    const savedHttpSettings = await readProxyHostHttpSettings(transaction, proxyHost.id)
    const savedResponseCache = (
        await readResponseCacheSettingsMap(transaction, [proxyHost.id])
    ).get(proxyHost.id)
    return {
        ...toProxyHostSummary(updatedProxyHost, domains),
        responseCompression: savedHttpSettings.responseCompression ?? null,
        browserCache: savedHttpSettings.browserCache,
        ...(savedResponseCache ? { responseCache: savedResponseCache } : {}),
        ...(tags ? { tags } : {}),
    }
}

async function writeAuthorizedResponseCacheSettings(
    transaction: AuthTransaction,
    actor: ProxyHostMutationActor,
    proxyHostId: string,
    settings: ResponseCacheSettings | null,
): Promise<void> {
    const existing =
        (await readResponseCacheSettingsMap(transaction, [proxyHostId])).get(proxyHostId) ?? null
    if (JSON.stringify(existing) === JSON.stringify(settings)) return
    await authorizeProxyHostMutation(transaction, actor, PERMISSIONS.PROXY_HOSTS_APPLY)
    await writeResponseCacheSettings(transaction, proxyHostId, settings)
    await appendAuditEventInTransactionService(transaction, {
        ...mutationAuditActor(actor),
        action: 'save',
        resource: 'proxy-host-settings',
        targetId: proxyHostId,
        result: 'success',
        metadata: { ...mutationAuditMetadata(actor), enabled: settings !== null },
    })
}

export async function deleteProxyHostInTransaction(
    transaction: AuthTransaction,
    actor: ProxyHostMutationActor,
    proxyHostId: string,
): Promise<void> {
    await lockProxyRuntimeSettings(transaction)
    await authorizeProxyHostMutation(transaction, actor, PERMISSIONS.PROXY_HOSTS_DELETE)
    const host = await loadProxyHostForUpdate(transaction, proxyHostId)
    if (!host) throw new ProxyHostDomainError('proxy_host_not_found', 'Proxy host was not found.')
    await writeProxyHostHttpSettings(transaction, host.id, {})
    await writeResponseCacheSettings(transaction, host.id, null)
    await assertDiscoveryHostEditable(transaction, host.id)
    // Deleting the host would cascade into the monitoring rows an open handoff exports and an
    // abort hands back to platform.
    if (await isHostMonitoringHandoffOpenInTransaction(transaction, host.id))
        throw new ProxyHostDomainError(
            'monitoring_handoff_open',
            'Proxy host monitoring is being handed over to an app.',
        )
    await assignHostTagsInTransaction(transaction, 'proxy', host.id, [])
    await transaction.delete(proxyHosts).where(eq(proxyHosts.id, host.id))
    await invalidateHostMonitoringForHostsInTransaction(transaction, [host.id])
    await recordProxyHostEventsInTransaction(
        transaction,
        [{ proxyHostId: host.id, type: 'proxyHostRemoved' }],
        actingInstallation(actor),
    )
    await appendAuditEventInTransactionService(transaction, {
        ...mutationAuditActor(actor),
        action: 'delete',
        resource: 'proxy-host',
        targetId: host.id,
        result: 'success',
        ...(typeof actor === 'string' ? {} : { metadata: mutationAuditMetadata(actor) }),
    })
}
