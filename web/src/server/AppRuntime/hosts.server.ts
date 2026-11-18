import '@tanstack/react-start/server-only'

import { createHash } from 'node:crypto'
import { and, asc, eq, gt, inArray, or, sql } from 'drizzle-orm'
import { z } from 'zod'
import { DOMAIN_DIAGNOSTICS_RATE_LIMIT } from '@/config/domain-diagnostics.config.ts'
import { PERMISSIONS } from '@/config/permissions.config.ts'
import type { PermissionKey } from '@/config/Types/permissions-config.types.ts'
import { appRuntimeOwnedProxyHosts, hostDomains, proxyHosts } from '@/db/schema.ts'
import type { ProxyHostSummary } from '@/lib/Admin/ProxyHostManagement/Types/proxy-hosts.types.ts'
import {
    createProxyHostInTransaction,
    deleteProxyHostInTransaction,
    loadProxyHostForUpdate,
    parseCreateProxyHostInput,
    parseUpdateProxyHostInput,
    toProxyHostSummary,
    updateProxyHostInTransaction,
} from '@/server/Admin/ProxyHostManagement/proxy-hosts.mutations.server.ts'
import { proxyHostSummaryColumns } from '@/server/Admin/ProxyHostManagement/proxy-hosts.storage.server.ts'
import type { ProxyHostMutationActor } from '@/server/Admin/ProxyHostManagement/Types/proxy-hosts-mutations.types.ts'
import { getAuthDatabase } from '@/server/Auth/Core/database.server.ts'
import type { AuthTransaction } from '@/server/Auth/Core/Types/database.types.ts'
import { inspectControllerDomain } from '@/server/Controller/domain-diagnostics.server.ts'
import { readDomainDiagnosticsContextInTransaction } from '@/server/RuntimeDiagnostics/domain-diagnostics-data.ts'
import { DomainDiagnosticsError } from '@/server/RuntimeDiagnostics/domain-diagnostics.errors.ts'
import { consumeRateLimit, RateLimitError } from '@/server/Valkey/rate-limiter.service.ts'
import {
    isAppRuntimeAuthorized,
    requireAppRuntimeAuthorization,
    resolveAppRuntimePrincipalInTransaction,
} from './authority.server.ts'
import { isAppRuntimeGrantAuthorized } from './authority-policy.server.ts'
import { appProxyHostQuery, appUpstreamProbe } from './contract.ts'
import { appendAppRuntimeEventInTransaction } from './events.server.ts'
import { AppRuntimeProblem } from './problem.ts'
import { AppRuntimeAuthorityError } from './Types/authority.types.ts'
import type { AppRuntimeCredentials, AppRuntimePrincipal } from './Types/authority.types.ts'
import type {
    AppOwnedProxyHostChange,
    AppProxyHostPage,
    AppProxyHostQuery,
    AppUpstreamProbe,
    AppUpstreamProbeResult,
} from './Types/hosts.types.ts'
import type { AppOperationResult } from './Types/operations.types.ts'

const platformHostId = z.uuid().refine((value) => value === value.toLowerCase())

const readHosts = { id: 'proxy.hosts.read.v1', scope: 'proxyHosts' } as const
const probeHosts = { id: 'diagnostics.upstream.probe.v1', scope: 'proxyHosts' } as const
export const manageOwnedHosts = {
    id: 'proxy.hosts.manage-owned.v1',
    scope: 'ownedProxyHosts',
} as const

/** Keep foreground app RPC database work inside a bounded transaction. */
export async function setAppRuntimeTransactionTimeout(transaction: AuthTransaction): Promise<void> {
    await transaction.execute(sql`select set_config('statement_timeout', '2500ms', true),
        set_config('lock_timeout', '2500ms', true), set_config('transaction_timeout', '3500ms', true)`)
}

export function appProxyHostRevision(host: ProxyHostSummary): string {
    return createHash('sha256')
        .update(JSON.stringify(toProxyHostSummary(host, host.domains)))
        .digest('hex')
}

function projectHost(host: ProxyHostSummary, id: string, hostname: string) {
    return { id, hostname, revision: appProxyHostRevision(host) }
}

export async function listAppProxyHosts(
    credentials: AppRuntimeCredentials,
    raw: AppProxyHostQuery,
): Promise<AppProxyHostPage> {
    const input = appProxyHostQuery.safeParse(raw)
    if (!input.success) throw new AppRuntimeAuthorityError('invalid_input')
    const { limit, cursor } = input.data
    if (cursor !== undefined && !platformHostId.safeParse(cursor).success)
        throw new AppRuntimeAuthorityError('invalid_input')
    return getAuthDatabase().transaction(async (transaction) => {
        await setAppRuntimeTransactionTimeout(transaction)
        const principal = await resolveAppRuntimePrincipalInTransaction(transaction, credentials)
        const allowed = principal.grants.flatMap((grant) =>
            grant.capability.id === readHosts.id &&
            grant.capability.scope === readHosts.scope &&
            isAppRuntimeGrantAuthorized(principal, grant)
                ? [grant.resourceId]
                : [],
        )
        if (allowed.length === 0) return { hosts: [] }
        const rows = await transaction
            .select({
                ...proxyHostSummaryColumns,
                ownedHostId: appRuntimeOwnedProxyHosts.hostId,
                domains: sql<string[]>`array(select d.domain from ${hostDomains} d
                    where d.proxy_host_id = "proxy_hosts"."id" order by d.domain)`,
            })
            .from(proxyHosts)
            .leftJoin(
                appRuntimeOwnedProxyHosts,
                and(
                    eq(appRuntimeOwnedProxyHosts.proxyHostId, proxyHosts.id),
                    eq(appRuntimeOwnedProxyHosts.installationId, principal.identity.installationId),
                ),
            )
            .where(
                and(
                    or(
                        inArray(
                            proxyHosts.id,
                            allowed.filter((id) => platformHostId.safeParse(id).success),
                        ),
                        inArray(appRuntimeOwnedProxyHosts.hostId, allowed),
                    ),
                    cursor === undefined ? undefined : gt(proxyHosts.id, cursor),
                    sql`exists (select 1 from ${hostDomains} d where d.proxy_host_id = "proxy_hosts"."id")`,
                ),
            )
            .orderBy(asc(proxyHosts.id))
            .limit(limit + 1)
        const hosts = rows.slice(0, limit).flatMap((row) => {
            const domain = row.domains[0]
            return domain
                ? [
                      projectHost(
                          toProxyHostSummary(row, row.domains),
                          row.ownedHostId ?? row.id,
                          domain,
                      ),
                  ]
                : []
        })
        const nextCursor = rows.at(limit - 1)?.id
        return rows.length > limit && nextCursor ? { hosts, nextCursor } : { hosts }
    })
}

export function ownedHostPermission(input: AppOwnedProxyHostChange): PermissionKey {
    if (input.action === 'remove') return PERMISSIONS.PROXY_HOSTS_DELETE
    return input.expectedRevision === null
        ? PERMISSIONS.PROXY_HOSTS_CREATE
        : PERMISSIONS.PROXY_HOSTS_UPDATE
}

function upsertValues(
    input: Extract<AppOwnedProxyHostChange, { action: 'upsert' }>,
    previous: ProxyHostSummary | null,
) {
    return {
        domains: [input.hostname],
        forwardScheme: input.upstream.scheme,
        forwardHost: input.upstream.address,
        forwardPort: input.upstream.port,
        enabled: previous?.enabled ?? true,
        ...(previous?.forwardScheme === 'https' && input.upstream.scheme === 'https'
            ? {
                  verifyUpstreamTls: previous.verifyUpstreamTls,
                  upstreamTlsServerName: previous.upstreamTlsServerName,
              }
            : {}),
    }
}

/** Call under the proxy settings lock so a concurrent write cannot replace the revision. */
export async function checkAppOwnedProxyHostChange(
    transaction: AuthTransaction,
    principal: AppRuntimePrincipal,
    input: AppOwnedProxyHostChange,
): Promise<ProxyHostSummary | null> {
    requireAppRuntimeAuthorization(principal, manageOwnedHosts, input.hostId, [
        ownedHostPermission(input),
    ])
    const [owner] = await transaction
        .select({ proxyHostId: appRuntimeOwnedProxyHosts.proxyHostId })
        .from(appRuntimeOwnedProxyHosts)
        .where(
            and(
                eq(appRuntimeOwnedProxyHosts.installationId, principal.identity.installationId),
                eq(appRuntimeOwnedProxyHosts.hostId, input.hostId),
            ),
        )
    if (!owner) {
        if (input.expectedRevision !== null)
            throw new AppRuntimeProblem(409, 'hostRevisionConflict', 'Proxy host revision changed')
        // A UUID-shaped app ID cannot shadow an existing Platform host or its grants.
        if (
            platformHostId.safeParse(input.hostId).success &&
            (await loadProxyHostForUpdate(transaction, input.hostId))
        )
            throw new AppRuntimeProblem(
                409,
                'hostOwnershipConflict',
                'Proxy host ID is already in use',
            )
        if (input.action === 'upsert') parseCreateProxyHostInput(upsertValues(input, null))
        return null
    }
    if (input.expectedRevision === null)
        throw new AppRuntimeProblem(409, 'hostRevisionConflict', 'Proxy host revision changed')
    const host = await loadProxyHostForUpdate(transaction, owner.proxyHostId)
    const domains = await transaction
        .select({ domain: hostDomains.domain })
        .from(hostDomains)
        .where(eq(hostDomains.proxyHostId, owner.proxyHostId))
    const summary = host
        ? toProxyHostSummary(
              host,
              domains.map(({ domain }) => domain),
          )
        : null
    if (!summary || appProxyHostRevision(summary) !== input.expectedRevision)
        throw new AppRuntimeProblem(409, 'hostRevisionConflict', 'Proxy host revision changed')
    if (input.action === 'upsert')
        parseUpdateProxyHostInput({
            ...upsertValues(input, summary),
            proxyHostId: summary.id,
        })
    return summary
}

export async function applyAppOwnedProxyHostChange(
    transaction: AuthTransaction,
    principal: AppRuntimePrincipal,
    input: AppOwnedProxyHostChange,
    operationId: string,
): Promise<AppOperationResult> {
    const previous = await checkAppOwnedProxyHostChange(transaction, principal, input)
    const actor: ProxyHostMutationActor = {
        userId: principal.user?.id ?? null,
        operationId,
        ...(!previous && platformHostId.safeParse(input.hostId).success
            ? { proxyHostId: input.hostId }
            : {}),
        authorize: (permission) => {
            if (permission !== ownedHostPermission(input))
                throw new AppRuntimeAuthorityError('forbidden')
            requireAppRuntimeAuthorization(principal, manageOwnedHosts, input.hostId, [permission])
        },
    }
    const { installationId } = principal.identity
    if (input.action === 'remove') {
        if (!previous) throw new AppRuntimeAuthorityError('conflict')
        await deleteProxyHostInTransaction(transaction, actor, previous.id)
        await appendAppRuntimeEventInTransaction(transaction, {
            installationId,
            capability: manageOwnedHosts,
            type: 'proxyHostRemoved',
            resourceId: input.hostId,
        })
        return { action: 'remove', hostId: input.hostId }
    }
    const values = upsertValues(input, previous)
    const saved = previous
        ? await updateProxyHostInTransaction(transaction, actor, {
              ...values,
              proxyHostId: previous.id,
          })
        : await createProxyHostInTransaction(transaction, actor, values)
    if (!previous)
        await transaction.insert(appRuntimeOwnedProxyHosts).values({
            installationId,
            hostId: input.hostId,
            proxyHostId: saved.id,
        })
    const host = { ...projectHost(saved, input.hostId, input.hostname), platformHostId: saved.id }
    await appendAppRuntimeEventInTransaction(transaction, {
        installationId,
        capability: manageOwnedHosts,
        type: 'proxyHostChanged',
        resourceId: input.hostId,
        revision: host.revision,
    })
    return { action: 'upsert', host }
}

async function authorizeProbeSelection(
    transaction: AuthTransaction,
    credentials: AppRuntimeCredentials,
    hostId: string,
) {
    const principal = await resolveAppRuntimePrincipalInTransaction(transaction, credentials)
    const [owner] = await transaction
        .select({ proxyHostId: appRuntimeOwnedProxyHosts.proxyHostId })
        .from(appRuntimeOwnedProxyHosts)
        .where(
            and(
                eq(appRuntimeOwnedProxyHosts.installationId, principal.identity.installationId),
                eq(appRuntimeOwnedProxyHosts.hostId, hostId),
            ),
        )
    if (!owner || !isAppRuntimeAuthorized(principal, probeHosts, owner.proxyHostId))
        requireAppRuntimeAuthorization(principal, probeHosts, hostId)
    const actualId = owner?.proxyHostId ?? hostId
    if (!platformHostId.safeParse(actualId).success) throw new AppRuntimeAuthorityError('not_found')
    const [row] = await transaction
        .select({ domain: hostDomains.domain, enabled: proxyHosts.enabled })
        .from(hostDomains)
        .innerJoin(proxyHosts, eq(proxyHosts.id, hostDomains.proxyHostId))
        .where(eq(hostDomains.proxyHostId, actualId))
        .orderBy(asc(hostDomains.domain))
        .limit(1)
    if (!row) throw new AppRuntimeAuthorityError('not_found')
    return {
        input: { hostType: 'proxy' as const, hostId: actualId, domain: row.domain },
        enabled: row.enabled,
        expiresAt: principal.expiresAt,
    }
}

async function readProbeContext(credentials: AppRuntimeCredentials, hostId: string) {
    return getAuthDatabase().transaction(
        async (transaction) => {
            await setAppRuntimeTransactionTimeout(transaction)
            const selection = await authorizeProbeSelection(transaction, credentials, hostId)
            const context = await readDomainDiagnosticsContextInTransaction(
                transaction,
                selection.input,
            )
            return { ...selection, context }
        },
        { isolationLevel: 'repeatable read' },
    )
}

export async function probeAppProxyUpstream(
    credentials: AppRuntimeCredentials,
    raw: AppUpstreamProbe,
    signal?: AbortSignal,
): Promise<AppUpstreamProbeResult> {
    const parsed = appUpstreamProbe.safeParse(raw)
    if (!parsed.success) throw new AppRuntimeAuthorityError('invalid_input')
    const { hostId, timeoutMs } = parsed.data
    signal?.throwIfAborted()
    const selection = await getAuthDatabase().transaction(async (transaction) => {
        await setAppRuntimeTransactionTimeout(transaction)
        return authorizeProbeSelection(transaction, credentials, hostId)
    })
    signal?.throwIfAborted()
    if (!selection.enabled) return { outcome: 'unreachable' }
    // The controller admits native work with a minimum 1s budget.
    if (timeoutMs < 1_000) return { outcome: 'timedOut' }
    try {
        await consumeRateLimit({
            ...DOMAIN_DIAGNOSTICS_RATE_LIMIT,
            scope: 'app-runtime-upstream-probe',
            identifier: credentials.identity.installationId,
        })
    } catch (error) {
        if (error instanceof RateLimitError)
            throw new AppRuntimeProblem(429, 'rateLimited', 'Upstream probe rate limit reached')
        throw new AppRuntimeProblem(
            503,
            'diagnosticsUnavailable',
            'Upstream diagnostics unavailable',
        )
    }
    signal?.throwIfAborted()
    const before = await readProbeContext(credentials, hostId)
    signal?.throwIfAborted()
    if (!before.context.enabled) return { outcome: 'unreachable' }
    if (before.expiresAt.getTime() <= Date.now()) throw new AppRuntimeAuthorityError('unauthorized')
    const timeout = AbortSignal.timeout(timeoutMs)
    const probeSignal = signal ? AbortSignal.any([signal, timeout]) : timeout
    const request = { ...before.input, expectedRevision: before.context.revision }
    try {
        const result = await inspectControllerDomain(request, probeSignal, {
            upstreamOnly: true,
            timeoutMs,
        })
        signal?.throwIfAborted()
        const after = await readProbeContext(credentials, hostId)
        signal?.throwIfAborted()
        if (
            !after.context.enabled ||
            after.context.proof !== before.context.proof ||
            after.context.revision !== before.context.revision ||
            after.input.domain !== before.input.domain
        )
            throw new AppRuntimeProblem(
                409,
                'hostConfigurationChanged',
                'Proxy host configuration changed',
            )
        const configuration = result.stages.configuration.code
        if (configuration === 'runtime_unavailable')
            throw new AppRuntimeProblem(
                503,
                'diagnosticsUnavailable',
                'Upstream diagnostics unavailable',
            )
        if (configuration !== 'configuration_active')
            throw new AppRuntimeProblem(
                409,
                'hostConfigurationChanged',
                'Proxy host configuration changed',
            )
        const upstream = result.stages.upstream
        if (upstream.httpStatus !== null)
            return { outcome: 'reachable', durationMs: Math.min(timeoutMs, upstream.durationMs) }
        return { outcome: upstream.code === 'upstream_timeout' ? 'timedOut' : 'unreachable' }
    } catch (error) {
        signal?.throwIfAborted()
        if (error instanceof DomainDiagnosticsError) {
            if (timeout.aborted) return { outcome: 'timedOut' }
            throw new AppRuntimeProblem(
                503,
                'diagnosticsUnavailable',
                'Upstream diagnostics unavailable',
            )
        }
        throw error
    }
}
