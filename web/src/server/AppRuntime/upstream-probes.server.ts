import '@tanstack/react-start/server-only'

import { and, eq, inArray } from 'drizzle-orm'
import { z } from 'zod'
import { appRuntimeOwnedProxyHosts, hostDomains, proxyHosts } from '@/db/schema.ts'
import type { DomainDiagnosticsResult } from '@/lib/RuntimeDiagnostics/Types/domain-diagnostics.types.ts'
import type { AuthTransaction } from '@/server/Auth/Core/Types/database.types.ts'
import { inspectControllerDomain } from '@/server/Controller/domain-diagnostics.server.ts'
import { getBackgroundDatabase } from '@/server/Foundation/background-database.server.ts'
import { ResourceAdmissionError } from '@/server/Foundation/resource-admission.ts'
import type { HostMonitoringProbeContext } from '@/server/HostMonitoring/Types/host-monitoring-probe.types.ts'
import { readHostMonitoringContextsInTransaction } from '@/server/RuntimeDiagnostics/domain-diagnostics-data.ts'
import { DomainDiagnosticsError } from '@/server/RuntimeDiagnostics/domain-diagnostics.errors.ts'
import { isAppRuntimeAuthorized, resolveAppRuntimePrincipalInTransaction } from './authority.server.ts'
import { appUpstreamProbeBatch } from './contract.ts'
import { appProbeRevision } from './hosts.server.ts'
import { AppRuntimeAuthorityError } from './Types/authority.types.ts'
import type { AppRuntimeCredentials } from './Types/authority.types.ts'
import type {
    AppUpstreamProbeBatch,
    AppUpstreamProbeBatchResult,
    AppUpstreamProbeOutcome,
    AppUpstreamProbeRefusal,
    AppUpstreamProbeTarget,
} from './Types/upstream-probes.types.ts'
import { upstreamProbeOutcome } from './upstream-probe-outcome.ts'

const probeHosts = { id: 'diagnostics.upstream.probe.v2', scope: 'proxyHosts' } as const
const platformHostId = z.uuid().refine((value) => value === value.toLowerCase())

type Inspect = typeof inspectControllerDomain

/** A probe the platform may run, with the host fence it read before the probe. */
type Selection =
    | { readonly ready: false; readonly outcome: AppUpstreamProbeRefusal }
    | {
          readonly ready: true
          readonly proxyHostId: string
          readonly context: HostMonitoringProbeContext
      }

/**
 * Authorize every probe of the batch once and read its host fence in the same snapshot. The grant
 * decides before the host state, so an uncovered host never reveals whether it exists.
 */
async function readSelections(
    transaction: AuthTransaction,
    credentials: AppRuntimeCredentials,
    probes: readonly AppUpstreamProbeTarget[],
): Promise<readonly Selection[]> {
    const principal = await resolveAppRuntimePrincipalInTransaction(transaction, credentials)
    if (principal.expiresAt.getTime() <= Date.now())
        throw new AppRuntimeAuthorityError('unauthorized')
    const owned = await transaction
        .select({
            hostId: appRuntimeOwnedProxyHosts.hostId,
            proxyHostId: appRuntimeOwnedProxyHosts.proxyHostId,
        })
        .from(appRuntimeOwnedProxyHosts)
        .where(
            and(
                eq(appRuntimeOwnedProxyHosts.installationId, principal.identity.installationId),
                inArray(
                    appRuntimeOwnedProxyHosts.hostId,
                    probes.map(({ hostId }) => hostId),
                ),
            ),
        )
    const ownedIds = new Map(owned.map(({ hostId, proxyHostId }) => [hostId, proxyHostId]))
    const covered = probes.map(({ hostId }) => {
        const proxyHostId = ownedIds.get(hostId)
        const authorized =
            (proxyHostId !== undefined &&
                isAppRuntimeAuthorized(principal, probeHosts, proxyHostId)) ||
            isAppRuntimeAuthorized(principal, probeHosts, hostId)
        return authorized ? (proxyHostId ?? hostId) : null
    })
    const ids = [
        ...new Set(
            covered.filter(
                (id): id is string => id !== null && platformHostId.safeParse(id).success,
            ),
        ),
    ]
    const rows =
        ids.length === 0
            ? []
            : await transaction
                  .select({
                      id: proxyHosts.id,
                      enabled: proxyHosts.enabled,
                      domain: hostDomains.domain,
                  })
                  .from(proxyHosts)
                  .leftJoin(hostDomains, eq(hostDomains.proxyHostId, proxyHosts.id))
                  .where(inArray(proxyHosts.id, ids))
    const hosts = new Map<string, { enabled: boolean; domains: Set<string> }>()
    for (const { id, enabled, domain } of rows) {
        const host = hosts.get(id) ?? { enabled, domains: new Set<string>() }
        if (domain !== null) host.domains.add(domain)
        hosts.set(id, host)
    }
    const refusals = probes.map(({ domain }, index): AppUpstreamProbeRefusal | null => {
        const proxyHostId = covered[index]
        if (proxyHostId === null || proxyHostId === undefined) return 'scopeDenied'
        const host = hosts.get(proxyHostId)
        if (!host) return 'hostRemoved'
        if (!host.enabled) return 'hostDisabled'
        return host.domains.has(domain) ? null : 'domainNotFound'
    })
    const contexts = await readHostMonitoringContextsInTransaction(
        transaction,
        probes.flatMap(({ domain }, index) =>
            refusals[index] === null
                ? [{ hostType: 'proxy' as const, hostId: covered[index]!, domain }]
                : [],
        ),
    )
    return probes.map((_probe, index): Selection => {
        const refusal = refusals[index]
        if (refusal !== null && refusal !== undefined) return { ready: false, outcome: refusal }
        const proxyHostId = covered[index]!
        const context = contexts.get(proxyHostId)
        return context?.enabled
            ? { ready: true, proxyHostId, context }
            : { ready: false, outcome: 'configurationChanged' }
    })
}

/** Host fences share the monitoring database class, apart from interactive requests. */
function readBatchSelections(
    credentials: AppRuntimeCredentials,
    probes: readonly AppUpstreamProbeTarget[],
): Promise<readonly Selection[] | null> {
    return getBackgroundDatabase('monitoring')
        .transaction((transaction) => readSelections(transaction, credentials, probes), {
            isolationLevel: 'repeatable read',
        })
        .catch((error: unknown) => {
            // Saturated monitoring capacity makes every probe of the batch busy.
            if (error instanceof ResourceAdmissionError && error.reason !== 'cancelled')
                return null
            throw error
        })
}

async function runProbe(
    inspect: Inspect,
    installationId: string,
    target: AppUpstreamProbeTarget,
    selection: Extract<Selection, { ready: true }>,
    signal?: AbortSignal,
): Promise<DomainDiagnosticsResult | AppUpstreamProbeRefusal> {
    try {
        return await inspect(
            {
                hostType: 'proxy',
                hostId: selection.proxyHostId,
                domain: target.domain,
                expectedRevision: selection.context.revision,
            },
            signal,
            { upstreamOnly: true, timeoutMs: target.timeoutMs, installationId },
        )
    } catch (error) {
        signal?.throwIfAborted()
        if (!(error instanceof DomainDiagnosticsError)) throw error
        if (error.code === 'busy') return 'busy'
        if (error.code === 'rate_limited') return 'rateLimited'
        return 'unavailable'
    }
}

/**
 * Run a monitoring-class batch of upstream probes. Every probe is admitted by the core against
 * this installation's budget, apart from interactive Domain Checks and built-in monitoring, and
 * its result counts only while the grant and the host fence still hold afterwards, as for
 * built-in monitoring. A probe the platform cannot run returns an explicit outcome.
 */
export function createAppUpstreamProbes(inspect: Inspect = inspectControllerDomain) {
    return async (
        credentials: AppRuntimeCredentials,
        raw: AppUpstreamProbeBatch,
        signal?: AbortSignal,
    ): Promise<AppUpstreamProbeBatchResult> => {
        const parsed = appUpstreamProbeBatch.safeParse(raw)
        if (!parsed.success) throw new AppRuntimeAuthorityError('invalid_input')
        const { probes } = parsed.data
        const refused = (outcome: AppUpstreamProbeRefusal) =>
            probes.map(({ hostId, domain }) => ({ outcome, hostId, domain }))
        signal?.throwIfAborted()
        const before = await readBatchSelections(credentials, probes)
        if (before === null) return { results: refused('busy') }
        signal?.throwIfAborted()
        const { installationId } = credentials.identity
        const observed = await Promise.all(
            probes.map((target, index) => {
                const selection = before[index]!
                return selection.ready
                    ? runProbe(inspect, installationId, target, selection, signal)
                    : selection.outcome
            }),
        )
        signal?.throwIfAborted()
        const ran = observed.some((result) => typeof result !== 'string')
        const after = ran ? await readBatchSelections(credentials, probes) : before
        signal?.throwIfAborted()
        const results = probes.map((target, index): AppUpstreamProbeOutcome => {
            const { hostId, domain } = target
            const result = observed[index]!
            if (typeof result === 'string') return { outcome: result, hostId, domain }
            const first = before[index]!
            const last = after?.[index]
            if (!first.ready || !last) return { outcome: 'busy', hostId, domain }
            if (!last.ready) return { outcome: last.outcome, hostId, domain }
            if (
                last.proxyHostId !== first.proxyHostId ||
                last.context.proof !== first.context.proof ||
                last.context.revision !== first.context.revision
            )
                return { outcome: 'configurationChanged', hostId, domain }
            return upstreamProbeOutcome(
                target,
                appProbeRevision(first.context.availability.revision),
                result.stages,
            )
        })
        return { results }
    }
}

export const probeAppProxyUpstreams = createAppUpstreamProbes()
