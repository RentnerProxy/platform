import '@tanstack/react-start/server-only'

import { and, eq, inArray, sql } from 'drizzle-orm'
import { HOST_MONITORING_APP, HOST_MONITORING_LIMITS } from '@/config/host-monitoring.config.ts'
import { PERMISSIONS } from '@/config/permissions.config.ts'
import { appRuntimeOwnedProxyHosts, proxyHosts } from '@/db/schema.ts'
import { readProxyHostSummariesInTransaction } from '@/server/Admin/ProxyHostManagement/proxy-hosts.service.ts'
import { isAppRuntimeAuthorized } from '@/server/AppRuntime/authority-policy.server.ts'
import {
    APP_RUNTIME_SUPPORT_CAPABILITIES,
    readAppRuntimeLiveServiceInTransaction,
} from '@/server/AppRuntime/authority.server.ts'
import { readHosts } from '@/server/AppRuntime/hosts.server.ts'
import { appUiEnabled } from '@/server/AppRuntime/ui/transport.server.ts'
import { requirePermissionService } from '@/server/Auth/Access/authorization.service.ts'
import { requirePermissionInTransaction } from '@/server/Auth/Access/rbac.service.ts'
import { getAuthDatabase } from '@/server/Auth/Core/database.server.ts'
import { readLegacyFeatureOwnerInTransaction } from '@/server/LegacyHandoff/ownership.server.ts'
import {
    invokeMonitoringProvider,
    monitoringSampleCache,
} from './host-monitoring-app.provider.server.ts'
import {
    createHostMonitoringAppService,
    type HostMonitoringAppContext,
} from './host-monitoring-app.service.server.ts'

async function readContext(
    actorId: string,
    proxyHostIds: readonly string[],
): Promise<HostMonitoringAppContext> {
    return getAuthDatabase().transaction(
        async (transaction): Promise<HostMonitoringAppContext> => {
            const timeout = `${HOST_MONITORING_LIMITS.transactionTimeoutMs}ms`
            await transaction.execute(
                sql`select set_config('statement_timeout', ${timeout}, true), set_config('lock_timeout', ${timeout}, true), set_config('transaction_timeout', ${timeout}, true)`,
            )
            await requirePermissionInTransaction(transaction, actorId, PERMISSIONS.PROXY_HOSTS_VIEW)
            const owner = await readLegacyFeatureOwnerInTransaction(transaction, 'monitoring')
            if (owner.owner !== 'app') return { owner: 'platform' }
            const { installationId } = owner
            const live = await readAppRuntimeLiveServiceInTransaction(transaction, installationId)
            const provider = live?.providers.find(({ profile }) => profile === 'monitoring')
            const callable =
                appUiEnabled() &&
                live !== null &&
                provider !== undefined &&
                isAppRuntimeAuthorized(
                    live.principal,
                    APP_RUNTIME_SUPPORT_CAPABILITIES.provider,
                    'monitoring',
                )
            const [count] = await transaction
                .select({ total: sql<number>`count(*)::int` })
                .from(proxyHosts)
            const limit = Math.max(
                1,
                Math.min(HOST_MONITORING_APP.providerLimit, Number(count?.total ?? 1)),
            )
            const hosts = new Map<string, string>()
            if (live) {
                const visible = await readProxyHostSummariesInTransaction(transaction, proxyHostIds)
                const owned = new Map(
                    (
                        await transaction
                            .select({
                                proxyHostId: appRuntimeOwnedProxyHosts.proxyHostId,
                                hostId: appRuntimeOwnedProxyHosts.hostId,
                            })
                            .from(appRuntimeOwnedProxyHosts)
                            .where(
                                and(
                                    eq(appRuntimeOwnedProxyHosts.installationId, installationId),
                                    inArray(
                                        appRuntimeOwnedProxyHosts.proxyHostId,
                                        visible.map(({ id }) => id),
                                    ),
                                ),
                            )
                    ).map((row) => [row.proxyHostId, row.hostId]),
                )
                for (const host of visible) {
                    const ownedId = owned.get(host.id)
                    const covered =
                        isAppRuntimeAuthorized(live.principal, readHosts, host.id) ||
                        (ownedId !== undefined &&
                            isAppRuntimeAuthorized(live.principal, readHosts, ownedId))
                    if (!covered) continue
                    hosts.set(host.id, host.id)
                    if (ownedId !== undefined) hosts.set(ownedId, host.id)
                }
            }
            return {
                owner: 'app',
                installationId,
                target:
                    callable && live
                        ? {
                              installationId,
                              generation: live.principal.identity.generation,
                              providerId: provider.id,
                          }
                        : null,
                limit,
                hosts,
            }
        },
        { isolationLevel: 'repeatable read', accessMode: 'read only' },
    )
}

export const hostMonitoringAppService = createHostMonitoringAppService({
    requireActor: requirePermissionService,
    readContext,
    cache: monitoringSampleCache,
    invoke: invokeMonitoringProvider,
    now: Date.now,
})
