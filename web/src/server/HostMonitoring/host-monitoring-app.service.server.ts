import '@tanstack/react-start/server-only'

import { PERMISSIONS } from '@/config/permissions.config.ts'
import type { HostMonitoringAppSummary } from '@/lib/HostMonitoring/Types/host-monitoring-app.types.ts'
import { hostMonitoringSummarySchema } from '@/lib/HostMonitoring/validation.ts'
import { HostMonitoringError } from './host-monitoring.errors.ts'
import { mapMonitoringSamples } from './host-monitoring-app.mapping.ts'
import type {
    invokeMonitoringProvider,
    monitoringSampleCache,
    MonitoringProviderTarget,
} from './host-monitoring-app.provider.server.ts'

/** What the database says about one request. Nothing in it is cached between requests. */
export type HostMonitoringAppContext =
    | { readonly owner: 'platform' }
    | {
          readonly owner: 'app'
          readonly installationId: string
          /** The live generation's monitoring provider; null when the app cannot be called. */
          readonly target: MonitoringProviderTarget | null
          /** At most the provider's limit: the number of proxy hosts. */
          readonly limit: number
          /** Sample host IDs to platform host IDs, for visible hosts the app's grant covers. */
          readonly hosts: ReadonlyMap<string, string>
      }

export interface HostMonitoringAppServiceDependencies {
    readonly requireActor: (permission: typeof PERMISSIONS.PROXY_HOSTS_VIEW) => Promise<{
        readonly id: string
    }>
    readonly readContext: (
        actorId: string,
        proxyHostIds: readonly string[],
    ) => Promise<HostMonitoringAppContext>
    readonly cache: Pick<typeof monitoringSampleCache, 'read'>
    readonly invoke: typeof invokeMonitoringProvider
    readonly now: () => number
}

export function createHostMonitoringAppService(dependencies: HostMonitoringAppServiceDependencies) {
    return {
        /** Per-host availability from the monitoring app; only once an app owns monitoring. */
        async getAppSummary(raw: unknown): Promise<HostMonitoringAppSummary> {
            const input = hostMonitoringSummarySchema.safeParse(raw)
            if (!input.success) throw new HostMonitoringError('invalid_input')
            const actor = await dependencies.requireActor(PERMISSIONS.PROXY_HOSTS_VIEW)
            const context = await dependencies.readContext(actor.id, input.data.proxyHostIds)
            if (context.owner !== 'app') throw new HostMonitoringError('not_handed_off')
            const { installationId, target, limit, hosts } = context
            if (!target) return { status: 'unavailable' }
            // Nothing the user may see and the app may report on: no reason to call it.
            if (hosts.size === 0) return { status: 'available', installationId, hosts: [] }
            const key = `${target.installationId}:${target.generation}:${target.providerId}`
            const result = await dependencies.cache.read(key, (signal) =>
                dependencies.invoke(target, limit, signal),
            )
            if (!result.ok) return { status: 'unavailable' }
            return {
                status: 'available',
                installationId,
                hosts: mapMonitoringSamples({
                    samples: result.samples,
                    hosts,
                    now: dependencies.now(),
                }),
            }
        },
    }
}
