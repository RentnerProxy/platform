import '@tanstack/react-start/server-only'

import { and, eq, inArray, or } from 'drizzle-orm'
import { appRuntimeGrants } from '@/db/schema.ts'
import type { AuthTransaction } from '@/server/Auth/Core/Types/database.types.ts'
import { ALL_PROXY_HOSTS_RESOURCE } from './contract.ts'
import { appendAppRuntimeEventInTransaction } from './event-log.server.ts'

export type ProxyHostEventType =
    | 'proxyHostCreated'
    | 'proxyHostUpdated'
    | 'proxyHostEnabled'
    | 'proxyHostDisabled'
    | 'proxyHostRemoved'

export interface ProxyHostEvent {
    readonly proxyHostId: string
    readonly type: ProxyHostEventType
}

/** Read is preferred, so an app that holds both grants records the event under read. */
const coveringCapabilities = ['proxy.hosts.read.v1', 'diagnostics.upstream.probe.v1'] as const

/** Stored host settings, as a summary or a table row, with the enabled state and timestamps. */
type HostSettings = {
    readonly enabled: boolean
    readonly createdAt?: Date
    readonly updatedAt?: Date
}

/** The stored settings of a host apart from its enabled state and timestamps. */
function settingsView({
    createdAt: _created,
    updatedAt: _updated,
    enabled: _enabled,
    ...settings
}: HostSettings): string {
    return JSON.stringify(settings)
}

/**
 * The event a change of a host's stored settings produces: `proxyHostUpdated` when anything an
 * app sees in the listing besides the enabled state changed, otherwise the enabled transition,
 * otherwise none.
 */
export function proxyHostChange<Settings extends HostSettings>(
    previous: Settings,
    next: Settings,
): ProxyHostEventType | null {
    if (settingsView(previous) !== settingsView(next)) return 'proxyHostUpdated'
    if (previous.enabled === next.enabled) return null
    return next.enabled ? 'proxyHostEnabled' : 'proxyHostDisabled'
}

/**
 * Record each host change once for every installation whose published read or probe grant covers
 * the host, in the transaction that made the change, so an event exists exactly when the change
 * commits. A grant for all proxy hosts covers every host. `exceptInstallationId` names an
 * installation that made the change through its own owned-host operation; its operation result
 * already reports the change.
 */
export async function recordProxyHostEventsInTransaction(
    transaction: AuthTransaction,
    events: readonly ProxyHostEvent[],
    exceptInstallationId?: string,
): Promise<void> {
    if (events.length === 0) return
    const hostIds = [...new Set(events.map(({ proxyHostId }) => proxyHostId))]
    const grants = await transaction
        .select({
            installationId: appRuntimeGrants.installationId,
            capabilityId: appRuntimeGrants.capabilityId,
            scope: appRuntimeGrants.scope,
            resourceId: appRuntimeGrants.resourceId,
        })
        .from(appRuntimeGrants)
        .where(
            and(
                inArray(appRuntimeGrants.capabilityId, [...coveringCapabilities]),
                or(
                    and(
                        eq(appRuntimeGrants.scope, 'allProxyHosts'),
                        eq(appRuntimeGrants.resourceId, ALL_PROXY_HOSTS_RESOURCE),
                    ),
                    and(
                        eq(appRuntimeGrants.scope, 'proxyHosts'),
                        inArray(appRuntimeGrants.resourceId, hostIds),
                    ),
                ),
            ),
        )
    // A stable order keeps the per-installation event locks deadlock-free across writers.
    const installations = [...new Set(grants.map(({ installationId }) => installationId))]
        .filter((installationId) => installationId !== exceptInstallationId)
        .toSorted()
    for (const installationId of installations) {
        const held = grants.filter((grant) => grant.installationId === installationId)
        for (const { proxyHostId, type } of events) {
            const capabilityId = coveringCapabilities.find((id) =>
                held.some(
                    (grant) =>
                        grant.capabilityId === id &&
                        (grant.scope === 'allProxyHosts' || grant.resourceId === proxyHostId),
                ),
            )
            if (capabilityId === undefined) continue
            // oxlint-disable-next-line no-await-in-loop -- Events keep the order of the changes.
            await appendAppRuntimeEventInTransaction(transaction, {
                installationId,
                capability: { id: capabilityId, scope: 'proxyHosts' },
                type,
                resourceId: proxyHostId,
            })
        }
    }
}
