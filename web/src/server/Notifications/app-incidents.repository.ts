// oxlint-disable-next-line import/no-unassigned-import -- App incident authority is a privileged transaction boundary.
import '@tanstack/react-start/server-only'

import { randomUUID } from 'node:crypto'
import { and, eq, inArray, sql } from 'drizzle-orm'
import { PERMISSIONS } from '@/config/permissions.config.ts'
import type { PermissionKey } from '@/config/Types/permissions-config.types.ts'
import {
    appRuntimeGenerations,
    appRuntimeGrants,
    appRuntimeOwnedProxyHosts,
    hostDomains,
    proxyHosts,
} from '@/db/schema.ts'
import type { AppIncidentResolution } from '@/lib/Notifications/Types/notifications.types.ts'
import { ALL_PROXY_HOSTS_RESOURCE } from '@/server/AppRuntime/contract.ts'
import { HOST_EVENT_CAPABILITIES } from '@/server/AppRuntime/host-events.server.ts'
import type { AuthTransaction } from '@/server/Auth/Core/Types/database.types.ts'
import { resolveAppIncidents } from './app-incidents.ts'
import { observeNotificationSignals } from './incident-engine.ts'
import { resolveEffectiveNotificationConfigurationInTransaction } from './notification-access.ts'
import {
    lockNotificationConfiguration,
    lockNotificationRuntime,
    readNotificationRuntime,
    writeNotificationRuntime,
} from './notification-storage.ts'
import type { NotificationDeliveryClaim } from './Types/notification-internal.types.ts'
import type { AppIncidentFacts } from './Types/app-incidents.types.ts'
import type { NotificationIncident, NotificationState } from './Types/notification-state.types.ts'

const APP_INCIDENT_CAPABILITY = 'notifications.incidents.manage.v1'

type OpenAppIncident = NotificationIncident & {
    app: NonNullable<NotificationIncident['app']>
}

function isOpenAppIncident(incident: NotificationIncident): incident is OpenAppIncident {
    return incident.app !== undefined && incident.recoveredAt === null
}

/**
 * Read what decides whether the apps may still assert their incidents. The app tables are read
 * without locks: a change that commits after this read is seen by the next reconcile.
 */
async function readAppIncidentFacts(
    transaction: AuthTransaction,
    incidents: readonly NotificationIncident[],
): Promise<AppIncidentFacts> {
    const installationIds = [
        ...new Set(
            incidents.flatMap((incident) => (incident.app ? [incident.app.installationId] : [])),
        ),
    ]
    const hostIds = [
        ...new Set(
            incidents.flatMap((incident) =>
                incident.app?.resource ? [incident.app.resource.proxyHostId] : [],
            ),
        ),
    ]
    if (installationIds.length === 0)
        return { active: new Set(), grants: [], owned: new Map(), hostnames: new Map() }
    const [active, grants, owned, hosts] = await Promise.all([
        transaction
            .select({ installationId: appRuntimeGenerations.installationId })
            .from(appRuntimeGenerations)
            .where(
                and(
                    inArray(appRuntimeGenerations.installationId, installationIds),
                    eq(appRuntimeGenerations.state, 'active'),
                ),
            ),
        transaction
            .select({
                installationId: appRuntimeGrants.installationId,
                capabilityId: appRuntimeGrants.capabilityId,
                scope: appRuntimeGrants.scope,
                resourceId: appRuntimeGrants.resourceId,
            })
            .from(appRuntimeGrants)
            .where(
                and(
                    inArray(appRuntimeGrants.installationId, installationIds),
                    inArray(appRuntimeGrants.capabilityId, [
                        APP_INCIDENT_CAPABILITY,
                        ...HOST_EVENT_CAPABILITIES,
                    ]),
                ),
            ),
        hostIds.length === 0
            ? []
            : transaction
                  .select({
                      installationId: appRuntimeOwnedProxyHosts.installationId,
                      hostId: appRuntimeOwnedProxyHosts.hostId,
                      proxyHostId: appRuntimeOwnedProxyHosts.proxyHostId,
                  })
                  .from(appRuntimeOwnedProxyHosts)
                  .where(
                      and(
                          inArray(appRuntimeOwnedProxyHosts.installationId, installationIds),
                          inArray(appRuntimeOwnedProxyHosts.proxyHostId, hostIds),
                      ),
                  ),
        hostIds.length === 0
            ? []
            : transaction
                  .select({
                      id: proxyHosts.id,
                      // Hosts are named by their first domain, as everywhere an Owner picks one.
                      hostname: sql<
                          string | null
                      >`(select d.domain from ${hostDomains} d where d.proxy_host_id = "proxy_hosts"."id" order by d.domain limit 1)`,
                  })
                  .from(proxyHosts)
                  .where(inArray(proxyHosts.id, hostIds)),
    ])
    return {
        active: new Set(active.map(({ installationId }) => installationId)),
        grants,
        owned: new Map(
            owned.map(({ installationId, proxyHostId, hostId }) => [
                `${installationId}:${proxyHostId}`,
                hostId,
            ]),
        ),
        hostnames: new Map(hosts.map(({ id, hostname }) => [id, hostname])),
    }
}

function holdsIncidentGrant(facts: AppIncidentFacts, installationId: string) {
    return facts.grants.some(
        (grant) =>
            grant.installationId === installationId &&
            grant.capabilityId === APP_INCIDENT_CAPABILITY &&
            grant.scope === 'installation' &&
            grant.resourceId === installationId,
    )
}

/** A grant to read or probe the host covers it, whether it names the platform or the app's ID. */
function coversHost(facts: AppIncidentFacts, installationId: string, proxyHostId: string) {
    const ownedHostId = facts.owned.get(`${installationId}:${proxyHostId}`)
    return facts.grants.some(
        (grant) =>
            grant.installationId === installationId &&
            HOST_EVENT_CAPABILITIES.some((capability) => capability === grant.capabilityId) &&
            ((grant.scope === 'allProxyHosts' && grant.resourceId === ALL_PROXY_HOSTS_RESOURCE) ||
                (grant.scope === 'proxyHosts' &&
                    (grant.resourceId === proxyHostId || grant.resourceId === ownedHostId))),
    )
}

/** Why the platform can no longer keep an open incident, or undefined while the app may. */
function unkeepableReason(
    incident: OpenAppIncident,
    facts: AppIncidentFacts,
): AppIncidentResolution | undefined {
    const { installationId, resource } = incident.app
    if (!facts.active.has(installationId)) return 'appStopped'
    if (!holdsIncidentGrant(facts, installationId)) return 'grantRevoked'
    if (
        resource &&
        (!facts.hostnames.has(resource.proxyHostId) ||
            !coversHost(facts, installationId, resource.proxyHostId))
    )
        return 'resourceUnavailable'
    return undefined
}

/**
 * Close the open app incidents whose installation stopped or lost the incident grant, and those
 * whose host is gone or no longer covered, each with its reason. It reads app tables without
 * locking them, like the host availability reconcile.
 */
export async function reconcileAppIncidentsInTransaction(
    transaction: AuthTransaction,
    state: NotificationState,
    now: number,
): Promise<NotificationState> {
    const open = state.incidents.filter(isOpenAppIncident)
    if (open.length === 0) return state
    const facts = await readAppIncidentFacts(transaction, open)
    const resolutions = new Map<string, AppIncidentResolution>()
    for (const incident of open) {
        const reason = unkeepableReason(incident, facts)
        if (reason !== undefined) resolutions.set(incident.id, reason)
    }
    return resolveAppIncidents(state, resolutions, now)
}

/**
 * Resolve an installation's open incidents once it has no active generation, so a stop or an
 * uninstall ends them promptly. The caller holds the installation lock; configuration and
 * runtime follow in the usual order. An update keeps its active generation and resolves nothing.
 */
export async function resolveStoppedAppIncidentsInTransaction(
    transaction: AuthTransaction,
    installationId: string,
): Promise<void> {
    const snapshot = await readNotificationRuntime(transaction)
    if (
        !snapshot.engine.incidents.some(
            (incident) =>
                isOpenAppIncident(incident) && incident.app.installationId === installationId,
        )
    )
        return
    const configuration = await resolveEffectiveNotificationConfigurationInTransaction(
        transaction,
        await lockNotificationConfiguration(transaction),
    )
    const runtime = await lockNotificationRuntime(transaction)
    const now = Date.now()
    const resolved = await reconcileAppIncidentsInTransaction(transaction, runtime.engine, now)
    if (resolved === runtime.engine) return
    await writeNotificationRuntime(transaction, {
        ...runtime,
        engine: observeNotificationSignals(resolved, configuration, [], now, randomUUID),
    })
}

/**
 * Whether an app incident delivery may still be sent, with the payload to send. The incident must
 * exist in the state the delivery announces. A failure notice also needs the app to be running
 * with its grants, and for a host the owner's right to view hosts. A recovery needs only the
 * owner's right: the platform may end an incident because the app lost its grants.
 */
export async function authorizeAppIncidentDeliveryInTransaction(
    transaction: AuthTransaction,
    claim: NotificationDeliveryClaim,
    ownerPermissions: readonly PermissionKey[] | null,
): Promise<NotificationDeliveryClaim['payload'] | null> {
    const { payload } = claim
    if (payload.category !== 'app_incident' || payload.type === 'test') return payload
    const runtime = await readNotificationRuntime(transaction)
    const incident = runtime.engine.incidents.find(
        (candidate) =>
            candidate.id === payload.incidentId && candidate.resourceId === payload.resourceId,
    )
    const app = incident?.app
    if (!incident || !app) return null
    const recovery = payload.type === 'recovery'
    if (recovery !== (incident.recoveredAt !== null)) return null
    const host = app.resource
    if (host && ownerPermissions && !ownerPermissions.includes(PERMISSIONS.PROXY_HOSTS_VIEW))
        return null
    const facts = await readAppIncidentFacts(transaction, [incident])
    if (
        !recovery &&
        (!isOpenAppIncident(incident) || unkeepableReason(incident, facts) !== undefined)
    )
        return null
    if (!payload.app) return null
    // Only a notice that announced a host names it, and then by the host as it is now.
    const hostname = host && payload.app.resource ? facts.hostnames.get(host.proxyHostId) : null
    const { resource: _announced, ...shown } = payload.app
    return {
        ...payload,
        app: { ...shown, ...(hostname ? { resource: { type: 'proxyHost', hostname } } : {}) },
    }
}
