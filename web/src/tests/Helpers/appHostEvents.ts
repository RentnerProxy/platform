import { randomUUID } from 'node:crypto'
import { asc, eq, inArray } from 'drizzle-orm'
import {
    appRuntimeEventRetention,
    appRuntimeEvents,
    appRuntimeGenerations,
    appRuntimeGrants,
    appRuntimeInstallations,
} from '@/db/schema.ts'
import { APP_RUNTIME_SUPPORT_CAPABILITIES } from '@/server/AppRuntime/authority-policy.server.ts'
import {
    activateAppRuntimeGenerationInTransaction,
    registerAppRuntimeGenerationInTransaction,
    replaceAppRuntimeGrantsInTransaction,
} from '@/server/AppRuntime/lifecycle.server.ts'
import type {
    AppRuntimeGrant,
    AppRuntimeIdentity,
} from '@/server/AppRuntime/Types/authority.types.ts'
import { getAuthDatabase } from '@/server/Auth/Core/database.server.ts'

export const readHosts = { id: 'proxy.hosts.read.v1', scope: 'proxyHosts' } as const
export const probeHosts = { id: 'diagnostics.upstream.probe.v1', scope: 'proxyHosts' } as const
export const monitorHosts = { id: 'diagnostics.upstream.probe.v2', scope: 'proxyHosts' } as const

export function allHostsGrant(capabilityId: string): AppRuntimeGrant {
    return {
        capability: { id: capabilityId, scope: 'allProxyHosts' },
        resourceId: 'all',
        allowService: true,
    }
}

let nextUid = 59_900

/** Register and activate an app that may read change events, with the given host grants. */
export async function installEventApp(
    grants: readonly AppRuntimeGrant[],
): Promise<AppRuntimeIdentity> {
    const installationId = randomUUID()
    const identity = { appId: 'fixture.events', installationId, generation: 1, uid: nextUid++ }
    const leaseExpiresAt = new Date(Date.now() + 60_000)
    await getAuthDatabase().transaction(async (transaction) => {
        await registerAppRuntimeGenerationInTransaction(transaction, {
            identity,
            leaseExpiresAt,
            capabilities: [readHosts, probeHosts, monitorHosts],
        })
        await activateAppRuntimeGenerationInTransaction(transaction, identity, leaseExpiresAt)
    })
    await grantEventApp(identity, grants)
    return identity
}

/** Replace the app's host grants, keeping its permission to read change events. */
export async function grantEventApp(
    identity: AppRuntimeIdentity,
    grants: readonly AppRuntimeGrant[],
): Promise<void> {
    await getAuthDatabase().transaction((transaction) =>
        replaceAppRuntimeGrantsInTransaction(transaction, identity, [
            {
                capability: APP_RUNTIME_SUPPORT_CAPABILITIES.events,
                resourceId: identity.installationId,
                allowService: true,
            },
            ...grants,
        ]),
    )
}

/** The host events recorded for an installation, oldest first. */
export async function hostEventsOf(installationId: string) {
    return getAuthDatabase()
        .select({
            type: appRuntimeEvents.type,
            capabilityId: appRuntimeEvents.capabilityId,
            scope: appRuntimeEvents.scope,
            resourceId: appRuntimeEvents.resourceId,
        })
        .from(appRuntimeEvents)
        .where(eq(appRuntimeEvents.installationId, installationId))
        .orderBy(asc(appRuntimeEvents.sequence))
}

export async function removeEventApps(identities: readonly AppRuntimeIdentity[]): Promise<void> {
    const ids = identities.map(({ installationId }) => installationId)
    if (ids.length === 0) return
    await getAuthDatabase().transaction(async (transaction) => {
        await transaction
            .delete(appRuntimeEvents)
            .where(inArray(appRuntimeEvents.installationId, ids))
        await transaction
            .delete(appRuntimeEventRetention)
            .where(inArray(appRuntimeEventRetention.installationId, ids))
        await transaction
            .delete(appRuntimeGrants)
            .where(inArray(appRuntimeGrants.installationId, ids))
        await transaction
            .delete(appRuntimeGenerations)
            .where(inArray(appRuntimeGenerations.installationId, ids))
        await transaction
            .delete(appRuntimeInstallations)
            .where(inArray(appRuntimeInstallations.id, ids))
    })
}
