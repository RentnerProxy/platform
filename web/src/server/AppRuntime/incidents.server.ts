import '@tanstack/react-start/server-only'

import { randomUUID, createHash } from 'node:crypto'
import { and, count, eq, lte, sql } from 'drizzle-orm'
import { z } from 'zod'
import { appRuntimeMessages, appRuntimeOwnedProxyHosts, proxyHosts } from '@/db/schema.ts'
import type { AuthTransaction } from '@/server/Auth/Core/Types/database.types.ts'
import { observeAppIncident } from '@/server/Notifications/app-incidents.ts'
import { resolveEffectiveNotificationConfigurationInTransaction } from '@/server/Notifications/notification-access.ts'
import {
    lockNotificationConfiguration,
    lockNotificationRuntime,
    readNotificationConfiguration,
    writeNotificationRuntime,
} from '@/server/Notifications/notification-storage.ts'
import type { AppIncidentChange } from '@/server/Notifications/Types/app-incidents.types.ts'
import {
    isAppRuntimeAuthorized,
    lockAppRuntimeInstallation,
    lockAppRuntimeUserPolicy,
    requireAppRuntimeAuthorization,
    resolveAppRuntimePrincipalInTransaction,
} from './authority.server.ts'
import type { AppIncidentChangeInput } from './contract.ts'
import { HOST_EVENT_CAPABILITIES } from './host-events.server.ts'
import { APP_MESSAGE_LIMIT, APP_MESSAGE_RETENTION_MS } from './messages.server.ts'
import { readAppIncidentCategoriesInTransaction } from './lifecycle.server.ts'
import { AppRuntimeProblem } from './problem.ts'
import { AppRuntimeAuthorityError } from './Types/authority.types.ts'
import type { AppRuntimeCredentials, AppRuntimePrincipal } from './Types/authority.types.ts'

const INCIDENT_CAPABILITY = {
    id: 'notifications.incidents.manage.v1',
    scope: 'installation',
} as const
const platformHostId = z.uuid().refine((value) => value === value.toLowerCase())

/**
 * The platform host an incident names, when the app may see it. The grant decides before the
 * host's existence, so an uncovered host never reveals whether it exists. The ID is the listed
 * one: a platform host ID, or the app's own ID for a host it owns.
 */
async function readCoveredProxyHost(
    transaction: AuthTransaction,
    principal: AppRuntimePrincipal,
    hostId: string,
): Promise<string> {
    const [owned] = await transaction
        .select({ proxyHostId: appRuntimeOwnedProxyHosts.proxyHostId })
        .from(appRuntimeOwnedProxyHosts)
        .where(
            and(
                eq(appRuntimeOwnedProxyHosts.installationId, principal.identity.installationId),
                eq(appRuntimeOwnedProxyHosts.hostId, hostId),
            ),
        )
        .limit(1)
    const proxyHostId = owned?.proxyHostId ?? hostId
    const covered = HOST_EVENT_CAPABILITIES.some((id) => {
        const capability = { id, scope: 'proxyHosts' }
        return (
            isAppRuntimeAuthorized(principal, capability, proxyHostId) ||
            isAppRuntimeAuthorized(principal, capability, hostId)
        )
    })
    if (!covered || !platformHostId.safeParse(proxyHostId).success)
        throw new AppRuntimeAuthorityError('not_found')
    const [host] = await transaction
        .select({ id: proxyHosts.id })
        .from(proxyHosts)
        .where(eq(proxyHosts.id, proxyHostId))
        .limit(1)
    if (!host) throw new AppRuntimeAuthorityError('not_found')
    return proxyHostId
}

async function describeChange(
    transaction: AuthTransaction,
    principal: AppRuntimePrincipal,
    incidentKey: string,
    change: AppIncidentChangeInput,
): Promise<AppIncidentChange> {
    const { installationId, appId } = principal.identity
    if (change.status === 'resolved')
        return { kind: 'resolve', subject: { installationId, key: incidentKey } }
    const categories = await readAppIncidentCategoriesInTransaction(transaction, installationId)
    const category = categories.find(({ id }) => id === change.category)
    if (!category)
        throw new AppRuntimeProblem(
            409,
            'incidentCategoryUndeclared',
            'Incident category is not declared by the app.',
        )
    // A category either names a host or none; the app cannot mix them.
    if ((category.resource === 'proxyHost') !== (change.resourceId !== undefined))
        throw new AppRuntimeAuthorityError('invalid_input')
    const proxyHostId =
        change.resourceId === undefined
            ? undefined
            : await readCoveredProxyHost(transaction, principal, change.resourceId)
    return {
        kind: 'open',
        severity: change.severity,
        app: {
            installationId,
            appId,
            categoryId: category.id,
            categoryName: category.name,
            key: incidentKey,
            title: change.title,
            message: change.message,
            resource: proxyHostId === undefined ? null : { type: 'proxyHost', proxyHostId },
        },
    }
}

/**
 * Record what an app asserts about one of its incidents. The app states the current condition by
 * its key: open creates or updates, resolved closes, and a repeated state notifies nobody again.
 * While notifications are off or paused after a restore the platform keeps no incident and still
 * answers, because the app asserts its state again with each observation.
 *
 * Locks are taken installation first, then notification configuration, then runtime.
 */
export async function setAppRuntimeIncidentInTransaction(
    transaction: AuthTransaction,
    credentials: AppRuntimeCredentials,
    incidentKey: string,
    idempotencyKey: string,
    change: AppIncidentChangeInput,
): Promise<void> {
    const { installationId, generation } = credentials.identity
    if (credentials.delegation !== undefined) await lockAppRuntimeUserPolicy(transaction)
    await lockAppRuntimeInstallation(transaction, credentials.identity, true)
    const principal = await resolveAppRuntimePrincipalInTransaction(transaction, credentials)
    requireAppRuntimeAuthorization(principal, INCIDENT_CAPABILITY, installationId)
    const actor = principal.user?.id ?? 'service'
    const payload = { incidentKey, ...change }
    const fingerprint = createHash('sha256').update(JSON.stringify(payload)).digest('hex')
    const scope = and(
        eq(appRuntimeMessages.installationId, installationId),
        eq(appRuntimeMessages.kind, 'incident'),
    )
    const [existing] = await transaction
        .select({ fingerprint: appRuntimeMessages.fingerprint })
        .from(appRuntimeMessages)
        .where(
            and(
                scope,
                eq(appRuntimeMessages.actor, actor),
                eq(appRuntimeMessages.key, idempotencyKey),
            ),
        )
        .limit(1)
    if (existing) {
        if (existing.fingerprint !== fingerprint)
            throw new AppRuntimeProblem(409, 'idempotencyConflict', 'Idempotency key was reused.')
        return
    }
    const asserted = await describeChange(transaction, principal, incidentKey, change)

    // The unlocked read spares an opening app the locks while notifications are off.
    const snapshot = await readNotificationConfiguration(transaction)
    if (asserted.kind === 'open' && (!snapshot.enabled || snapshot.pausedAfterRestore)) return
    const stored = await lockNotificationConfiguration(transaction)
    const configuration = await resolveEffectiveNotificationConfigurationInTransaction(
        transaction,
        stored,
    )
    const runtime = await lockNotificationRuntime(transaction)
    const outcome = observeAppIncident(
        runtime.engine,
        configuration,
        asserted,
        Date.now(),
        randomUUID,
    )
    if (outcome.result === 'limit' || outcome.result === 'saturated')
        throw new AppRuntimeProblem(429, 'incidentLimit', 'Too many open app incidents.')
    if (outcome.state !== runtime.engine)
        await writeNotificationRuntime(transaction, { ...runtime, engine: outcome.state })
    // A change made while notifications are off must stay repeatable after they resume.
    if (stored.enabled && !stored.pausedAfterRestore) {
        await transaction
            .delete(appRuntimeMessages)
            .where(
                and(
                    eq(appRuntimeMessages.installationId, installationId),
                    lte(
                        appRuntimeMessages.createdAt,
                        new Date(Date.now() - APP_MESSAGE_RETENTION_MS),
                    ),
                ),
            )
        const [usage] = await transaction
            .select({ total: count() })
            .from(appRuntimeMessages)
            .where(scope)
        if (!usage || usage.total >= APP_MESSAGE_LIMIT)
            throw new AppRuntimeProblem(429, 'messageLimit', 'App message storage limit reached.')
        await transaction.insert(appRuntimeMessages).values({
            installationId,
            actor,
            generation,
            kind: 'incident',
            key: idempotencyKey,
            fingerprint,
            payload: sql`${payload}`,
        })
    }
    if (principal.expiresAt.getTime() <= Date.now())
        throw new AppRuntimeAuthorityError('unauthorized')
}
