import { createHash } from 'node:crypto'
import { and, count, eq, lte, sql } from 'drizzle-orm'

import { appRuntimeMessages } from '@/db/schema.ts'
import type { AuthTransaction } from '@/server/Auth/Core/Types/database.types.ts'
import {
    requireAppRuntimeAuthorization,
    lockAppRuntimeInstallation,
    lockAppRuntimeUserPolicy,
    resolveAppRuntimePrincipalInTransaction,
} from './authority.server.ts'
import type { AppAuditEventInput, AppNotificationInput } from './contract.ts'
import { appendAppRuntimeEventInTransaction } from './events.server.ts'
import { AppRuntimeProblem } from './problem.ts'
import type { AppRuntimeCredentials } from './Types/authority.types.ts'
import { AppRuntimeAuthorityError } from './Types/authority.types.ts'

const RETENTION_MS = 30 * 24 * 60 * 60 * 1_000
const MAX_MESSAGES_PER_INSTALLATION = 10_000

/**
 * Persist typed app messages and their event together. The caller never supplies provenance.
 * Serialize against the installation row to bound storage even across different actors and keys.
 */
export async function recordAppRuntimeMessageInTransaction(
    transaction: AuthTransaction,
    credentials: AppRuntimeCredentials,
    key: string,
    message:
        | { kind: 'audit'; payload: AppAuditEventInput }
        | { kind: 'notification'; payload: AppNotificationInput },
): Promise<void> {
    const { installationId, generation } = credentials.identity
    if (credentials.delegation !== undefined) await lockAppRuntimeUserPolicy(transaction)
    await lockAppRuntimeInstallation(transaction, credentials.identity, true)
    const principal = await resolveAppRuntimePrincipalInTransaction(transaction, credentials)
    const capability = {
        id: message.kind === 'audit' ? 'app.audit.record' : 'notifications.publish.v1',
        scope: 'installation',
    } as const
    requireAppRuntimeAuthorization(principal, capability, installationId)
    const actor = principal.user?.id ?? 'service'
    const fingerprint = createHash('sha256').update(JSON.stringify(message.payload)).digest('hex')
    const scope = eq(appRuntimeMessages.installationId, installationId)
    const [existing] = await transaction
        .select({ fingerprint: appRuntimeMessages.fingerprint })
        .from(appRuntimeMessages)
        .where(
            and(
                scope,
                eq(appRuntimeMessages.actor, actor),
                eq(appRuntimeMessages.kind, message.kind),
                eq(appRuntimeMessages.key, key),
            ),
        )
        .limit(1)
    if (existing) {
        if (existing.fingerprint !== fingerprint) {
            throw new AppRuntimeProblem(409, 'idempotencyConflict', 'Idempotency key was reused.')
        }
        return
    }

    await transaction
        .delete(appRuntimeMessages)
        .where(and(scope, lte(appRuntimeMessages.createdAt, new Date(Date.now() - RETENTION_MS))))
    const [usage] = await transaction
        .select({ total: count() })
        .from(appRuntimeMessages)
        .where(scope)
    if (!usage || usage.total >= MAX_MESSAGES_PER_INSTALLATION) {
        throw new AppRuntimeProblem(429, 'messageLimit', 'App message storage limit reached.')
    }

    await transaction.insert(appRuntimeMessages).values({
        installationId,
        actor,
        generation,
        kind: message.kind,
        key,
        fingerprint,
        payload: sql`${message.payload}`,
    })
    await appendAppRuntimeEventInTransaction(transaction, {
        installationId,
        capability,
        resourceId: installationId,
        type: message.kind === 'audit' ? 'appAuditRecorded' : 'appNotificationPublished',
        payload: { ...message.payload },
    })
    if (principal.expiresAt.getTime() <= Date.now())
        throw new AppRuntimeAuthorityError('unauthorized')
}
