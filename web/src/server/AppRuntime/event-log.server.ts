import '@tanstack/react-start/server-only'

import { and, desc, eq, gt, lte, sql } from 'drizzle-orm'
import { appRuntimeEventRetention, appRuntimeEvents } from '@/db/schema.ts'
import type { AuthTransaction } from '@/server/Auth/Core/Types/database.types.ts'
import { isAppRuntimeGrantTarget } from './authority-policy.server.ts'
import { appRecordId } from './contract.ts'
import { AppRuntimeAuthorityError, type AppRuntimeEventInput } from './Types/authority.types.ts'

/**
 * The durable app event log. Writers append here inside the transaction that makes the change;
 * replay lives in events.server.ts. Keeping the writes apart lets platform write paths record
 * events without loading the runtime authority.
 */

/** Held through commit so readers never skip an earlier sequence allocated by another writer. */
export const eventOrderLock = 871369124
const eventRetentionMs = 30 * 24 * 60 * 60 * 1000
const retainedEventLimit = 4_096
const maxEventPayloadBytes = 16_384
const eventTypePattern = /^[a-z][a-zA-Z0-9]{0,63}$/

async function readExpiredPosition(
    transaction: AuthTransaction,
    installationId: string,
): Promise<bigint> {
    const [expired] = await transaction
        .select({ position: appRuntimeEvents.sequence })
        .from(appRuntimeEvents)
        .where(
            and(
                eq(appRuntimeEvents.installationId, installationId),
                lte(appRuntimeEvents.occurredAt, new Date(Date.now() - eventRetentionMs)),
            ),
        )
        .orderBy(desc(appRuntimeEvents.sequence))
        .limit(1)
    return expired?.position ?? 0n
}

async function trimAppEvents(transaction: AuthTransaction, installationId: string): Promise<void> {
    const [overflow] = await transaction
        .select({ position: appRuntimeEvents.sequence })
        .from(appRuntimeEvents)
        .where(eq(appRuntimeEvents.installationId, installationId))
        .orderBy(desc(appRuntimeEvents.sequence))
        .limit(1)
        .offset(retainedEventLimit)
    const expired = await readExpiredPosition(transaction, installationId)
    const excess = overflow?.position ?? 0n
    const floor = expired > excess ? expired : excess
    if (floor === 0n) return

    await transaction
        .insert(appRuntimeEventRetention)
        .values({ installationId, floor })
        .onConflictDoUpdate({
            target: appRuntimeEventRetention.installationId,
            set: { floor },
            setWhere: gt(sql`excluded.floor`, appRuntimeEventRetention.floor),
        })
    await transaction
        .delete(appRuntimeEvents)
        .where(
            and(
                eq(appRuntimeEvents.installationId, installationId),
                lte(appRuntimeEvents.sequence, floor),
            ),
        )
}

export async function readAppEventFloor(
    transaction: AuthTransaction,
    installationId: string,
): Promise<bigint> {
    const [retained] = await transaction
        .select({ floor: appRuntimeEventRetention.floor })
        .from(appRuntimeEventRetention)
        .where(eq(appRuntimeEventRetention.installationId, installationId))
    const floor = retained?.floor ?? 0n
    const expired = await readExpiredPosition(transaction, installationId)
    return expired > floor ? expired : floor
}

export async function appendAppRuntimeEventInTransaction(
    transaction: AuthTransaction,
    event: AppRuntimeEventInput,
): Promise<string> {
    const { installationId, type, capability, resourceId, revision, payload } = event
    if (
        !appRecordId.safeParse(installationId).success ||
        !eventTypePattern.test(type) ||
        !isAppRuntimeGrantTarget(capability, resourceId, installationId) ||
        (revision !== undefined && !appRecordId.safeParse(revision).success) ||
        (payload !== undefined && Buffer.byteLength(JSON.stringify(payload)) > maxEventPayloadBytes)
    )
        throw new AppRuntimeAuthorityError('invalid_input')

    // Hold through commit so readers never skip an earlier sequence allocated by another writer.
    await transaction.execute(
        sql`select pg_advisory_xact_lock(${eventOrderLock}, hashtext(${installationId}))`,
    )
    const [row] = await transaction
        .insert(appRuntimeEvents)
        .values({
            installationId,
            type,
            capabilityId: capability.id,
            scope: capability.scope,
            resourceId,
            occurredAt: sql`clock_timestamp()`,
            ...(revision === undefined ? {} : { revision }),
            ...(payload === undefined ? {} : { payload: sql`${payload}` }),
        })
        .returning({ id: appRuntimeEvents.id })
    if (!row) throw new Error('App runtime event could not be persisted.')
    await trimAppEvents(transaction, installationId)
    return row.id
}
