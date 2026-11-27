import '@tanstack/react-start/server-only'

import { createHash } from 'node:crypto'
import { and, asc, desc, eq, gt, lte, or, sql } from 'drizzle-orm'

import { appRuntimeEventRetention, appRuntimeEvents } from '@/db/schema.ts'
import type { AuthTransaction } from '@/server/Auth/Core/Types/database.types.ts'
import {
    decodeBase64Url,
    decryptSecret,
    encryptSecret,
} from '@/server/Auth/Core/encryption.server.ts'
import {
    APP_RUNTIME_SUPPORT_CAPABILITIES,
    coversAllProxyHosts,
    isAppRuntimeGrantAuthorized,
    isAppRuntimeGrantTarget,
    requireAppRuntimeAuthorization,
} from './authority-policy.server.ts'
import { resolveAppRuntimePrincipalInTransaction } from './authority.server.ts'
import { appRecordId } from './contract.ts'
import {
    AppRuntimeAuthorityError,
    type AppRuntimeCredentials,
    type AppRuntimeEvent,
    type AppRuntimeEventInput,
    type AppRuntimePrincipal,
} from './Types/authority.types.ts'

const eventOrderLock = 871369124
const cursorLifetimeMs = 15 * 60 * 1000
const pageSize = 100
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

async function readAppEventFloor(
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

export function appRuntimeEventCursorContext(principal: AppRuntimePrincipal): string {
    const grants = principal.grants
        .map(({ capability, resourceId, allowService, permissionKey }) =>
            JSON.stringify([
                capability.id,
                capability.scope,
                resourceId,
                allowService,
                permissionKey,
            ]),
        )
        .toSorted()
    const { appId, installationId, generation, uid } = principal.identity
    const fingerprint = createHash('sha256')
        .update(
            JSON.stringify([
                appId,
                installationId,
                generation,
                uid,
                principal.kind,
                principal.delegationId,
                principal.sessionId,
                principal.user?.id,
                principal.authorizationEpoch.toString(),
                principal.permissions.toSorted(),
                principal.appPermissions.toSorted(),
                grants,
            ]),
        )
        .digest('hex')
    return `app-runtime-event-cursor:v1:${fingerprint}`
}

export async function createAppRuntimeEventCursor(
    position: bigint,
    expiresAt: number,
    context: string,
): Promise<string> {
    const plaintext = Buffer.alloc(16)
    plaintext.writeBigUInt64BE(position)
    plaintext.writeBigUInt64BE(BigInt(expiresAt), 8)
    const { ciphertext, iv } = await encryptSecret(plaintext.toString('base64url'), context)
    return Buffer.concat([iv, ciphertext]).toString('base64url')
}

export async function readAppRuntimeEventCursor(
    cursor: string,
    now: number,
    context: string,
): Promise<bigint> {
    const decoded = cursor.length <= 256 ? decodeBase64Url(cursor) : null
    if (!decoded || decoded.byteLength !== 50) throw new AppRuntimeAuthorityError('cursor_expired')
    try {
        const plaintext = await decryptSecret(
            {
                iv: decoded.subarray(0, 12),
                ciphertext: decoded.subarray(12),
            },
            context,
        )
        const bytes = Buffer.from(plaintext, 'base64url')
        const position = bytes.readBigUInt64BE()
        if (bytes.readBigUInt64BE(8) <= BigInt(now) || position > 9223372036854775807n)
            throw new AppRuntimeAuthorityError('cursor_expired')
        return position
    } catch {
        throw new AppRuntimeAuthorityError('cursor_expired')
    }
}

export async function replayAppRuntimeEventsInTransaction(
    transaction: AuthTransaction,
    credentials: AppRuntimeCredentials,
    cursor?: string,
): Promise<{ events: AppRuntimeEvent[]; cursor: string }> {
    const principal = await resolveAppRuntimePrincipalInTransaction(transaction, credentials)
    const { installationId } = principal.identity
    requireAppRuntimeAuthorization(
        principal,
        APP_RUNTIME_SUPPORT_CAPABILITIES.events,
        installationId,
    )
    const context = appRuntimeEventCursorContext(principal)
    const now = Date.now()
    const cursorPosition =
        cursor === undefined ? null : await readAppRuntimeEventCursor(cursor, now, context)
    // Keep the retention floor and delivered page in the same committed prefix.
    await transaction.execute(
        sql`select pg_advisory_xact_lock_shared(${eventOrderLock}, hashtext(${installationId}))`,
    )
    const floor = await readAppEventFloor(transaction, installationId)
    if (cursorPosition !== null && cursorPosition < floor)
        throw new AppRuntimeAuthorityError('cursor_expired')
    const position = cursorPosition ?? floor
    const filter = principal.grants
        .filter((grant) => isAppRuntimeGrantAuthorized(principal, grant))
        .map((grant) =>
            // A grant for all proxy hosts covers the events of every host it reads or probes.
            coversAllProxyHosts(grant, { id: grant.capability.id, scope: 'proxyHosts' })
                ? and(
                      eq(appRuntimeEvents.capabilityId, grant.capability.id),
                      eq(appRuntimeEvents.scope, 'proxyHosts'),
                  )
                : and(
                      eq(appRuntimeEvents.capabilityId, grant.capability.id),
                      eq(appRuntimeEvents.scope, grant.capability.scope),
                      eq(appRuntimeEvents.resourceId, grant.resourceId),
                  ),
        )
    if (filter.length === 0) throw new AppRuntimeAuthorityError('unauthorized')
    const rows = await transaction
        .select()
        .from(appRuntimeEvents)
        .where(
            and(
                eq(appRuntimeEvents.installationId, installationId),
                gt(appRuntimeEvents.sequence, position),
                or(...filter),
            ),
        )
        .orderBy(asc(appRuntimeEvents.sequence))
        .limit(pageSize)
    const expiresAt = now + cursorLifetimeMs
    const events = await Promise.all(
        rows.map(async (row) => {
            const event: AppRuntimeEvent = {
                id: row.id,
                cursor: await createAppRuntimeEventCursor(row.sequence, expiresAt, context),
                type: row.type,
                resourceId: row.resourceId,
                occurredAt: row.occurredAt.toISOString(),
            }
            if (row.revision !== null) Object.assign(event, { revision: row.revision })
            if (row.payload !== null) Object.assign(event, { payload: row.payload })
            return event
        }),
    )
    let nextCursor = events.at(-1)?.cursor
    if (nextCursor === undefined) {
        // The authorized page is empty. Advance past the filtered rows in this locked prefix.
        const [latest] = await transaction
            .select({ position: appRuntimeEvents.sequence })
            .from(appRuntimeEvents)
            .where(
                and(
                    eq(appRuntimeEvents.installationId, installationId),
                    gt(appRuntimeEvents.sequence, position),
                ),
            )
            .orderBy(desc(appRuntimeEvents.sequence))
            .limit(1)
        nextCursor = await createAppRuntimeEventCursor(
            latest?.position ?? position,
            expiresAt,
            context,
        )
    }
    if (principal.expiresAt.getTime() <= Date.now())
        throw new AppRuntimeAuthorityError('unauthorized')
    return { events, cursor: nextCursor }
}
