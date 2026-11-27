import '@tanstack/react-start/server-only'

import { createHash } from 'node:crypto'
import { and, asc, desc, eq, gt, inArray, or, sql } from 'drizzle-orm'

import { appRuntimeEvents } from '@/db/schema.ts'
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
    requireAppRuntimeAuthorization,
} from './authority-policy.server.ts'
import { resolveAppRuntimePrincipalInTransaction } from './authority.server.ts'
import { eventOrderLock, readAppEventFloor } from './event-log.server.ts'
import { HOST_EVENT_CAPABILITIES } from './host-events.server.ts'
import {
    AppRuntimeAuthorityError,
    type AppRuntimeCredentials,
    type AppRuntimeEvent,
    type AppRuntimePrincipal,
} from './Types/authority.types.ts'

export { appendAppRuntimeEventInTransaction } from './event-log.server.ts'

const cursorLifetimeMs = 15 * 60 * 1000
const pageSize = 100

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
        .map((grant) => {
            // A grant that covers a host receives its lifecycle events under any covering
            // capability, so revoking the grant that recorded an event keeps it for the others.
            const capability = (HOST_EVENT_CAPABILITIES as readonly string[]).includes(
                grant.capability.id,
            )
                ? inArray(appRuntimeEvents.capabilityId, [...HOST_EVENT_CAPABILITIES])
                : eq(appRuntimeEvents.capabilityId, grant.capability.id)
            // A grant for all proxy hosts covers the events of every host it reads or probes.
            return coversAllProxyHosts(grant, { id: grant.capability.id, scope: 'proxyHosts' })
                ? and(capability, eq(appRuntimeEvents.scope, 'proxyHosts'))
                : and(
                      capability,
                      eq(appRuntimeEvents.scope, grant.capability.scope),
                      eq(appRuntimeEvents.resourceId, grant.resourceId),
                  )
        })
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
