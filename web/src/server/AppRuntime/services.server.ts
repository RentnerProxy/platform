import '@tanstack/react-start/server-only'

import { sql } from 'drizzle-orm'
import { setTimeout as delay } from 'node:timers/promises'
import type { z } from 'zod'

import { getAuthDatabase } from '@/server/Auth/Core/database.server.ts'
import type { AuthTransaction } from '@/server/Auth/Core/Types/database.types.ts'
import {
    isAppRuntimeAuthorized,
    readAppRuntimeContextInTransaction,
    readAppRuntimeSecretInTransaction,
    resolveAppRuntimePrincipalInTransaction,
} from './authority.server.ts'
import {
    appAuditEvent,
    appAuthorizationRequest,
    appNotification,
    appProxyHostChange,
    appProxyHostQuery,
    appRpcLimits,
    appUpstreamProbe,
} from './contract.ts'
import { replayAppRuntimeEventsInTransaction } from './events.server.ts'
import { listAppProxyHosts, probeAppProxyUpstream } from './hosts.server.ts'
import { recordAppRuntimeMessageInTransaction } from './messages.server.ts'
import {
    cancelAppOperation,
    getAppOperation,
    updateAppOwnedProxyHost,
} from './operations.server.ts'
import { AppRuntimeProblem } from './problem.ts'
import { AppRuntimeAuthorityError, type AppRuntimeEvent } from './Types/authority.types.ts'
import type { AppRuntimeCall } from './Types/gateway.types.ts'

const authorityProblems = {
    unauthorized: new AppRuntimeProblem(
        401,
        'unauthorized',
        'App authority has expired or is invalid.',
    ),
    forbidden: new AppRuntimeProblem(
        403,
        'scopeDenied',
        'App operation is outside the current grant.',
    ),
    not_found: new AppRuntimeProblem(404, 'notFound', 'App resource is unavailable.'),
    conflict: new AppRuntimeProblem(409, 'conflict', 'App operation conflicts with current state.'),
    cursor_expired: new AppRuntimeProblem(
        410,
        'cursorExpired',
        'Resynchronize authorized app state.',
    ),
    invalid_input: new AppRuntimeProblem(400, 'invalidRequest', 'Invalid App API request.'),
} as const

export function parseAppInput<T>(schema: z.ZodType<T>, value: unknown): T {
    const parsed = schema.safeParse(value)
    if (!parsed.success) throw authorityProblems.invalid_input
    return parsed.data
}

export async function withAppRuntimeErrors<T>(run: () => Promise<T>): Promise<T> {
    try {
        return await run()
    } catch (error) {
        if (error instanceof AppRuntimeAuthorityError) throw authorityProblems[error.code]
        throw error
    }
}

export function appRuntimeTransaction<T>(
    signal: AbortSignal,
    run: (transaction: AuthTransaction) => Promise<T>,
): Promise<T> {
    signal.throwIfAborted()
    return getAuthDatabase().transaction(async (transaction) => {
        signal.throwIfAborted()
        const budget = appRpcLimits.requestMs + 'ms'
        await transaction.execute(sql`select set_config('transaction_timeout', ${budget}, true),
            set_config('statement_timeout', ${budget}, true),
            set_config('lock_timeout', '2000ms', true)`)
        signal.throwIfAborted()
        const result = await run(transaction)
        signal.throwIfAborted()
        return result
    })
}

function json(body: unknown, status = 200): Response {
    return Response.json(body, { status, headers: { 'Cache-Control': 'no-store' } })
}

function required(value: string | undefined): string {
    if (value === undefined) throw authorityProblems.invalid_input
    return value
}

async function subscribe(call: AppRuntimeCall): Promise<Response> {
    const disconnect = new AbortController()
    const keepAlive = AbortSignal.any([call.streamSignal, disconnect.signal])
    let cursor = call.cursor
    const encoder = new TextEncoder()
    function enqueueEvents(
        controller: ReadableStreamDefaultController<Uint8Array>,
        events: readonly AppRuntimeEvent[],
    ): boolean {
        if (events.length === 0) return false
        const batch = events.map(
            (event) => 'id: ' + event.cursor + '\ndata: ' + JSON.stringify(event) + '\n\n',
        )
        controller.enqueue(encoder.encode(batch.join('')))
        return true
    }

    async function pull(controller: ReadableStreamDefaultController<Uint8Array>) {
        try {
            if (keepAlive.aborted) return controller.close()
            for (let poll = 0; poll < 5; poll += 1) {
                const signal = AbortSignal.any([
                    keepAlive,
                    AbortSignal.timeout(appRpcLimits.requestMs),
                ])
                // oxlint-disable-next-line no-await-in-loop -- Each poll resumes at the latest durable cursor.
                const sent = await appRuntimeTransaction(signal, async (transaction) => {
                    const page = await replayAppRuntimeEventsInTransaction(
                        transaction,
                        call.credentials,
                        cursor,
                    )
                    signal.throwIfAborted()
                    cursor = page.cursor
                    return enqueueEvents(controller, page.events)
                })
                if (sent) return
                // oxlint-disable-next-line no-await-in-loop -- Bound idle polling without concurrent transactions.
                await delay(1_000, undefined, { signal: keepAlive })
            }
            controller.enqueue(encoder.encode(': keepalive\n\n'))
        } catch {
            if (!disconnect.signal.aborted) controller.close()
        }
    }

    const stream = await appRuntimeTransaction(call.signal, async (transaction) => {
        const initialPage = await replayAppRuntimeEventsInTransaction(
            transaction,
            call.credentials,
            cursor,
        )
        call.signal.throwIfAborted()
        cursor = initialPage.cursor
        return new ReadableStream<Uint8Array>({
            start(controller) {
                // Commit this delivery while the initial authority and sequence locks are held.
                controller.enqueue(encoder.encode(': connected\n\n'))
                enqueueEvents(controller, initialPage.events)
            },
            pull,
            cancel() {
                disconnect.abort()
            },
        })
    })
    return new Response(stream, {
        headers: { 'Content-Type': 'text/event-stream', 'Cache-Control': 'no-store' },
    })
}

export function executeAppRuntimeCall(call: AppRuntimeCall): Promise<Response> {
    const { credentials, body, resourceId, idempotencyKey, signal, requestId } = call
    const transact = <T>(run: (transaction: AuthTransaction) => Promise<T>) =>
        appRuntimeTransaction(signal, run)
    return withAppRuntimeErrors(async () => {
        switch (call.operation) {
            case 'context':
                return transact(async (transaction) => {
                    if (credentials.delegation !== undefined)
                        await resolveAppRuntimePrincipalInTransaction(transaction, credentials)
                    return json(
                        await readAppRuntimeContextInTransaction(transaction, credentials.identity),
                    )
                })
            case 'authorization': {
                const input = parseAppInput(appAuthorizationRequest, body)
                return transact(async (transaction) => {
                    const principal = await resolveAppRuntimePrincipalInTransaction(
                        transaction,
                        credentials,
                    )
                    return json({
                        allowed: isAppRuntimeAuthorized(
                            principal,
                            input.capability,
                            input.resourceId,
                        ),
                    })
                })
            }
            case 'listHosts':
                return json(
                    await listAppProxyHosts(
                        credentials,
                        parseAppInput(appProxyHostQuery, body),
                        signal,
                    ),
                )
            case 'updateHost':
                return json(
                    await updateAppOwnedProxyHost(
                        credentials,
                        parseAppInput(appProxyHostChange, body),
                        required(idempotencyKey),
                        requestId,
                        signal,
                    ),
                    202,
                )
            case 'probe':
                return json(
                    await probeAppProxyUpstream(
                        credentials,
                        parseAppInput(appUpstreamProbe, body),
                        signal,
                    ),
                )
            case 'notification':
            case 'audit': {
                const message =
                    call.operation === 'audit'
                        ? { kind: 'audit' as const, payload: parseAppInput(appAuditEvent, body) }
                        : {
                              kind: 'notification' as const,
                              payload: parseAppInput(appNotification, body),
                          }
                await transact((transaction) =>
                    recordAppRuntimeMessageInTransaction(
                        transaction,
                        credentials,
                        required(idempotencyKey),
                        message,
                    ),
                )
                return new Response(null, { status: 204, headers: { 'Cache-Control': 'no-store' } })
            }
            case 'secret':
                return transact(async (transaction) => {
                    const principal = await resolveAppRuntimePrincipalInTransaction(
                        transaction,
                        credentials,
                    )
                    return json(
                        await readAppRuntimeSecretInTransaction(
                            transaction,
                            principal,
                            required(resourceId),
                        ),
                    )
                })
            case 'provider':
                await transact((transaction) =>
                    resolveAppRuntimePrincipalInTransaction(transaction, credentials),
                )
                throw authorityProblems.not_found
            case 'operation':
                return json(await getAppOperation(credentials, required(resourceId), signal))
            case 'cancelOperation':
                return json(
                    await cancelAppOperation(
                        credentials,
                        required(resourceId),
                        required(idempotencyKey),
                        requestId,
                        signal,
                    ),
                    202,
                )
            case 'events':
                return subscribe(call)
        }
    })
}
