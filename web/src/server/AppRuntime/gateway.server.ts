import { randomUUID, timingSafeEqual } from 'node:crypto'

import {
    appCursorSchema,
    appDelegationSchema,
    appGenerationSchema,
    appIdSchema,
    appRecordId,
    appRpcLimits,
    appUidSchema,
    isAppWireJson,
} from './contract.ts'
import { AppRuntimeProblem } from './problem.ts'
import type { AppRuntimeCall, AppRuntimeOperation } from './Types/gateway.types.ts'

const invalid = new AppRuntimeProblem(400, 'invalidRequest', 'Invalid App API request.')
const unavailable = new AppRuntimeProblem(503, 'unavailable', 'App API is unavailable.')
const tooLarge = new AppRuntimeProblem(413, 'payloadTooLarge', 'App API payload is too large.')
const timedOut = new AppRuntimeProblem(504, 'deadlineExceeded', 'App API deadline exceeded.')
const notFound = new AppRuntimeProblem(404, 'notFound', 'App API operation was not found.')
const unauthorized = new AppRuntimeProblem(401, 'unauthorized', 'App API credential is invalid.')

const directRoutes = new Map<string, AppRuntimeOperation>([
    ['GET /platform/v1/context', 'context'],
    ['POST /platform/v1/authorization', 'authorization'],
    ['POST /platform/v1/proxy-hosts/query', 'listHosts'],
    ['POST /platform/v1/proxy-hosts/owned', 'updateHost'],
    ['POST /platform/v1/diagnostics/upstream', 'probe'],
    ['POST /platform/v1/notifications', 'notification'],
    ['POST /platform/v1/audit-events', 'audit'],
    ['GET /platform/v1/events', 'events'],
])

const resourceRoutes: readonly [RegExp, AppRuntimeOperation][] = [
    [/^GET \/platform\/v1\/secrets\/([^/]+)$/u, 'secret'],
    [/^GET \/platform\/v1\/providers\/([^/]+)$/u, 'provider'],
    [/^GET \/platform\/v1\/operations\/([^/]+)$/u, 'operation'],
    [/^POST \/platform\/v1\/operations\/([^/]+)\/cancel$/u, 'cancelOperation'],
]

function identifyOperation(request: Request) {
    const url = new URL(request.url)
    if (url.search) throw invalid
    const key = request.method + ' ' + url.pathname
    const direct = directRoutes.get(key)
    if (direct) return { operation: direct }
    for (const [pattern, operation] of resourceRoutes) {
        const match = pattern.exec(key)
        if (match) return { operation, resourceId: requiredRecordId(match[1]) }
    }
    throw notFound
}

function requiredRecordId(value: unknown): string {
    const result = appRecordId.safeParse(value)
    if (!result.success) throw invalid
    return result.data
}

/** Only the peer-checked native broker may supply these installation headers. */
function readIdentity(headers: Headers) {
    const installationId = requiredRecordId(headers.get('X-App-Installation'))
    const generationHeader = headers.get('X-App-Generation') ?? ''
    const uidHeader = headers.get('X-RentnerProxy-App-Uid') ?? ''
    if (!/^[1-9][0-9]{0,15}$/u.test(generationHeader) || !/^[0-9]{5}$/u.test(uidHeader)) {
        throw invalid
    }
    const generation = appGenerationSchema.safeParse(Number(generationHeader))
    const uid = appUidSchema.safeParse(Number(uidHeader))
    const appId = appIdSchema.safeParse(headers.get('X-RentnerProxy-App-Id'))
    if (!appId.success || !generation.success || !uid.success) throw invalid
    return { appId: appId.data, installationId, generation: generation.data, uid: uid.data }
}

function readHeaders(request: Request, operation: AppRuntimeOperation) {
    const { headers } = request
    const rawDelegation = headers.get('X-App-Delegation')
    const delegation = appDelegationSchema.safeParse(rawDelegation ?? undefined)
    if (rawDelegation !== null && !delegation.success) throw invalid
    const rawCursor = headers.get('Last-Event-ID')
    const cursor = appCursorSchema.safeParse(rawCursor ?? undefined)
    if (rawCursor !== null && (operation !== 'events' || !cursor.success)) throw invalid
    const rawKey = headers.get('Idempotency-Key')
    const needsKey =
        operation === 'updateHost' ||
        operation === 'cancelOperation' ||
        operation === 'audit' ||
        operation === 'notification'
    if (!needsKey && rawKey !== null) throw invalid
    return {
        credentials: {
            identity: readIdentity(headers),
            ...(delegation.success && { delegation: delegation.data }),
        },
        ...(needsKey && { idempotencyKey: requiredRecordId(rawKey) }),
        ...(cursor.success && { cursor: cursor.data }),
    }
}

async function readBody(request: Request, hasBody: boolean, signal: AbortSignal) {
    if (!hasBody) {
        if (request.body !== null) throw invalid
        return undefined
    }
    const contentType = request.headers.get('Content-Type')?.split(';')[0]?.trim().toLowerCase()
    if (contentType !== 'application/json' || !request.body) throw invalid

    const reader = request.body.getReader()
    const cancel = () => {
        void reader.cancel().catch(() => undefined)
    }
    const chunks: Uint8Array[] = []
    let size = 0
    signal.addEventListener('abort', cancel, { once: true })
    try {
        while (true) {
            signal.throwIfAborted()
            // oxlint-disable-next-line no-await-in-loop -- Read sequentially to enforce the payload budget.
            const chunk = await reader.read()
            if (chunk.done) break
            size += chunk.value.byteLength
            if (size > appRpcLimits.jsonBytes) throw tooLarge
            chunks.push(chunk.value)
        }
        signal.throwIfAborted()
    } finally {
        cancel()
        signal.removeEventListener('abort', cancel)
        reader.releaseLock()
    }

    try {
        const decoded = new TextDecoder('utf-8', { fatal: true }).decode(
            Buffer.concat(chunks, size),
        )
        const value: unknown = JSON.parse(decoded)
        if (!isAppWireJson(value)) throw invalid
        return value
    } catch {
        throw invalid
    }
}

async function replyWithinDeadline(run: () => Promise<Response>, signal: AbortSignal) {
    signal.throwIfAborted()
    const aborted = Promise.withResolvers<never>()
    const onAbort = () => aborted.reject(timedOut)
    signal.addEventListener('abort', onAbort, { once: true })
    try {
        const work = run().then((response) => {
            if (signal.aborted) {
                void response.body?.cancel().catch(() => undefined)
                throw timedOut
            }
            return response
        })
        return await Promise.race([work, aborted.promise])
    } finally {
        signal.removeEventListener('abort', onAbort)
    }
}

export function createAppRuntimeGateway(
    bridgeToken: string,
    shutdown: AbortSignal,
    execute: (call: AppRuntimeCall) => Promise<Response>,
    manage?: (action: string, body: unknown, signal: AbortSignal) => Promise<Response>,
) {
    const expected = Buffer.from('Bearer ' + bridgeToken)
    return async (request: Request): Promise<Response> => {
        const requestId = randomUUID()
        const authorization = Buffer.from(request.headers.get('Authorization') ?? '')
        if (authorization.length !== expected.length || !timingSafeEqual(expected, authorization)) {
            return unauthorized.response(requestId)
        }
        if (shutdown.aborted) return unavailable.response(requestId)

        const streamSignal = AbortSignal.any([request.signal, shutdown])
        const signal = AbortSignal.any([streamSignal, AbortSignal.timeout(appRpcLimits.requestMs)])
        try {
            const url = new URL(request.url)
            const management = /^\/internal\/v1\/app-generations\/([a-z-]+)$/u.exec(url.pathname)
            if (management?.[1] && request.method === 'POST' && !url.search && manage) {
                const action = management[1]
                const body = await readBody(request, true, signal)
                return await replyWithinDeadline(() => manage(action, body, signal), signal)
            }
            const route = identifyOperation(request)
            const context = readHeaders(request, route.operation)
            const hasBody = request.method === 'POST' && route.operation !== 'cancelOperation'
            const body = await readBody(request, hasBody, signal)
            return await replyWithinDeadline(
                () => execute({ ...route, ...context, signal, streamSignal, requestId, body }),
                signal,
            )
        } catch (error) {
            if (error instanceof AppRuntimeProblem) return error.response(requestId)
            if (signal.aborted) return timedOut.response(requestId)
            console.warn('[app-api] request failed', requestId)
            return unavailable.response(requestId)
        }
    }
}
