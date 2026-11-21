import '@tanstack/react-start/server-only'

import { z } from 'zod'
import type { AppUiPayload } from '@/lib/AppUi/contract.ts'

import {
    appCapabilitySchema,
    appGenerationSchema,
    appIdSchema,
    appRecordId,
    appRpcLimits,
    appUidSchema,
    isAppWireJson,
} from '../contract.ts'
import { AppRuntimeProblem } from '../problem.ts'

const socket = '/run/rentnerproxy/app-ui/web.sock'
const pathComponent = /^[A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+)*$/u
export const appUiTokenPattern = /^([A-Za-z0-9_-]{16})\.([A-Za-z0-9_-]{22,1024})$/u

export const uiProblems = {
    invalid: new AppRuntimeProblem(400, 'invalidRequest', 'Invalid app UI request.'),
    frameRevoked: new AppRuntimeProblem(401, 'frameRevoked', 'This app UI session has ended.'),
    forbidden: new AppRuntimeProblem(403, 'scopeDenied', 'App UI access is forbidden.'),
    missing: new AppRuntimeProblem(404, 'notFound', 'This app UI is unavailable.'),
    stale: new AppRuntimeProblem(409, 'staleGeneration', 'The app has changed. Reload its UI.'),
    conflict: new AppRuntimeProblem(409, 'conflict', 'The app rejected the current request state.'),
    tooLarge: new AppRuntimeProblem(413, 'payloadTooLarge', 'App UI payload is too large.'),
    rateLimited: new AppRuntimeProblem(429, 'rateLimited', 'The app has too many active requests.'),
    upstream: new AppRuntimeProblem(502, 'appUnavailable', 'The app backend is unavailable.'),
    unavailable: new AppRuntimeProblem(503, 'unavailable', 'App UI is unavailable.'),
}

export function validUiPackagePath(path: string): boolean {
    return path.length <= 240 && path.split('/').every((part) => pathComponent.test(part))
}

const permissionKey = z.string().regex(/^[a-z][a-z0-9-]{0,31}$/u)
const uiSlot = z.enum(['navigation', 'proxyHostTab', 'dashboardWidget', 'search'])
const uiEntrypoint = z
    .string()
    .refine((path) => path.startsWith('ui/') && path.endsWith('.html') && validUiPackagePath(path))

const nativeApp = z.strictObject({
    appId: appIdSchema,
    installationId: appRecordId,
    generation: appGenerationSchema,
    uid: appUidSchema,
    archiveSha256: z.string().regex(/^[a-f0-9]{64}$/u),
    name: z.string().min(1).max(120),
    entrypoint: uiEntrypoint,
    slots: z.array(uiSlot).max(4),
    permissionKeys: z.array(permissionKey).max(64),
    routes: z.array(appRecordId).min(1).max(32),
    dialogs: z.array(appRecordId).max(32),
    events: z.array(appRecordId).max(32),
})
const nativeApps = z.array(nativeApp).max(256)
const operationPolicy = z.strictObject({
    permissionKey,
    resource: z
        .strictObject({
            capability: appCapabilitySchema,
            resourceIdField: z.string().regex(/^[A-Za-z][A-Za-z0-9_]{0,63}$/u),
        })
        .optional(),
})

const appUiBinding = z.strictObject({
    installationId: appRecordId,
    generation: appGenerationSchema,
})
export const appUiSession = z.strictObject({ sessionId: z.uuid() })
export const appUiOpenInput = appUiBinding.extend(appUiSession.shape)
const appUiPayload = z.custom<AppUiPayload>(
    (value: unknown) =>
        value !== null &&
        typeof value === 'object' &&
        !Array.isArray(value) &&
        isAppWireJson(value),
)
const appUiCallInput = appUiBinding.extend({
    frameToken: z.string().regex(appUiTokenPattern),
    requestId: appRecordId,
    operationId: appRecordId,
    idempotencyKey: appRecordId,
    payload: appUiPayload,
})
export type NativeAppUi = z.infer<typeof nativeApp>
export type AppUiCallInput = z.infer<typeof appUiCallInput>
export type AppUiOperationPolicy = z.infer<typeof operationPolicy>

export function appUiEnabled(): boolean {
    return process.env.RENTNERPROXY_APP_RUNTIME === '1'
}

export function appUiSignal(request: Request): AbortSignal {
    return AbortSignal.any([request.signal, AbortSignal.timeout(appRpcLimits.requestMs)])
}

export async function readAppUiJson(
    message: Request | Response,
    signal: AbortSignal,
    limit: number = appRpcLimits.jsonBytes,
) {
    const type = message.headers.get('content-type')?.split(';')[0]?.trim().toLowerCase()
    if (type !== 'application/json' || !message.body) throw uiProblems.invalid
    const length = message.headers.get('content-length')
    if (length !== null && Number(length) > limit) throw uiProblems.tooLarge
    const reader = message.body.getReader()
    const cancel = () => {
        void reader.cancel().catch(() => undefined)
    }
    const chunks: Uint8Array[] = []
    let lengthRead = 0
    signal.addEventListener('abort', cancel, { once: true })
    try {
        while (true) {
            signal.throwIfAborted()
            // oxlint-disable-next-line no-await-in-loop -- Enforce the byte budget before decoding JSON.
            const chunk = await reader.read()
            if (chunk.done) break
            lengthRead += chunk.value.byteLength
            if (lengthRead > limit) throw uiProblems.tooLarge
            chunks.push(chunk.value)
        }
        signal.throwIfAborted()
        try {
            const json = new TextDecoder('utf-8', { fatal: true }).decode(Buffer.concat(chunks))
            return JSON.parse(json) as unknown
        } catch {
            throw uiProblems.invalid
        }
    } finally {
        cancel()
        signal.removeEventListener('abort', cancel)
        reader.releaseLock()
    }
}

export async function readAppUiCall(
    request: Request,
    signal: AbortSignal,
): Promise<AppUiCallInput> {
    const envelopeLimit = appRpcLimits.jsonBytes + 4_096
    const input = appUiCallInput.safeParse(await readAppUiJson(request, signal, envelopeLimit))
    if (!input.success) throw uiProblems.invalid
    if (Buffer.byteLength(JSON.stringify(input.data.payload), 'utf8') > appRpcLimits.jsonBytes)
        throw uiProblems.tooLarge
    return input.data
}

async function nativeRequest(path: string, signal: AbortSignal, init?: RequestInit) {
    try {
        const response = await fetch('http://localhost' + path, {
            ...init,
            signal,
            unix: socket,
            redirect: 'error',
        })
        if (response.ok) return response
        void response.body?.cancel().catch(() => undefined)
        switch (response.status) {
            case 400:
                throw uiProblems.invalid
            case 404:
                throw uiProblems.missing
            case 409:
                throw uiProblems.conflict
            case 412:
                throw uiProblems.stale
            case 413:
                throw uiProblems.tooLarge
            case 429:
                throw uiProblems.rateLimited
            case 502:
                throw uiProblems.upstream
            default:
                throw uiProblems.unavailable
        }
    } catch (error) {
        if (error instanceof AppRuntimeProblem) throw error
        throw uiProblems.unavailable
    }
}

export async function nativeAppRuntimeJson<T>(
    schema: z.ZodType<T>,
    path: string,
    signal: AbortSignal,
    init?: RequestInit,
    maxBytes?: number,
) {
    const response = await nativeRequest(path, signal, init)
    const value = await readAppUiJson(response, signal, maxBytes).catch(() => {
        throw uiProblems.unavailable
    })
    const parsed = schema.safeParse(value)
    if (!parsed.success) throw uiProblems.unavailable
    return parsed.data
}

type Binding = z.infer<typeof appUiBinding>

function nativePath(binding: Binding): string {
    return '/v1/apps/' + binding.installationId + '/' + binding.generation
}

export function nativeAppUis(signal: AbortSignal) {
    return nativeAppRuntimeJson(nativeApps, '/v1/apps', signal, undefined, 4 * 1024 * 1024)
}

export function nativeAppUi(binding: Binding, signal: AbortSignal) {
    return nativeAppRuntimeJson(nativeApp, nativePath(binding) + '/metadata', signal)
}

export function nativeAppUiAsset(binding: Binding, path: string, signal: AbortSignal) {
    if (!validUiPackagePath(path)) throw uiProblems.missing
    return nativeRequest(nativePath(binding) + '/assets/' + path, signal)
}

export function nativeAppUiPolicy(input: AppUiCallInput, signal: AbortSignal) {
    const path = nativePath(input) + '/operations/' + input.operationId
    return nativeAppRuntimeJson(operationPolicy, path, signal)
}

export function nativeAppUiCall(input: AppUiCallInput, signal: AbortSignal) {
    const path = nativePath(input) + '/operations/' + input.operationId
    return nativeAppRuntimeJson(appUiPayload, path, signal, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'Idempotency-Key': input.idempotencyKey,
        },
        body: JSON.stringify(input.payload),
    })
}
