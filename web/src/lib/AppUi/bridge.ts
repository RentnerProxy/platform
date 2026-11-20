import { z } from 'zod'

import type { AppUiPayload, AppUiSummary } from './contract.ts'

const recordId = z.string().regex(/^[a-z0-9][a-z0-9_-]{0,63}$/u)
const generation = z.number().int().min(1).max(Number.MAX_SAFE_INTEGER)
const binding = { installId: recordId, installationGeneration: generation, generation }
const maxPayloadBytes = 1_048_576

// Check the structured clone before reading it as JSON or recursively parsing it.
export function isAppUiPayload(value: unknown): value is AppUiPayload {
    if (value === null || typeof value !== 'object' || Array.isArray(value)) return false

    let budget = maxPayloadBytes
    const visited = new Set<object>()
    const inspect = (member: unknown, depth: number): boolean => {
        budget -= 1
        if (budget < 0) return false
        if (member === null || typeof member === 'boolean') return true
        if (typeof member === 'number') return Math.abs(member) <= Number.MAX_SAFE_INTEGER
        if (typeof member === 'string') {
            budget -= member.length
            return budget >= 0 && !/\p{Cs}/u.test(member)
        }
        if (typeof member !== 'object' || depth >= 64 || visited.has(member)) return false

        visited.add(member)
        if (Array.isArray(member)) {
            for (const item of member as unknown[]) {
                if (!inspect(item, depth + 1)) return false
            }
        } else {
            if (Object.getPrototypeOf(member) !== Object.prototype) return false
            const record = member as Record<string, unknown>
            for (const key in record) {
                if (!Object.hasOwn(record, key)) continue
                if (!inspect(key, depth + 1) || !inspect(record[key], depth + 1)) return false
            }
        }
        visited.delete(member)
        return true
    }

    return (
        inspect(value, 0) &&
        new TextEncoder().encode(JSON.stringify(value)).length <= maxPayloadBytes
    )
}

export const appUiReady = z.strictObject({
    type: z.literal('runtime:ready'),
    nonce: z.string().regex(/^[A-Za-z0-9_-]{1,128}$/u),
})

// App-to-host messages from the Marketplace App UI bridge v1.
export const appUiMessage = z.discriminatedUnion('type', [
    z.strictObject({ type: z.literal('connected'), ...binding }),
    z.strictObject({ type: z.literal('navigate'), ...binding, route: recordId }),
    z.strictObject({
        type: z.literal('dialog'),
        ...binding,
        requestId: recordId,
        dialogId: recordId,
    }),
    z.strictObject({
        type: z.literal('apiRequest'),
        ...binding,
        requestId: recordId,
        operationId: recordId,
        idempotencyKey: recordId,
        payload: z.custom<AppUiPayload>(isAppUiPayload),
    }),
])

export type AppUiApiRequest = Extract<z.infer<typeof appUiMessage>, { type: 'apiRequest' }>
export type AppUiDialogRequest = Extract<z.infer<typeof appUiMessage>, { type: 'dialog' }>

export function appUiDefaultRoute(app: AppUiSummary) {
    return app.routes.includes('overview') ? 'overview' : (app.routes[0] ?? 'overview')
}
