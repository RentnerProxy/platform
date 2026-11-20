export const defaultGreeting = 'Hello from RentnerProxy!'
export const maxGreetingLength = 120

export function isRecord(value: unknown): value is Record<string, unknown> {
    return value !== null && typeof value === 'object' && !Array.isArray(value)
}

export function isRecordId(value: unknown): value is string {
    return typeof value === 'string' && /^[a-z0-9][a-z0-9_-]{0,63}$/u.test(value)
}

export function isGeneration(value: unknown): value is number {
    return typeof value === 'number' && Number.isSafeInteger(value) && value > 0
}

export function readGreeting(value: unknown): string | undefined {
    if (!isRecord(value) || Object.keys(value).length !== 1) return
    const { greeting } = value
    if (
        typeof greeting === 'string' &&
        greeting === greeting.trim() &&
        greeting.length > 0 &&
        greeting.length <= maxGreetingLength &&
        !/[\p{Cc}\p{Cs}]/u.test(greeting)
    ) {
        return greeting
    }
}
