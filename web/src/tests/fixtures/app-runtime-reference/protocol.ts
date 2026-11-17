type Binding = { installId: string; generation: number }

export type Channel = Binding & { port: MessagePort }
export type ReadyMessage = { type: 'runtime:ready'; nonce: string }
export type BootstrapMessage = Binding & { type: 'runtime:bootstrap' }
export type AppMessage = Binding & ({ type: 'connected' } | { type: 'navigate'; route: 'details' })
export type ContextMessage = Binding & {
    type: 'context'
    theme: 'light' | 'dark'
    locale: 'en' | 'de'
    route: 'overview' | 'details'
    ready: boolean
}

export function isRecord(value: unknown): value is Record<string, unknown> {
    return value !== null && typeof value === 'object' && !Array.isArray(value)
}
