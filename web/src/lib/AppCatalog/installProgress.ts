import type { CatalogSnapshot } from './contract.ts'

const RECOVERY_MS = 30_000

export const unavailableCatalog: CatalogSnapshot = {
    state: 'unavailable',
    entries: [],
    install: null,
    installations: [],
    lifecycle: null,
}

export type CatalogQueryResult = CatalogSnapshot & {
    isConnected: boolean
    recoverUntil?: number
}

export function keepCatalogProgress(
    previous: CatalogQueryResult | undefined,
    current: CatalogSnapshot | null,
    now: number,
): CatalogQueryResult {
    if (current) return { ...current, isConnected: true }

    const install = previous?.install ?? null
    const lifecycle = previous?.lifecycle ?? null
    const pending = install?.status === 'installing' || lifecycle?.status === 'pending'
    const deadline = previous?.recoverUntil ?? now + RECOVERY_MS
    const recoverUntil = pending && now < deadline ? deadline : undefined
    return {
        ...unavailableCatalog,
        isConnected: false,
        entries: previous?.entries ?? [],
        installations: previous?.installations ?? [],
        install: install?.status === 'installing' && !recoverUntil ? null : install,
        lifecycle: lifecycle?.status === 'pending' && !recoverUntil ? null : lifecycle,
        ...(recoverUntil === undefined ? {} : { recoverUntil }),
    }
}
