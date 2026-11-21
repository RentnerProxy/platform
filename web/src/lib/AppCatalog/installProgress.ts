import type { CatalogSnapshot } from './contract.ts'

const RECOVERY_MS = 30_000

export const unavailableCatalog: CatalogSnapshot = {
    state: 'unavailable',
    entries: [],
    install: null,
}

export type CatalogQueryResult = CatalogSnapshot & { recoverUntil?: number }

export function keepCatalogInstall(
    previous: CatalogQueryResult | undefined,
    current: CatalogSnapshot,
    now: number,
): CatalogQueryResult {
    if (
        current.state !== 'unavailable' ||
        current.install ||
        previous?.install?.status !== 'installing'
    )
        return current
    const recoverUntil = previous.recoverUntil ?? now + RECOVERY_MS
    if (now >= recoverUntil) return current
    return { ...current, install: previous.install, recoverUntil }
}
