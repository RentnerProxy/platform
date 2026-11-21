import { describe, expect, test } from 'bun:test'
import type { CatalogInstall, CatalogSnapshot } from '@/lib/AppCatalog/contract.ts'
import { keepCatalogInstall, unavailableCatalog } from '@/lib/AppCatalog/installProgress.ts'

const selection = {
    appId: 'rentnerproxy.greeting',
    version: '1.0.0',
    archiveSha256: 'a'.repeat(64),
}
const installing = { ...selection, status: 'installing' } satisfies CatalogInstall
const ready = { state: 'ready', entries: [], install: installing } satisfies CatalogSnapshot

describe('catalog installation progress', () => {
    test('keeps polling an accepted installation across a temporary outage', () => {
        const firstFailure = keepCatalogInstall(ready, unavailableCatalog, 1_000)
        expect(firstFailure.install).toEqual(installing)
        const secondFailure = keepCatalogInstall(firstFailure, unavailableCatalog, 2_000)
        expect(secondFailure).toEqual(firstFailure)
        expect(keepCatalogInstall(secondFailure, unavailableCatalog, 31_000)).toEqual(
            unavailableCatalog,
        )
    })

    test('uses an authoritative recovery or terminal result immediately', () => {
        const failure = keepCatalogInstall(ready, unavailableCatalog, 1_000)
        for (const install of [
            null,
            { ...selection, status: 'installed', installationId: 'greeting-test' },
            { ...selection, status: 'failed', error: 'installFailed' },
        ] satisfies (CatalogInstall | null)[]) {
            const snapshot = { state: 'ready', entries: [], install } satisfies CatalogSnapshot
            expect(keepCatalogInstall(failure, snapshot, 2_000)).toEqual(snapshot)
        }
    })
})
