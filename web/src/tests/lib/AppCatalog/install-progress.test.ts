import { describe, expect, test } from 'bun:test'
import type { CatalogInstall, CatalogLifecycle } from '@/lib/AppCatalog/contract.ts'
import { keepCatalogProgress, unavailableCatalog } from '@/lib/AppCatalog/installProgress.ts'

const selection = {
    appId: 'rentnerproxy.greeting',
    version: '1.0.0',
    archiveSha256: 'a'.repeat(64),
}
const installing = { ...selection, status: 'installing' } satisfies CatalogInstall
const ready = keepCatalogProgress(
    undefined,
    { ...unavailableCatalog, state: 'ready', install: installing },
    0,
)

describe('catalog installation progress', () => {
    test('keeps polling an accepted installation across a temporary outage', () => {
        const firstFailure = keepCatalogProgress(ready, null, 1_000)
        expect(firstFailure.install).toEqual(installing)
        const secondFailure = keepCatalogProgress(firstFailure, null, 2_000)
        expect(secondFailure).toEqual(firstFailure)
        expect(keepCatalogProgress(secondFailure, null, 31_000)).toEqual({
            ...unavailableCatalog,
            isConnected: false,
        })
    })

    test('uses an authoritative recovery or terminal result immediately', () => {
        const failure = keepCatalogProgress(ready, null, 1_000)
        for (const install of [
            null,
            { ...selection, status: 'installed', installationId: 'greeting-test' },
            { ...selection, status: 'failed', error: 'installFailed' },
        ] satisfies (CatalogInstall | null)[]) {
            const snapshot = { ...unavailableCatalog, state: 'ready' as const, install }
            expect(keepCatalogProgress(failure, snapshot, 2_000)).toEqual({
                ...snapshot,
                isConnected: true,
            })
        }
    })

    test('distinguishes unavailable catalog content from an interrupted local connection', () => {
        const { appId, ...release } = selection
        const installation = {
            ...release,
            appId,
            generation: 1,
            installationId: 'greeting-test',
            state: 'running' as const,
            providers: null,
            previous: null,
            update: null,
        }
        const lifecycle = {
            action: 'deactivate',
            installationId: installation.installationId,
            expected: { ...release, generation: installation.generation },
            status: 'pending',
        } satisfies CatalogLifecycle
        const connected = keepCatalogProgress(
            undefined,
            {
                ...unavailableCatalog,
                installations: [installation],
                lifecycle,
            },
            0,
        )
        expect(connected.isConnected).toBe(true)
        const interrupted = keepCatalogProgress(connected, null, 1_000)
        expect(interrupted).toMatchObject({
            isConnected: false,
            lifecycle,
            installations: [installation],
        })
        const timedOut = keepCatalogProgress(interrupted, null, 31_000)
        expect(timedOut).toMatchObject({ lifecycle: null, installations: [installation] })
    })
})
