import { describe, expect, test } from 'bun:test'
import type { CatalogEntry, CatalogInstallation } from '@/lib/AppCatalog/contract.ts'
import {
    catalogBlockedRelease,
    catalogInstallationActions,
    compareCatalogVersions,
} from '@/lib/AppCatalog/installationActions.ts'

const installation = {
    appId: 'rentnerproxy.greeting',
    installationId: 'greeting-test',
    version: '1.0.0',
    archiveSha256: 'a'.repeat(64),
    generation: 2,
    state: 'running',
    name: null,
    providers: null,
    grants: null,
    update: null,
    updateRequiresApproval: false,
    previous: null,
} satisfies CatalogInstallation

const providerGrant = {
    capability: { id: 'app.provider.register', scope: 'providerProfiles' },
    resourceId: 'monitoring',
    allowService: true,
}

function actions(row: CatalogInstallation) {
    return catalogInstallationActions(row, true, undefined).map(({ action }) => action)
}

function entry(
    version: string,
    availability: CatalogEntry['availability'],
    appId = installation.appId,
): CatalogEntry {
    return {
        appId,
        version,
        archiveSha256: 'b'.repeat(64),
        name: 'Greeting',
        summary: 'Save a greeting.',
        publisher: 'RentnerProxy',
        hasUi: true,
        providers: [],
        grants: [],
        permissionKeys: [],
        availability,
        cached: false,
    }
}

describe('catalog installation releases', () => {
    test('orders versions by semantic version precedence', () => {
        const ordered = [
            '1.0.0-alpha',
            '1.0.0-alpha.1',
            '1.0.0-alpha.beta',
            '1.0.0-beta',
            '1.0.0-beta.2',
            '1.0.0-beta.11',
            '1.0.0-rc.1',
            '1.0.0',
            '1.0.2',
            '1.10.0',
            '2.0.0',
        ]
        for (const [index, version] of ordered.entries()) {
            expect(compareCatalogVersions(version, version)).toBe(0)
            for (const later of ordered.slice(index + 1)) {
                expect(compareCatalogVersions(version, later)).toBeLessThan(0)
                expect(compareCatalogVersions(later, version)).toBeGreaterThan(0)
            }
        }
    })

    test('names the newest listed release that the appliance cannot offer', () => {
        expect(catalogBlockedRelease(installation, [])).toBeUndefined()
        expect(
            catalogBlockedRelease(installation, [
                entry('1.0.1', 'available'),
                entry('1.0.2', 'grantsRequired'),
                entry('0.9.0', 'incompatible'),
            ]),
        ).toEqual({ version: '1.0.2', availability: 'grantsRequired' })
        expect(
            catalogBlockedRelease(installation, [
                entry('1.10.0', 'incompatible'),
                entry('1.9.0', 'grantsRequired'),
            ]),
        ).toEqual({ version: '1.10.0', availability: 'incompatible' })
    })

    test('offers an update that needs an approval for the Owner to review', () => {
        const requesting = { ...entry('1.0.1', 'available'), grants: [providerGrant] }
        const update = { version: '1.0.1', archiveSha256: 'b'.repeat(64) }
        // The approval dialog opens for the update instead of starting it.
        const reviewed = { ...installation, update, updateRequiresApproval: true }
        expect(actions(reviewed)).toEqual(['update', 'deactivate', 'uninstall'])
        expect(catalogBlockedRelease(reviewed, [requesting])).toBeUndefined()
        const carried = { ...installation, update, updateRequiresApproval: false }
        expect(actions(carried)).toEqual(['update', 'deactivate', 'uninstall'])
        expect(catalogBlockedRelease(carried, [requesting])).toBeUndefined()
    })

    test('stays silent when the newest release is offered or belongs to another app', () => {
        expect(
            catalogBlockedRelease(installation, [
                entry('1.0.1', 'grantsRequired'),
                entry('1.0.2', 'available'),
            ]),
        ).toBeUndefined()
        expect(
            catalogBlockedRelease(installation, [
                entry('0.9.0', 'incompatible'),
                entry('1.0.0', 'grantsRequired'),
                entry('2.0.0', 'incompatible', 'example.other'),
            ]),
        ).toBeUndefined()
    })
})
