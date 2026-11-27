import { describe, expect, test } from 'bun:test'
import type {
    CatalogGrant,
    CatalogInstallation,
    CatalogRequestedGrant,
} from '@/lib/AppCatalog/contract.ts'
import {
    canRevokeGrants,
    grantApproval,
    grantDraft,
    grantDraftComplete,
    grantNameKey,
    grantScopeKey,
    isSupportGrant,
    revokeGrantRequest,
    updateGrantDraft,
} from '@/lib/AppCatalog/grantApproval.ts'

const HOST_A = '2f9c4b1e-6a3d-4e8f-9b7c-0d1e2f3a4b5c'
const HOST_B = '8a7b6c5d-4e3f-4a1b-9c8d-7e6f5a4b3c2d'
const HOSTS = [HOST_A, HOST_B]
const read = { id: 'proxy.hosts.read.v1', scope: 'proxyHosts' }
const notify = { id: 'notifications.publish.v1', scope: 'installation' }
const provider = { id: 'app.provider.register', scope: 'providerProfiles' }
const audit = { id: 'app.audit.record', scope: 'installation' }

const requested: CatalogRequestedGrant[] = [
    { capability: read, allowService: true },
    { capability: notify, allowService: true },
    { capability: provider, resourceId: 'monitoring', allowService: true },
    { capability: audit, allowService: true },
]

const installation = {
    appId: 'example.monitor',
    installationId: 'app-monitor',
    version: '1.2.0',
    archiveSha256: 'a'.repeat(64),
    generation: 4,
    state: 'running',
    name: null,
    providers: null,
    grants: null,
    update: null,
    updateRequiresApproval: false,
    previous: null,
} satisfies CatalogInstallation

describe('catalog grant approval', () => {
    test('needs a selected host before it builds exactly the requested approval', () => {
        const draft = grantDraft(requested, ['view'])
        expect(draft.map((item) => item.selectable)).toEqual([true, false, false, false])
        expect(grantDraftComplete(draft)).toBe(false)
        const selected = updateGrantDraft(draft, 0, { resources: HOSTS })
        expect(grantDraftComplete(selected)).toBe(true)
        expect(grantApproval(selected)).toEqual([
            { capability: read, resourceId: HOST_A, allowService: true },
            { capability: read, resourceId: HOST_B, allowService: true },
            { capability: notify, allowService: true },
            { capability: provider, resourceId: 'monitoring', allowService: true },
            { capability: audit, allowService: true },
        ])
    })

    test('only narrows service access and names declared permission keys', () => {
        const narrow = grantDraft([{ capability: notify, allowService: false }], ['view'])
        // A request without background access never gains it.
        const widened = updateGrantDraft(narrow, 0, { allowService: true })
        expect(grantApproval(widened)).toEqual([{ capability: notify, allowService: false }])
        const draft = updateGrantDraft(grantDraft(requested, ['view']), 0, {
            resources: [HOST_A],
            allowService: false,
            permissionKey: 'view',
        })
        expect(grantApproval(draft)[0]).toEqual({
            capability: read,
            resourceId: HOST_A,
            allowService: false,
            permissionKey: 'view',
        })
    })

    test('preselects a previous approval where it still applies', () => {
        const previous: CatalogGrant[] = [
            { capability: read, resourceId: HOST_B, allowService: false, permissionKey: 'view' },
            { capability: notify, resourceId: 'app-monitor', allowService: true },
            { capability: provider, resourceId: 'docker-discovery', allowService: true },
        ]
        // A key the release no longer declares is not preselected.
        const [hosts, notifications, profile] = grantDraft(requested, ['view'], previous)
        expect(hosts).toMatchObject({ resources: [HOST_B], allowService: false })
        expect(hosts?.permissionKey).toBe('view')
        expect(notifications).toMatchObject({ allowService: true, permissionKey: undefined })
        expect(profile).toMatchObject({ resourceId: 'monitoring', allowService: true })
        expect(grantDraft(requested, [], previous)[0]?.permissionKey).toBeUndefined()
    })

    test('refuses an approval larger than one request allows', () => {
        const draft = grantDraft([{ capability: read, allowService: true }], [])
        const resources = Array.from(
            { length: 129 },
            (_, index) => `00000000-0000-4000-8000-${String(index).padStart(12, '0')}`,
        )
        expect(grantDraftComplete(updateGrantDraft(draft, 0, { resources }))).toBe(false)
        expect(
            grantDraftComplete(updateGrantDraft(draft, 0, { resources: resources.slice(0, 128) })),
        ).toBe(true)
    })

    test('names capabilities and scopes, and separates support grants', () => {
        expect(grantNameKey(read)).toBe('proxyHostsRead')
        expect(
            grantNameKey({ id: 'docker.inventory.observe.v1', scope: 'dockerConnections' }),
        ).toBe('unknown')
        expect(grantNameKey({ id: 'constructor', scope: 'installation' })).toBe('unknown')
        expect(grantScopeKey(provider)).toBe('providerProfiles')
        expect(grantScopeKey({ id: read.id, scope: 'allProxyHosts' })).toBe('unknown')
        expect([read, notify, provider, audit].map(isSupportGrant)).toEqual([
            false,
            false,
            true,
            true,
        ])
    })

    test('revokes one recorded grant of the installed release', () => {
        const grant = { capability: read, resourceId: HOST_A, allowService: true }
        expect(revokeGrantRequest(installation, grant)).toEqual({
            action: 'revoke',
            installationId: 'app-monitor',
            expected: { generation: 4, version: '1.2.0', archiveSha256: 'a'.repeat(64) },
            grants: [{ capability: read, resourceId: HOST_A }],
        })
        expect(canRevokeGrants(installation)).toBe(true)
        expect(canRevokeGrants({ ...installation, state: 'removed' })).toBe(false)
    })
})
