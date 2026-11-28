import { describe, expect, spyOn, test } from 'bun:test'
import { PERMISSIONS } from '@/config/permissions.config.ts'
import { filterAppUiResult } from '@/server/AppRuntime/ui/access.server.ts'
import type { AppUiOperationPolicy } from '@/server/AppRuntime/ui/transport.server.ts'
import { nativeAppUiPolicy, uiProblems } from '@/server/AppRuntime/ui/transport.server.ts'

const capability = { id: 'proxy.hosts.read.v1', scope: 'proxyHosts' } as const
const results: NonNullable<AppUiOperationPolicy['results']> = {
    capability,
    listField: 'hosts',
    resourceIdField: 'hostId',
}

function principal(
    grants: { resourceId: string; capability: { id: string; scope: string } }[],
    permissions: string[] = [PERMISSIONS.APP_ACCESS, PERMISSIONS.PROXY_HOSTS_VIEW],
) {
    return {
        kind: 'user' as const,
        identity: {
            appId: 'rentnerproxy.monitoring',
            installationId: 'monitoring',
            generation: 1,
            uid: 20_001,
        },
        expiresAt: new Date(Date.now() + 60_000),
        appPermissions: [],
        permissions,
        grants: grants.map((grant) => ({ ...grant, allowService: false })),
    } as unknown as Parameters<typeof filterAppUiResult>[0]
}

const hostGrant = (resourceId: string) => ({ resourceId, capability })
const allHosts = {
    resourceId: 'all',
    capability: { id: capability.id, scope: 'allProxyHosts' },
}
const page = {
    hosts: [
        { hostId: 'host-a', state: 'up' },
        { hostId: 'host-b', state: 'down' },
    ],
}

describe('app UI list result filtering', () => {
    test('drops items outside the grant', () => {
        expect(filterAppUiResult(principal([hostGrant('host-a')]), results, page)).toEqual({
            hosts: [{ hostId: 'host-a', state: 'up' }],
        })
    })

    test('returns an empty list without the platform permission', () => {
        const viewer = principal(
            [hostGrant('host-a'), hostGrant('host-b')],
            [PERMISSIONS.APP_ACCESS],
        )
        expect(filterAppUiResult(viewer, results, page)).toEqual({ hosts: [] })
    })

    test('keeps every host for an all-proxy-hosts grant', () => {
        expect(filterAppUiResult(principal([allHosts]), results, page)).toEqual(page)
    })

    test('drops items with a missing or invalid ID or a non-object item', () => {
        const everything = principal([allHosts])
        const result = filterAppUiResult(everything, results, {
            hosts: [
                { state: 'x' },
                { hostId: 7 },
                { hostId: '/etc' },
                { hostId: 'Host-A' },
                'host-a',
                null,
                { hostId: 'host-a' },
            ],
        })
        expect(result).toEqual({ hosts: [{ hostId: 'host-a' }] })
    })

    test('fails closed on a non-object result, a non-array list or a missing list', () => {
        const everything = principal([allHosts])
        for (const result of [null, 'text', 3, [], [page], { hosts: {} }, { hosts: 'a' }, {}]) {
            expect(() => filterAppUiResult(everything, results, result)).toThrow(uiProblems.invalid)
        }
    })

    test('fails closed on extra top-level keys', () => {
        const everything = principal([allHosts])
        expect(() => filterAppUiResult(everything, results, { ...page, total: 2 })).toThrow(
            uiProblems.invalid,
        )
        expect(() =>
            filterAppUiResult(everything, results, { ...page, nextCursor: null, total: 2 }),
        ).toThrow(uiProblems.invalid)
    })

    test('passes nextCursor through', () => {
        const viewer = principal([hostGrant('host-a')])
        expect(filterAppUiResult(viewer, results, { ...page, nextCursor: 'c1' })).toEqual({
            hosts: [{ hostId: 'host-a', state: 'up' }],
            nextCursor: 'c1',
        })
        expect(filterAppUiResult(viewer, results, { ...page, nextCursor: null })).toMatchObject({
            nextCursor: null,
        })
    })

    test('honors a grant revoked between the call and the re-check', () => {
        const grants = [hostGrant('host-a'), hostGrant('host-b')]
        expect(filterAppUiResult(principal(grants), results, page)).toEqual(page)
        // The re-check reads the principal again after the app answered.
        expect(filterAppUiResult(principal(grants.slice(0, 1)), results, page)).toEqual({
            hosts: page.hosts.slice(0, 1),
        })
    })
})

describe('app UI operation policy', () => {
    const binding = { operationId: 'get-overview', installationId: 'monitoring', generation: 1 }

    test('accepts results next to a resource and rejects malformed members', async () => {
        const fetch = spyOn(globalThis, 'fetch')
        const signal = AbortSignal.timeout(1_000)
        const policy = {
            permissionKey: 'monitoring-read',
            resource: { capability, resourceIdField: 'hostId' },
            results,
        }
        try {
            fetch.mockResolvedValueOnce(Response.json(policy))
            await expect(nativeAppUiPolicy(binding, signal)).resolves.toEqual(policy)
            for (const broken of [
                { ...results, extra: true },
                { ...results, listField: '_x' },
                { capability, listField: 'hosts' },
                null,
            ]) {
                fetch.mockResolvedValueOnce(Response.json({ ...policy, results: broken }))
                // oxlint-disable-next-line no-await-in-loop -- Sequential mocked responses.
                await expect(nativeAppUiPolicy(binding, signal)).rejects.toBeDefined()
            }
            fetch.mockResolvedValueOnce(Response.json({ permissionKey: 'monitoring-read' }))
            await expect(nativeAppUiPolicy(binding, signal)).resolves.toEqual({
                permissionKey: 'monitoring-read',
            })
        } finally {
            fetch.mockRestore()
        }
    })
})
