import { beforeEach, describe, expect, mock, test } from 'bun:test'
import { PERMISSIONS } from '@/config/permissions.config.ts'
import type { AppUiOperationPolicy } from '@/server/AppRuntime/ui/transport.server.ts'

const capability = { id: 'proxy.hosts.read.v1', scope: 'proxyHosts' } as const
const identity = {
    appId: 'rentnerproxy.monitoring',
    installationId: 'monitoring',
    generation: 1,
    uid: 20_001,
}
const events: string[] = []
let policy: AppUiOperationPolicy
let appResult: unknown
let grants: string[]
let platformPermissions: string[]
let afterCall: () => void

const realAuthority = await import('@/server/AppRuntime/authority.server.ts')
const realServices = await import('@/server/AppRuntime/services.server.ts')
const realTransport = await import('@/server/AppRuntime/ui/transport.server.ts')

void mock.module('@/server/AppRuntime/authority.server.ts', () => ({
    ...realAuthority,
    readAppUiActorInTransaction: () => Promise.resolve({}),
    readAppUiPrincipalInTransaction: (
        _transaction: unknown,
        _identity: unknown,
        _actor: unknown,
        includeGrants: boolean,
    ) => {
        events.push(`principal:${includeGrants ? 'grants' : 'plain'}`)
        return Promise.resolve({
            kind: 'user',
            identity,
            expiresAt: new Date(Date.now() + 60_000),
            appPermissions: ['app:rentnerproxy.monitoring:monitoring-read'],
            permissions: platformPermissions,
            grants: includeGrants
                ? grants.map((resourceId) => ({ resourceId, capability, allowService: false }))
                : [],
        })
    },
}))
void mock.module('@/server/AppRuntime/services.server.ts', () => ({
    ...realServices,
    appRuntimeTransaction: (_signal: unknown, run: (transaction: unknown) => unknown) =>
        Promise.resolve(run({})),
}))
void mock.module('@/server/AppRuntime/ui/transport.server.ts', () => ({
    ...realTransport,
    appUiEnabled: () => true,
    nativeAppUi: () => Promise.resolve({ ...identity }),
    nativeAppUiPolicy: () => Promise.resolve(policy),
    nativeAppUiCall: () => {
        events.push('call')
        afterCall()
        return Promise.resolve(appResult)
    },
}))

const { executeAppUiCall } = await import('@/server/AppRuntime/ui/access.server.ts')

const input = {
    installationId: 'monitoring',
    generation: 1,
    frameToken: 'a'.repeat(16) + '.' + 'b'.repeat(128),
    requestId: 'ui-request',
    operationId: 'get-overview',
    idempotencyKey: 'ui-call',
    payload: {},
}
const run = () =>
    executeAppUiCall('session', input, identity, AbortSignal.timeout(1_000)) as Promise<unknown>
const results = { capability, listField: 'hosts', resourceIdField: 'hostId' }
const page = { hosts: [{ hostId: 'host-a' }, { hostId: 'host-b' }] }

beforeEach(() => {
    events.length = 0
    policy = { permissionKey: 'monitoring-read', results }
    appResult = page
    grants = ['host-a']
    platformPermissions = [PERMISSIONS.APP_ACCESS, PERMISSIONS.PROXY_HOSTS_VIEW]
    afterCall = () => undefined
})

describe('executeAppUiCall result filtering', () => {
    test('filters with a grant-bearing principal read after the app answered', async () => {
        await expect(run()).resolves.toEqual({ hosts: [{ hostId: 'host-a' }] })
        expect(events.at(-1)).toBe('principal:grants')
        expect(events.indexOf('call')).toBeLessThan(events.lastIndexOf('principal:grants'))
    })

    test('returns an empty list without the platform permission', async () => {
        platformPermissions = [PERMISSIONS.APP_ACCESS]
        await expect(run()).resolves.toEqual({ hosts: [] })
    })

    test('honors a grant revoked while the app was answering', async () => {
        grants = ['host-a', 'host-b']
        afterCall = () => {
            grants = ['host-b']
        }
        await expect(run()).resolves.toEqual({ hosts: [{ hostId: 'host-b' }] })
    })

    test('fails closed on a result that is not a filterable list', async () => {
        appResult = { ...page, total: 2 }
        await expect(run()).rejects.toMatchObject({ code: 'invalidRequest' })
    })

    test('returns the app result untouched when the policy has no results', async () => {
        policy = { permissionKey: 'monitoring-read' }
        appResult = { ...page, total: 99, nested: { anything: [1, 2] } }
        const answer = await run()
        expect(answer).toBe(appResult)
        expect(events).not.toContain('principal:grants')
    })
})
