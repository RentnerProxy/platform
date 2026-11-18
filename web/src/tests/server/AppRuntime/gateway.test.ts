import { describe, expect, test } from 'bun:test'
import { createAppRuntimeGateway } from '@/server/AppRuntime/gateway.server.ts'
import { appRpcLimits } from '@/server/AppRuntime/contract.ts'
import type { AppRuntimeCall } from '@/server/AppRuntime/Types/gateway.types.ts'

const token = 'synthetic-bridge-credential'
const identity = {
    appId: 'rentnerproxy.test-fixture',
    installationId: 'test-install',
    generation: 2,
    uid: 20_001,
}
const headers = {
    Authorization: 'Bearer ' + token,
    'X-App-Installation': identity.installationId,
    'X-App-Generation': String(identity.generation),
    'X-RentnerProxy-App-Id': identity.appId,
    'X-RentnerProxy-App-Uid': String(identity.uid),
}

function fixture() {
    const calls: AppRuntimeCall[] = []
    const shutdown = new AbortController()
    const gateway = createAppRuntimeGateway(token, shutdown.signal, (call) => {
        calls.push(call)
        return Promise.resolve(new Response(null, { status: 204 }))
    })
    return { gateway, calls, shutdown }
}

describe('private app gateway', () => {
    test('takes identity from the trusted broker and ignores arbitrary user headers', async () => {
        const { gateway, calls } = fixture()
        const response = await gateway(
            new Request('http://app-api/platform/v1/context', {
                headers: { ...headers, 'X-User-ID': 'owner', 'X-App-Id': 'external.claim' },
            }),
        )
        expect(response.status).toBe(204)
        expect(calls[0]?.credentials).toEqual({ identity })
    })

    test('does not accept missing broker auth, ambiguous identity, or noncanonical generations', async () => {
        const { gateway, calls } = fixture()
        const request = (overrides: Record<string, string>) =>
            gateway(
                new Request('http://app-api/platform/v1/context', {
                    headers: { ...headers, ...overrides },
                }),
            )
        expect((await request({ Authorization: 'Bearer untrusted' })).status).toBe(401)
        expect((await request({ 'X-App-Installation': 'test-install, other' })).status).toBe(400)
        expect((await request({ 'X-App-Generation': '02' })).status).toBe(400)
        expect(calls).toHaveLength(0)
    })

    test('requires mutation keys and validates bounded Unicode-safe JSON', async () => {
        const { gateway, calls } = fixture()
        const notify = (body: string, key?: string) =>
            gateway(
                new Request('http://app-api/platform/v1/notifications', {
                    method: 'POST',
                    headers: {
                        ...headers,
                        'Content-Type': 'application/json',
                        ...(key && { 'Idempotency-Key': key }),
                    },
                    body,
                }),
            )
        expect((await notify('{}')).status).toBe(400)
        expect((await notify('plain text', 'sample')).status).toBe(400)
        expect((await notify('{"value":"\\uD800"}', 'sample')).status).toBe(400)
        const deep = '['.repeat(65) + 'null' + ']'.repeat(65)
        expect((await notify(deep, 'sample')).status).toBe(400)
        expect((await notify('"'.repeat(appRpcLimits.jsonBytes + 1), 'sample')).status).toBe(413)
        expect((await notify('{"safe":true}', 'sample')).status).toBe(204)
        expect(calls[0]?.body).toEqual({ safe: true })
    })

    test('keeps control requests private and refuses requests while draining', async () => {
        const { gateway, shutdown } = fixture()
        expect(
            (
                await gateway(
                    new Request('http://app-api/internal/v1/app-generations/activate', {
                        method: 'POST',
                        headers,
                    }),
                )
            ).status,
        ).toBe(404)
        shutdown.abort()
        expect(
            (await gateway(new Request('http://app-api/platform/v1/context', { headers }))).status,
        ).toBe(503)
    })
})
