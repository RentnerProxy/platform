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
    test('finishes a cancelled request while its handler still waits for admission', async () => {
        const shutdown = new AbortController()
        const client = new AbortController()
        const entered = Promise.withResolvers<void>()
        const work = Promise.withResolvers<Response>()
        const gateway = createAppRuntimeGateway(token, shutdown.signal, () => {
            entered.resolve()
            return work.promise
        })
        const response = gateway(
            new Request('http://app-api/platform/v1/context', { headers, signal: client.signal }),
        )
        await entered.promise
        client.abort()
        expect((await response).status).toBe(504)
        work.resolve(new Response(null, { status: 204 }))
    })

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

    test('routes legacy handoffs with their domain, keys and bodies', async () => {
        const { gateway, calls } = fixture()
        const send = (
            method: 'GET' | 'POST',
            route: string,
            { key, body }: { key?: string; body?: string } = {},
        ) =>
            gateway(
                new Request('http://app-api/platform/v1/legacy-handoffs/' + route, {
                    method,
                    headers: {
                        ...headers,
                        ...(key !== undefined && { 'Idempotency-Key': key }),
                        ...(body !== undefined && { 'Content-Type': 'application/json' }),
                    },
                    ...(body !== undefined && { body }),
                }),
            )
        const digest = 'a'.repeat(64)

        expect((await send('GET', 'monitoring')).status).toBe(204)
        expect((await send('POST', 'dns/begin', { key: 'begin-1' })).status).toBe(204)
        expect((await send('POST', 'oidc/parts', { body: '{"sequence":2}' })).status).toBe(204)
        expect(
            (await send('POST', 'crowdsec/commit', { key: 'commit-1', body: `{"digest":"${digest}"}` }))
                .status,
        ).toBe(204)
        expect(
            calls.map(({ operation, resourceId, idempotencyKey, body }) => ({
                operation,
                resourceId,
                idempotencyKey,
                body,
            })),
        ).toEqual([
            {
                operation: 'getLegacyHandoff',
                resourceId: 'monitoring',
                idempotencyKey: undefined,
                body: undefined,
            },
            {
                operation: 'beginLegacyHandoff',
                resourceId: 'dns',
                idempotencyKey: 'begin-1',
                body: undefined,
            },
            {
                operation: 'readLegacyHandoffPart',
                resourceId: 'oidc',
                idempotencyKey: undefined,
                body: { sequence: 2 },
            },
            {
                operation: 'commitLegacyHandoff',
                resourceId: 'crowdsec',
                idempotencyKey: 'commit-1',
                body: { digest },
            },
        ])

        // Begin and commit need a key, reads refuse one, and only parts and commit carry JSON.
        const refused = [
            send('GET', 'monitoring', { key: 'read-1' }),
            send('POST', 'dns/begin'),
            send('POST', 'dns/begin', { key: 'begin-1', body: '{}' }),
            send('POST', 'oidc/parts', { key: 'part-1', body: '{"sequence":2}' }),
            send('POST', 'oidc/parts'),
            send('POST', 'crowdsec/commit', { body: `{"digest":"${digest}"}` }),
            send('GET', 'Monitoring'),
        ]
        expect((await Promise.all(refused)).map((response) => response.status)).toEqual(
            refused.map(() => 400),
        )
        // Only the contract routes exist.
        const missing = [
            send('GET', 'monitoring/begin'),
            send('POST', 'monitoring', { body: '{}' }),
            send('POST', 'monitoring/abort', { key: 'abort-1' }),
            send('GET', 'monitoring/parts/0'),
        ]
        expect((await Promise.all(missing)).map((response) => response.status)).toEqual(
            missing.map(() => 404),
        )
        expect(calls).toHaveLength(4)
    })
})
