import { describe, expect, mock, spyOn, test } from 'bun:test'
import { GlobalRegistrator } from '@happy-dom/global-registrator'

import { isAppUiPayload } from '@/lib/AppUi/bridge.ts'
import type { AppUiSummary } from '@/lib/AppUi/contract.ts'
import { bindAppUiFrame, type AppUiRevocation } from '@/lib/AppUi/session.ts'

if (!GlobalRegistrator.isRegistered) GlobalRegistrator.register()

const app: AppUiSummary = {
    appId: 'test.app',
    installationId: 'test-installation',
    generation: 7,
    name: 'Test app',
    routes: ['overview', 'details'],
    dialogs: ['confirm-save'],
    slots: ['navigation'],
    events: [],
    permissionKeys: [],
}

function nextMessage(port: MessagePort): Promise<MessageEvent<unknown>> {
    return new Promise((resolve) => {
        port.addEventListener('message', resolve, { once: true })
        port.start()
    })
}

function dispatchReady(
    port: MessagePort,
    source: MessageEventSource | null,
    origin: string,
    nonce: string,
) {
    window.dispatchEvent(
        new MessageEvent('message', {
            source,
            origin,
            data: { type: 'runtime:ready', nonce },
            ports: [port],
        }),
    )
}

describe('app UI document binding', () => {
    test.each(['disconnected', 'revoked'] as const)(
        'requires a loaded, acknowledged document and closes when %s',
        async (reason) => {
            const frame = Object.assign(new EventTarget(), { contentWindow: window })
            const boundFrame = frame as unknown as HTMLIFrameElement
            const active = new MessageChannel()
            const sendBootstrap = spyOn(active.port2, 'postMessage')
            const spoof = new MessageChannel()
            const navigate = mock((_route: string) => {})
            const dialog = mock(() => {})
            const revoked = Promise.withResolvers<AppUiRevocation>()
            const onRevoked = mock(revoked.resolve)
            const onApiRequest = mock(async (request: { requestId: string }) => {
                if (request.requestId === 'request-revoked')
                    return {
                        ok: false as const,
                        problem: {
                            type: 'urn:rentnerproxy:problem:frameRevoked',
                            title: 'Frame revoked',
                            status: 401,
                            code: 'frameRevoked',
                            requestId: request.requestId,
                        },
                    }
                return { ok: true as const, payload: { greeting: 'Hello' } }
            })
            const bridge = bindAppUiFrame(boundFrame, 'frame-nonce', app, {
                onConnected: () => ({ theme: 'dark', locale: 'en-US', route: 'overview' }),
                onNavigate: navigate,
                onDialog: dialog,
                onApiRequest,
                onRevoked,
            })
            let session: MessagePort | undefined
            try {
                dispatchReady(spoof.port2, null, 'null', 'frame-nonce')
                dispatchReady(spoof.port2, window, 'https://platform.test', 'frame-nonce')
                dispatchReady(spoof.port2, window, 'null', 'wrong-nonce')
                dispatchReady(active.port2, window, 'null', 'frame-nonce')
                expect(sendBootstrap).not.toHaveBeenCalled()
                frame.dispatchEvent(new Event('load'))
                expect(sendBootstrap).toHaveBeenCalledTimes(1)

                const binding = {
                    installId: app.installationId,
                    installationGeneration: app.generation,
                    generation: 1,
                }
                const bootstrap = await nextMessage(active.port1)
                expect(bootstrap.data).toEqual({
                    type: 'runtime:bootstrap',
                    bridgeVersion: '1.0.0',
                    ...binding,
                })
                session = bootstrap.ports[0]!
                session.postMessage({ type: 'connected', ...binding, generation: 2 }, [])
                session.postMessage({ type: 'navigate', ...binding, route: 'details' }, [])
                session.postMessage(
                    {
                        type: 'dialog',
                        ...binding,
                        dialogId: 'confirm-save',
                        requestId: 'early-dialog',
                    },
                    [],
                )
                session.postMessage(
                    {
                        type: 'apiRequest',
                        ...binding,
                        operationId: 'read',
                        requestId: 'early-request',
                        idempotencyKey: 'early-key',
                        payload: {},
                    },
                    [],
                )
                session.postMessage({ type: 'connected', ...binding }, [])
                expect((await nextMessage(session)).data).toEqual({
                    type: 'context',
                    ...binding,
                    theme: 'dark',
                    locale: 'en-US',
                    route: 'overview',
                    ready: true,
                })
                expect(navigate).not.toHaveBeenCalled()
                expect(dialog).not.toHaveBeenCalled()
                expect(onApiRequest).not.toHaveBeenCalled()
                session.postMessage(
                    { type: 'navigate', ...binding, generation: 2, route: 'details' },
                    [],
                )
                session.postMessage(
                    { type: 'navigate', ...binding, installationGeneration: 6, route: 'details' },
                    [],
                )
                session.postMessage({ type: 'navigate', ...binding, route: 'unauthorized' }, [])
                session.postMessage({ type: 'navigate', ...binding, route: 'details' }, [])
                session.postMessage(
                    {
                        type: 'apiRequest',
                        ...binding,
                        operationId: 'read',
                        requestId: 'request-1',
                        idempotencyKey: 'read-1',
                        payload: {},
                    },
                    [],
                )
                expect((await nextMessage(session)).data).toEqual({
                    type: 'apiResult',
                    ...binding,
                    requestId: 'request-1',
                    result: { ok: true, payload: { greeting: 'Hello' } },
                })
                expect(navigate.mock.calls).toEqual([['details']])
                expect(onApiRequest).toHaveBeenCalledTimes(1)

                if (reason === 'revoked') {
                    session.postMessage(
                        {
                            type: 'apiRequest',
                            ...binding,
                            operationId: 'read',
                            requestId: 'request-revoked',
                            idempotencyKey: 'revoked-key',
                            payload: {},
                        },
                        [],
                    )
                } else {
                    frame.dispatchEvent(new Event('load'))
                }
                expect(await revoked.promise).toBe(reason)
                bridge.close()
                expect(onRevoked.mock.calls).toEqual([[reason]])
            } finally {
                sendBootstrap.mockRestore()
                bridge.close()
                for (const port of [active.port1, active.port2, spoof.port1, spoof.port2, session])
                    port?.close()
            }
        },
    )

    test('bounds JSON before serializing structured clones', () => {
        const cyclic: Record<string, unknown> = {}
        cyclic.self = cyclic
        expect(isAppUiPayload({ empty: {}, values: ['✓', 1, null] })).toBe(true)
        expect(isAppUiPayload(cyclic)).toBe(false)
        expect(isAppUiPayload({ value: new Map() })).toBe(false)
        expect(isAppUiPayload({ value: '\ud800' })).toBe(false)
        expect(isAppUiPayload({ value: '€'.repeat(350_000) })).toBe(false)
    })
})
