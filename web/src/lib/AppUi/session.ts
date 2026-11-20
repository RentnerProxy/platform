import {
    appUiMessage,
    appUiReady,
    type AppUiApiRequest,
    type AppUiDialogRequest,
} from './bridge.ts'
import type { AppUiResult, AppUiSummary } from './contract.ts'

type AppUiContextMessage = { theme: 'light' | 'dark'; locale: string; route: string }
export type AppUiRevocation = 'stale' | 'revoked' | 'disconnected' | 'unmounted'
type AppUiCallbacks = {
    onConnected: () => AppUiContextMessage
    onNavigate: (route: string) => void
    onDialog: (
        request: AppUiDialogRequest,
        settle: (outcome: 'confirmed' | 'cancelled') => void,
    ) => void
    onApiRequest: (request: AppUiApiRequest, signal: AbortSignal) => Promise<AppUiResult>
    onRevoked: (reason: AppUiRevocation) => void
}

const maxPendingRequests = 8
const maxMessagesPerWindow = 64
const messageWindowMs = 10_000
const handshakeTimeoutMs = 15_000
const requestTimeoutMs = 15_000

function bridgeProblem(
    requestId: string,
    status: number,
    code: string,
    title: string,
): AppUiResult {
    return {
        ok: false,
        problem: { requestId, status, code, title, type: 'urn:rentnerproxy:problem:' + code },
    }
}

export function bindAppUiFrame(
    frame: HTMLIFrameElement,
    nonce: string,
    app: AppUiSummary,
    callbacks: AppUiCallbacks,
) {
    const binding = {
        installId: app.installationId,
        installationGeneration: app.generation,
        generation: 1,
    }
    const expectedWindow = frame.contentWindow
    const pending = new Set<string>()
    const sessionAbort = new AbortController()
    let controlPort: MessagePort | undefined
    let sessionPort: MessagePort | undefined
    let closed = false
    let connected = false
    let loaded = false
    let messageCount = 0
    let windowStarted = performance.now()

    function revoke(reason: AppUiRevocation) {
        if (closed) return
        closed = true
        window.clearTimeout(handshakeTimeout)
        window.removeEventListener('message', receiveReady)
        frame.removeEventListener('load', receiveLoad)
        controlPort?.close()
        sessionPort?.close()
        sessionAbort.abort()
        pending.clear()
        callbacks.onRevoked(reason)
    }

    function receiveLoad() {
        if (loaded) {
            revoke('disconnected')
            return
        }
        loaded = true
        bootstrap()
    }

    function sendContext(context: AppUiContextMessage) {
        if (!closed && connected) {
            sessionPort?.postMessage({ type: 'context', ...binding, ...context, ready: true }, [])
        }
    }

    function sendApiResult(requestId: string, result: AppUiResult) {
        if (closed) return
        sessionPort?.postMessage({ type: 'apiResult', ...binding, requestId, result }, [])
        if (result.ok) return
        const { code, status } = result.problem
        if (code === 'staleGeneration' && status === 409) revoke('stale')
        if (code === 'frameRevoked' && status === 401) revoke('revoked')
    }

    async function dispatchApiRequest(request: AppUiApiRequest) {
        const { requestId } = request
        if (pending.has(requestId)) return
        if (pending.size >= maxPendingRequests) {
            sendApiResult(
                requestId,
                bridgeProblem(requestId, 429, 'rateLimited', 'Too many pending requests'),
            )
            return
        }

        pending.add(requestId)
        try {
            const signal = AbortSignal.any([
                sessionAbort.signal,
                AbortSignal.timeout(requestTimeoutMs),
            ])
            sendApiResult(requestId, await callbacks.onApiRequest(request, signal))
        } catch {
            sendApiResult(
                requestId,
                bridgeProblem(requestId, 502, 'unavailable', 'App request could not be completed'),
            )
        } finally {
            pending.delete(requestId)
        }
    }

    function receiveSession(event: MessageEvent<unknown>) {
        for (const transferred of event.ports) transferred.close()
        if (closed) return

        if (performance.now() - windowStarted >= messageWindowMs) {
            windowStarted = performance.now()
            messageCount = 0
        }
        messageCount += 1
        if (messageCount > maxMessagesPerWindow) {
            revoke('disconnected')
            return
        }
        if (event.ports.length !== 0) return

        const parsed = appUiMessage.safeParse(event.data)
        if (!parsed.success) return
        const message = parsed.data
        if (
            message.installId !== binding.installId ||
            message.installationGeneration !== binding.installationGeneration ||
            message.generation !== binding.generation
        )
            return

        if (!connected) {
            if (message.type !== 'connected') return
            connected = true
            window.clearTimeout(handshakeTimeout)
            sendContext(callbacks.onConnected())
            return
        }

        switch (message.type) {
            case 'navigate':
                if (app.routes.includes(message.route)) callbacks.onNavigate(message.route)
                break
            case 'dialog':
                if (!app.dialogs.includes(message.dialogId) || pending.has(message.requestId))
                    return
                if (pending.size >= maxPendingRequests) {
                    sessionPort?.postMessage(
                        {
                            type: 'dialogResult',
                            ...binding,
                            requestId: message.requestId,
                            outcome: 'cancelled',
                        },
                        [],
                    )
                    return
                }
                pending.add(message.requestId)
                callbacks.onDialog(message, (outcome) => {
                    if (!closed && pending.delete(message.requestId)) {
                        sessionPort?.postMessage(
                            {
                                type: 'dialogResult',
                                ...binding,
                                requestId: message.requestId,
                                outcome,
                            },
                            [],
                        )
                    }
                })
                break
            case 'apiRequest':
                void dispatchApiRequest(message).catch(() => revoke('disconnected'))
                break
            case 'connected':
                break
        }
    }

    function receiveReady(event: MessageEvent<unknown>) {
        if (!expectedWindow || event.source !== expectedWindow || event.origin !== 'null') return
        const [transferred] = event.ports
        const parsed = appUiReady.safeParse(event.data)
        if (
            closed ||
            controlPort ||
            !parsed.success ||
            parsed.data.nonce !== nonce ||
            !transferred ||
            event.ports.length !== 1
        ) {
            for (const port of event.ports) port.close()
            return
        }

        window.removeEventListener('message', receiveReady)
        controlPort = transferred
        controlPort.addEventListener('message', (message) => {
            for (const extra of message.ports) extra.close()
            revoke('disconnected')
        })
        controlPort.addEventListener('messageerror', () => revoke('disconnected'))
        controlPort.start()
        bootstrap()
    }

    function bootstrap() {
        // A posted ready message can outlive its document. Wait for load before asking
        // the owner of that document's private port to acknowledge a session.
        if (closed || !loaded || !controlPort || sessionPort) return
        const channel = new MessageChannel()
        sessionPort = channel.port1
        sessionPort.addEventListener('message', receiveSession)
        sessionPort.addEventListener('messageerror', () => revoke('disconnected'))
        sessionPort.start()
        controlPort.postMessage({ type: 'runtime:bootstrap', bridgeVersion: '1.0.0', ...binding }, [
            channel.port2,
        ])
    }

    const handshakeTimeout = window.setTimeout(() => revoke('disconnected'), handshakeTimeoutMs)
    window.addEventListener('message', receiveReady)
    frame.addEventListener('load', receiveLoad)

    return { sendContext, close: () => revoke('unmounted') }
}
