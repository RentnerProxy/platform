import { isGeneration, isRecord, isRecordId, readGreeting } from '../greeting.ts'

interface Binding {
    readonly installId: string
    readonly installationGeneration: number
    readonly generation: number
}

export interface Context {
    readonly generation: number
    readonly theme: 'light' | 'dark'
    readonly locale: string
    readonly route: string
    readonly ready: boolean
}

interface Session {
    readonly port: MessagePort
    readonly binding: Binding
}

function requestId() {
    const random = crypto.getRandomValues(new Uint8Array(16))
    return Array.from(random, (byte) => byte.toString(16).padStart(2, '0')).join('')
}

export function connectGreetingBridge(onContext: (context: Context | undefined) => void) {
    const control = new MessageChannel()
    const pending = new Map<string, (message?: Record<string, unknown>) => void>()
    let session: Session | undefined

    function reset() {
        session?.port.close()
        for (const finish of pending.values()) finish()
        onContext(undefined)
    }

    control.port1.addEventListener('message', ({ data, ports }: MessageEvent<unknown>) => {
        const [port] = ports
        if (
            !isRecord(data) ||
            data.type !== 'runtime:bootstrap' ||
            data.bridgeVersion !== '1.0.0' ||
            !isRecordId(data.installId) ||
            !isGeneration(data.installationGeneration) ||
            !isGeneration(data.generation) ||
            (session !== undefined &&
                (data.installId !== session.binding.installId ||
                    data.installationGeneration < session.binding.installationGeneration ||
                    data.generation <= session.binding.generation)) ||
            ports.length !== 1 ||
            !port
        ) {
            for (const invalidPort of ports) invalidPort.close()
            return
        }
        reset()
        const { installId, installationGeneration, generation } = data
        const binding = { installId, installationGeneration, generation }
        const active = { port, binding }
        session = active
        port.addEventListener('message', (event: MessageEvent<unknown>) => {
            const message = event.data
            for (const extraPort of event.ports) extraPort.close()
            if (
                event.ports.length > 0 ||
                session !== active ||
                !isRecord(message) ||
                message.installId !== installId ||
                message.installationGeneration !== installationGeneration ||
                message.generation !== generation
            )
                return
            if (
                message.type === 'context' &&
                (message.theme === 'light' || message.theme === 'dark') &&
                typeof message.locale === 'string' &&
                message.locale.length <= 64 &&
                /^[A-Za-z]{2,8}(?:-[A-Za-z0-9]{1,8})*$/u.test(message.locale) &&
                isRecordId(message.route) &&
                typeof message.ready === 'boolean'
            ) {
                onContext({
                    generation,
                    theme: message.theme,
                    locale: message.locale,
                    route: message.route,
                    ready: message.ready,
                })
            }
            if (isRecordId(message.requestId)) pending.get(message.requestId)?.(message)
        })
        port.start()
        port.postMessage({ type: 'connected', ...binding }, [])
    })
    control.port1.start()
    const nonce = new URLSearchParams(window.location.hash.slice(1)).get('nonce')
    if (nonce && /^[A-Za-z0-9_-]{1,128}$/u.test(nonce) && window.parent !== window) {
        window.parent.postMessage({ type: 'runtime:ready', nonce }, window.location.origin, [
            control.port2,
        ])
    } else {
        control.port2.close()
    }

    function exchange(
        request:
            | { type: 'dialog'; dialogId: string }
            | {
                  type: 'apiRequest'
                  operationId: string
                  payload: Record<string, string>
                  idempotencyKey: string
              },
        responseType: 'apiResult' | 'dialogResult',
    ) {
        const active = session
        if (!active) return Promise.resolve(undefined)
        const id = requestId()
        return new Promise<Record<string, unknown> | undefined>((resolve) => {
            const finish = (message?: Record<string, unknown>) => {
                if (message && message.type !== responseType) return
                clearTimeout(timeout)
                pending.delete(id)
                resolve(message)
            }
            const timeout = setTimeout(finish, request.type === 'dialog' ? 60_000 : 10_000)
            pending.set(id, finish)
            active.port.postMessage({ ...active.binding, ...request, requestId: id }, [])
        })
    }

    return {
        async greeting(
            operationId: 'get-greeting' | 'save-greeting',
            payload: Record<string, string>,
        ) {
            const message = await exchange(
                { type: 'apiRequest', operationId, payload, idempotencyKey: requestId() },
                'apiResult',
            )
            const result = message?.result
            if (isRecord(result) && result.ok === true) {
                const greeting = readGreeting(result.payload)
                if (greeting !== undefined) return greeting
            }
            throw new Error('Greeting operation unavailable')
        },
        async confirmSave() {
            const message = await exchange(
                { type: 'dialog', dialogId: 'confirm-save' },
                'dialogResult',
            )
            return message?.outcome === 'confirmed'
        },
        navigate(route: 'overview' | 'details') {
            session?.port.postMessage({ type: 'navigate', ...session.binding, route }, [])
        },
        close() {
            reset()
            session = undefined
            control.port1.close()
        },
    }
}
