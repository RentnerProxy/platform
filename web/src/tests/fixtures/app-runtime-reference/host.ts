import { isRecord, type BootstrapMessage, type Channel, type ContextMessage } from './protocol.ts'

const installId = 'reference-install'
const app = document.getElementById('app')
const appearance = document.getElementById('appearance')
const rotate = document.getElementById('rotate')
const load = document.getElementById('load')
const spoof = document.getElementById('spoof')
if (
    !(app instanceof HTMLIFrameElement) ||
    !appearance ||
    !rotate ||
    !(load instanceof HTMLButtonElement) ||
    !spoof
) {
    throw new Error('Missing runtime fixture host controls')
}
const status = document.body.dataset
const frameNonce = crypto.randomUUID()
let controlPort: MessagePort | undefined
let activeChannel: Channel | undefined
let generation = 0
let theme: ContextMessage['theme'] = 'light'
let locale: ContextMessage['locale'] = 'en'
let ready = false
let rejectedSources = 0
let rejectedMessages = 0

function sendContext() {
    const port = activeChannel?.port
    port?.postMessage({
        type: 'context',
        installId,
        generation,
        theme,
        locale,
        route: location.hash === '#/details' ? 'details' : 'overview',
        ready,
    } satisfies ContextMessage)
}

function openChannel() {
    const port = controlPort
    if (!port) {
        return
    }
    activeChannel?.port.close()
    ready = false
    generation += 1
    const { port1, port2 } = new MessageChannel()
    const channel = { port: port1, installId, generation }
    activeChannel = channel
    port1.addEventListener('message', ({ data }: MessageEvent<unknown>) => {
        if (
            activeChannel !== channel ||
            !isRecord(data) ||
            data.installId !== installId ||
            data.generation !== channel.generation
        ) {
            status.rejectedMessages = String(++rejectedMessages)
            return
        }

        if (data.type === 'connected') {
            status.generation = String(channel.generation)
            sendContext()
            fetch('/fixture/health')
                .then(async (response) => {
                    if (response.status !== 200) {
                        return false
                    }
                    const body: unknown = await response.json()
                    return isRecord(body) && body.ready === true
                })
                .then((reportedReady) => {
                    if (activeChannel === channel && reportedReady === true) {
                        ready = true
                        sendContext()
                    }
                })
                .catch(() => {})
        } else if (data.type === 'navigate' && data.route === 'details') {
            history.pushState(null, '', '#/details')
            sendContext()
        } else {
            status.rejectedMessages = String(++rejectedMessages)
        }
    })
    port1.start()

    // The control port belongs to a document, even when its WindowProxy survives navigation.
    port.postMessage(
        { type: 'runtime:bootstrap', installId, generation } satisfies BootstrapMessage,
        [port2],
    )
}

window.addEventListener('message', (event: MessageEvent<unknown>) => {
    if (!isRecord(event.data) || event.data.type !== 'runtime:ready') {
        return
    }

    if (
        event.source !== app.contentWindow ||
        event.origin !== 'null' ||
        event.data.nonce !== frameNonce ||
        event.ports.length !== 1 ||
        controlPort
    ) {
        status.rejectedSources = String(++rejectedSources)
        return
    }

    controlPort = event.ports[0]
    openChannel()
})

window.addEventListener('popstate', sendContext)
appearance.addEventListener('click', () => {
    theme = 'dark'
    locale = 'de'
    sendContext()
})

rotate.addEventListener('click', openChannel)
load.addEventListener('click', () => {
    load.disabled = true
    app.src = `/app/index.html#${frameNonce}`
})
spoof.addEventListener('click', () => {
    const sibling = document.createElement('iframe')
    sibling.setAttribute('sandbox', 'allow-scripts')
    sibling.title = 'Separate fixture frame'
    sibling.src = '/spoof.html'
    document.body.append(sibling)
})
