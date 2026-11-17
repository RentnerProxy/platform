const installId = 'reference-install'
const app = document.querySelector('#app')
const status = document.body.dataset
const frameNonce = crypto.randomUUID()
let controlPort
let activeChannel
let generation = 0
let theme = 'light'
let locale = 'en'
let route = location.hash === '#/details' ? 'details' : 'overview'
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
        route,
        ready,
    })
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
    const channel = { port: port1, generation }
    activeChannel = channel
    port1.addEventListener('message', ({ data }) => {
        if (
            activeChannel !== channel ||
            data?.installId !== installId ||
            data.generation !== channel.generation
        ) {
            status.rejectedMessages = String(++rejectedMessages)
            return
        }

        if (data.type === 'connected') {
            status.generation = String(channel.generation)
            sendContext()
            fetch('/fixture/health')
                .then(async (response) => response.status === 200 && (await response.json()).ready)
                .then((reportedReady) => {
                    if (activeChannel === channel && reportedReady === true) {
                        ready = true
                        sendContext()
                    }
                })
                .catch(() => {})
        } else if (data.type === 'navigate' && data.route === 'details') {
            route = data.route
            history.pushState(null, '', '#/details')
            sendContext()
        } else {
            status.rejectedMessages = String(++rejectedMessages)
        }
    })
    port1.start()

    // The control port belongs to a document, even when its WindowProxy survives navigation.
    port.postMessage({ type: 'runtime:bootstrap', installId, generation }, [port2])
}

window.addEventListener('message', (event) => {
    if (event.data?.type !== 'runtime:ready') {
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

document.querySelector('#appearance').addEventListener('click', () => {
    theme = 'dark'
    locale = 'de'
    sendContext()
})

document.querySelector('#rotate').addEventListener('click', openChannel)
document.querySelector('#load').addEventListener('click', (event) => {
    event.currentTarget.disabled = true
    app.src = `/app/index.html#${frameNonce}`
})
document.querySelector('#spoof').addEventListener('click', () => {
    const sibling = document.createElement('iframe')
    sibling.setAttribute('sandbox', 'allow-scripts')
    sibling.title = 'Separate fixture frame'
    sibling.src = '/spoof.html'
    document.body.append(sibling)
})
