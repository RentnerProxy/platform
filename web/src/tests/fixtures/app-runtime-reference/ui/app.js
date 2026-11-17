const parentOrigin = location.origin
const openDialog = document.querySelector('#open-dialog')
const openDetails = document.querySelector('#open-details')
const dialog = document.querySelector('dialog')
const routeLabel = document.querySelector('#route')
const readiness = document.querySelector('#readiness')
const control = new MessageChannel()
let activeChannel

openDialog.addEventListener('click', () => dialog.showModal())
dialog.addEventListener('close', () => openDialog.focus())
openDetails.addEventListener('click', () => {
    const { port, installId, generation } = activeChannel
    port.postMessage({ type: 'navigate', installId, generation, route: 'details' })
})

control.port1.addEventListener('message', (event) => {
    const message = event.data
    const [port] = event.ports
    if (
        message?.type !== 'runtime:bootstrap' ||
        typeof message.installId !== 'string' ||
        !Number.isSafeInteger(message.generation) ||
        message.generation <= (activeChannel?.generation ?? 0) ||
        (activeChannel && message.installId !== activeChannel.installId) ||
        event.ports.length !== 1
    ) {
        return
    }

    const { installId, generation } = message
    const channel = { port, installId, generation }
    activeChannel?.port.close()
    activeChannel = channel
    port.addEventListener('message', ({ data }) => {
        if (
            activeChannel !== channel ||
            data?.type !== 'context' ||
            data.installId !== installId ||
            data.generation !== generation
        ) {
            return
        }

        document.documentElement.dataset.theme = data.theme
        document.documentElement.lang = data.locale
        routeLabel.textContent = data.route === 'details' ? 'Details' : 'Overview'
        readiness.hidden = data.ready !== true
        openDialog.textContent = data.locale === 'de' ? 'Dialog öffnen' : 'Open dialog'
        openDetails.textContent = data.locale === 'de' ? 'Details öffnen' : 'Open details'
        openDialog.disabled = false
        openDetails.disabled = false
    })
    port.start()
    port.postMessage({ type: 'connected', installId, generation })
})

control.port1.start()
window.parent.postMessage({ type: 'runtime:ready', nonce: location.hash.slice(1) }, parentOrigin, [
    control.port2,
])
