import { isRecord, type AppMessage, type Channel, type ReadyMessage } from '../protocol.ts'

const parentOrigin = location.origin
const openDialog = document.getElementById('open-dialog')
const openDetails = document.getElementById('open-details')
const dialog = document.querySelector('dialog')
const routeLabel = document.getElementById('route')
const readiness = document.getElementById('readiness')
if (
    !(openDialog instanceof HTMLButtonElement) ||
    !(openDetails instanceof HTMLButtonElement) ||
    !dialog ||
    !routeLabel ||
    !readiness
) {
    throw new Error('Missing runtime reference app controls')
}
const control = new MessageChannel()
let activeChannel: Channel | undefined

openDialog.addEventListener('click', () => dialog.showModal())
dialog.addEventListener('close', () => openDialog.focus())
for (const button of dialog.querySelectorAll('button')) {
    button.addEventListener('click', () => dialog.close(button.value))
}
openDetails.addEventListener('click', () => {
    if (!activeChannel) {
        return
    }
    const { port, installId, generation } = activeChannel
    port.postMessage({
        type: 'navigate',
        installId,
        generation,
        route: 'details',
    } satisfies AppMessage)
})

control.port1.addEventListener('message', (event: MessageEvent<unknown>) => {
    const message = event.data
    const [port] = event.ports
    if (
        !isRecord(message) ||
        message.type !== 'runtime:bootstrap' ||
        typeof message.installId !== 'string' ||
        typeof message.generation !== 'number' ||
        !Number.isSafeInteger(message.generation) ||
        message.generation <= (activeChannel?.generation ?? 0) ||
        (activeChannel && message.installId !== activeChannel.installId) ||
        event.ports.length !== 1 ||
        !port
    ) {
        return
    }

    const { installId, generation } = message
    const channel = { port, installId, generation }
    activeChannel?.port.close()
    activeChannel = channel
    port.addEventListener('message', ({ data }: MessageEvent<unknown>) => {
        if (
            activeChannel !== channel ||
            !isRecord(data) ||
            data.type !== 'context' ||
            data.installId !== installId ||
            data.generation !== generation ||
            (data.theme !== 'light' && data.theme !== 'dark') ||
            (data.locale !== 'en' && data.locale !== 'de') ||
            (data.route !== 'overview' && data.route !== 'details') ||
            typeof data.ready !== 'boolean'
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
    port.postMessage({ type: 'connected', installId, generation } satisfies AppMessage)
})

control.port1.start()
window.parent.postMessage(
    { type: 'runtime:ready', nonce: location.hash.slice(1) } satisfies ReadyMessage,
    parentOrigin,
    [control.port2],
)
