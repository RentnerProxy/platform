import type { AppUiApiRequest } from '../../../lib/AppUi/bridge.ts'
import type { AppUiResult, AppUiSummary } from '../../../lib/AppUi/contract.ts'
import { APP_UI_PREFIX } from '../../../lib/AppUi/paths.ts'
import { bindAppUiFrame } from '../../../lib/AppUi/session.ts'
import { readGreeting } from '../app-template/greeting.ts'

const holder = document.getElementById('frame-slot')
const dialog = document.querySelector('dialog')
if (!holder || !dialog) throw new Error('Missing Greeting browser controls')

const app: AppUiSummary = {
    appId: 'rentnerproxy.greeting',
    installationId: 'greeting-fixture',
    generation: 0,
    name: 'Greeting',
    routes: ['overview', 'details'],
    slots: ['navigation'],
    dialogs: ['confirm-save'],
    events: [],
    permissionKeys: ['greeting-read', 'greeting-write'],
}

let theme: 'light' | 'dark' = 'light'
let locale = 'en'
let route = 'overview'
let requests = 0
let connection: ReturnType<typeof bindAppUiFrame> | undefined
let settleDialog: ((outcome: 'confirmed' | 'cancelled') => void) | undefined
const context = () => ({ theme, locale, route })

async function requestGreeting(
    request: AppUiApiRequest,
    signal: AbortSignal,
): Promise<AppUiResult> {
    requests += 1
    document.body.dataset.appRpcs = String(requests)
    const problem = {
        ok: false,
        problem: {
            requestId: request.requestId,
            type: 'urn:rentnerproxy:problem:invalidRequest',
            code: 'invalidRequest',
            title: 'Invalid greeting request',
            status: 400,
        },
    } as const
    const reading =
        request.operationId === 'get-greeting' && Object.keys(request.payload).length === 0
    const greeting =
        request.operationId === 'save-greeting' ? readGreeting(request.payload) : undefined
    if (!reading && greeting === undefined) return problem
    const response = await fetch('/fixture/greeting', {
        signal,
        ...(reading
            ? { method: 'GET' }
            : {
                  method: 'POST',
                  headers: { 'Content-Type': 'application/json' },
                  body: JSON.stringify({ greeting }),
              }),
    })
    const stored = response.ok ? readGreeting(await response.json()) : undefined
    return stored === undefined ? problem : { ok: true, payload: { greeting: stored } }
}

function mountFrame(target: HTMLElement, hostDialog: HTMLDialogElement) {
    connection?.close()
    app.generation += 1
    route = 'overview'
    document.body.dataset.generation = String(app.generation)
    const nonce = crypto.randomUUID()
    const frame = document.createElement('iframe')
    frame.id = 'greeting-app'
    frame.title = 'Greeting app'
    frame.setAttribute('sandbox', 'allow-scripts')
    frame.src =
        APP_UI_PREFIX +
        'greeting-test/index.html#' +
        new URLSearchParams({ nonce, slot: 'navigation' })
    target.replaceChildren(frame)
    connection = bindAppUiFrame(
        frame,
        nonce,
        { ...app },
        {
            onConnected: context,
            onNavigate(nextRoute) {
                route = nextRoute
                connection?.sendContext(context())
            },
            onDialog(_, settle) {
                settleDialog = settle
                hostDialog.showModal()
            },
            onApiRequest: requestGreeting,
            onRevoked() {
                settleDialog = undefined
                if (hostDialog.open) hostDialog.close()
            },
        },
    )
}

document
    .getElementById('replace-frame')
    ?.addEventListener('click', () => mountFrame(holder, dialog))
document.getElementById('german-dark')?.addEventListener('click', () => {
    theme = 'dark'
    locale = 'de'
    connection?.sendContext(context())
})
document.getElementById('confirm-save')?.addEventListener('click', () => dialog.close('confirmed'))
dialog.addEventListener('close', () => {
    settleDialog?.(dialog.returnValue === 'confirmed' ? 'confirmed' : 'cancelled')
    settleDialog = undefined
    dialog.returnValue = ''
})
mountFrame(holder, dialog)
