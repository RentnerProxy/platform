import { readFile } from 'node:fs/promises'
import { basename, isAbsolute, join } from 'node:path'
import {
    chromium,
    expect as playwrightExpect,
    type FrameLocator,
    type Page,
} from '@playwright/test'
import { isRecord } from './protocol.ts'
import { uiAssets } from './ui-assets.ts'

const timeout = 5_000
const expect = playwrightExpect.configure({ timeout })
const hostPolicy =
    "default-src 'none'; script-src 'self'; connect-src 'self'; frame-src 'self'; frame-ancestors 'none'"

declare global {
    interface Window {
        fixturePorts: MessagePort[]
        fixtureClosedPorts: number
        fixtureCspViolations: string[]
        fixtureWindowTransfers: number
    }
}

async function gatewayHealth(gatewayPort: number | undefined) {
    if (gatewayPort === undefined) {
        return new Response(null, { status: 204 })
    }
    try {
        const response = await fetch(`http://127.0.0.1:${gatewayPort}/health`, {
            redirect: 'error',
            signal: AbortSignal.timeout(3_000),
        })
        if (response.status === 200) {
            const body: unknown = await response.json()
            if (isRecord(body) && body.ready === true) {
                return Response.json({ ready: true }, { headers: { 'Cache-Control': 'no-store' } })
            }
        }
    } catch {
        // The browser must see the backend as unavailable if the loopback broker fails.
    }
    return new Response(null, { status: 502 })
}

function serveFixture(assets: Map<string, Response>, gatewayPort: number | undefined) {
    return Bun.serve({
        hostname: '127.0.0.1',
        port: 0,
        fetch(request, server) {
            const { pathname } = new URL(request.url)
            if (pathname === '/fixture/health' && request.method === 'GET') {
                return gatewayHealth(gatewayPort)
            }
            if (
                pathname === '/app/index.html' &&
                (request.headers.get('sec-fetch-dest') !== 'iframe' ||
                    request.headers.get('sec-fetch-mode') !== 'navigate' ||
                    request.headers.get('sec-fetch-site') !== 'same-origin')
            ) {
                return new Response('Embedded app document', { status: 403 })
            }
            const response = assets.get(pathname)?.clone()
            if (!response) {
                return new Response('Fixture asset not found', { status: 404 })
            }
            if (pathname === '/app/index.html') {
                const origin = server.url.origin
                response.headers.set(
                    'Content-Security-Policy',
                    `default-src 'none'; script-src ${origin}; style-src ${origin}; img-src ${origin}; frame-ancestors ${origin}; sandbox allow-scripts`,
                )
            }
            return response
        },
    })
}

function installObservers() {
    window.fixturePorts = []
    window.fixtureClosedPorts = 0
    window.fixtureCspViolations = []
    window.fixtureWindowTransfers = 0
    window.addEventListener('message', (event) => {
        if (event.data?.type === 'runtime:bootstrap') {
            window.fixtureWindowTransfers += event.ports.length
        }
    })
    globalThis.MessageChannel = class extends MessageChannel {
        constructor() {
            super()
            this.port1.addEventListener('message', (event) => {
                if (event.data?.type === 'runtime:bootstrap') {
                    window.fixturePorts.push(...event.ports)
                }
            })
        }
    }
    const close = MessagePort.prototype.close
    MessagePort.prototype.close = function () {
        close.call(this)
        window.fixtureClosedPorts += 1
    }
    document.addEventListener('securitypolicyviolation', (event) => {
        window.fixtureCspViolations.push(event.effectiveDirective)
    })
}

async function assertSandbox(page: Page, app: FrameLocator) {
    await expect(page.locator('#app')).toHaveAttribute('sandbox', 'allow-scripts')
    const appOrigin = await app.locator('html').evaluate(() => {
        let parentAccessDenied = false
        try {
            Reflect.get(window.parent, 'document')
        } catch (error) {
            parentAccessDenied = error instanceof DOMException && error.name === 'SecurityError'
        }
        return { origin: self.origin, parentAccessDenied }
    })
    expect(appOrigin).toEqual({ origin: 'null', parentAccessDenied: true })

    expect(
        await app.locator('body').evaluate(async (body) => {
            const inline = document.createElement('script')
            inline.textContent = "document.body.dataset.inlineRan = 'true'"
            body.append(inline)
            const connectDenied = await fetch('/fixture/health').then(
                () => false,
                () => true,
            )
            return { inlineRan: body.dataset.inlineRan ?? null, connectDenied }
        }),
    ).toEqual({ inlineRan: null, connectDenied: true })
    await expect
        .poll(() => app.locator('html').evaluate(() => window.fixtureCspViolations))
        .toEqual(expect.arrayContaining(['script-src-elem', 'connect-src']))
    await expect(app.getByRole('img', { name: 'Reference app icon' })).toHaveJSProperty(
        'naturalWidth',
        24,
    )
    await expect(app.locator('body')).toHaveCSS('background-color', 'rgb(250, 249, 246)')
}

async function assertChannelRotation(page: Page, app: FrameLocator) {
    await page.getByRole('button', { name: 'Rotate channel' }).click()
    const status = page.locator('body')
    await expect(status).toHaveAttribute('data-generation', '2')
    expect(await page.evaluate(() => window.fixtureClosedPorts)).toBe(1)

    await app.locator('html').evaluate(() => {
        const [port1, port2] = window.fixturePorts
        if (!port1 || !port2) {
            throw new Error('Expected both channel generations in the frame')
        }
        const navigate = { type: 'navigate', installId: 'reference-install', route: 'details' }
        port1.postMessage({ ...navigate, generation: 2 })
        port2.postMessage({ ...navigate, generation: 1 })
        port2.postMessage({ ...navigate, generation: 2, installId: 'other-install' })
    })
    await expect(status).toHaveAttribute('data-rejected-messages', '2')
    await expect(app.locator('#route')).toHaveText('Overview')
    expect(new URL(page.url()).hash).toBe('')
}

async function assertInteractions(page: Page, app: FrameLocator) {
    await page.getByRole('button', { name: 'German dark theme' }).click()
    await expect(app.locator('html')).toHaveAttribute('lang', 'de')
    await expect(app.locator('body')).toHaveCSS('background-color', 'rgb(21, 29, 35)')

    const dialogTrigger = app.getByRole('button', { name: 'Dialog öffnen' })
    await dialogTrigger.focus()
    await page.keyboard.press('Enter')
    const dialog = app.getByRole('dialog', { name: 'App dialog' })
    await expect(dialog).toBeVisible()
    await expect(dialog.getByRole('button', { name: 'Confirm' })).toBeFocused()
    await page.keyboard.press('Tab')
    await expect(dialog.getByRole('button', { name: 'Dismiss' })).toBeFocused()
    await page.keyboard.press('Escape')
    await expect(dialog).toBeHidden()
    await expect(dialogTrigger).toBeFocused()

    await dialogTrigger.click()
    await dialog.getByRole('button', { name: 'Confirm' }).click()
    await expect(dialog).toBeHidden()
    await expect(dialogTrigger).toBeFocused()

    await dialogTrigger.click()
    await dialog.getByRole('button', { name: 'Dismiss' }).click()
    await expect(dialog).toBeHidden()
    await expect(dialogTrigger).toBeFocused()

    await app.getByRole('button', { name: 'Details öffnen' }).click()
    await expect(page).toHaveURL(/#\/details$/)
    await expect(app.locator('#route')).toHaveText('Details')
    await page.goBack()
    expect(new URL(page.url()).hash).toBe('')
    await expect(app.locator('#route')).toHaveText('Overview')
    await page.goForward()
    await expect(page).toHaveURL(/#\/details$/)
    await expect(app.locator('#route')).toHaveText('Details')
    await page.reload()
    await page.getByRole('button', { name: 'Load app' }).click()
    await expect(app.locator('#route')).toHaveText('Details')
}

async function assertNavigationReplayRejected(page: Page, app: FrameLocator) {
    const status = page.locator('body')
    await expect(status).toHaveAttribute('data-generation', '1')
    await app.locator('html').evaluate(() => location.replace(`/spoof.html${location.hash}`))
    await expect(status).toHaveAttribute('data-rejected-sources', '1')
    await page.getByRole('button', { name: 'Rotate channel' }).click()
    await expect(status).toHaveAttribute('data-generation', '1')
    expect(
        await app.locator('html').evaluate(() => ({
            transfers: window.fixtureWindowTransfers,
            ports: window.fixturePorts.length,
        })),
    ).toEqual({ transfers: 0, ports: 0 })
}

function asset(body: BodyInit, contentType: string, policy?: string) {
    const headers = new Headers({
        'Content-Type': contentType,
        'Cache-Control': 'no-store',
        'X-Content-Type-Options': 'nosniff',
    })
    if (policy) {
        headers.set('Content-Security-Policy', policy)
    }
    return new Response(body, { headers })
}

const [uiDirectory, evidenceFile, gatewayPortArgument] = Bun.argv.slice(2)
if (!uiDirectory || !isAbsolute(uiDirectory) || !evidenceFile || !isAbsolute(evidenceFile)) {
    throw new Error(
        'Usage: browser.mts <absolute-installed-ui-directory> <absolute-evidence-file> [loopback-gateway-port]',
    )
}
const gatewayPort = gatewayPortArgument === undefined ? undefined : Number(gatewayPortArgument)
if (
    gatewayPortArgument !== undefined &&
    (!/^[1-9][0-9]{0,4}$/.test(gatewayPortArgument) || Number(gatewayPortArgument) > 65_535)
) {
    throw new Error('Loopback gateway port must be an integer from 1 to 65535')
}

const assets = new Map<string, Response>(
    await Promise.all(
        Object.entries(uiAssets).map(
            async ([filename, contentType]) =>
                [
                    `/app/${filename}`,
                    asset(await readFile(join(uiDirectory, filename)), contentType),
                ] as const,
        ),
    ),
)
assets.set(
    '/',
    asset(await readFile(join(import.meta.dir, 'host.html')), uiAssets['index.html'], hostPolicy),
)
const harness = await Bun.build({
    entrypoints: ['host.ts', 'spoof.ts'].map((file) => join(import.meta.dir, file)),
    target: 'browser',
    format: 'iife',
})
if (!harness.success) {
    throw new AggregateError(harness.logs, 'The reference browser harness build failed')
}
for (const output of harness.outputs) {
    assets.set(`/${basename(output.path)}`, asset(output, uiAssets['app.js']))
}
assets.set(
    '/spoof.html',
    new Response('<!doctype html><script src="/spoof.js" defer></script>', {
        headers: { 'Content-Type': uiAssets['index.html'] },
    }),
)

const server = serveFixture(assets, gatewayPort)
const origin = server.url.origin
try {
    const browser = await chromium.launch({ timeout: 15_000 })
    try {
        const context = await browser.newContext({ serviceWorkers: 'block' })
        context.setDefaultTimeout(timeout)
        await context.route('**/*', (route) =>
            new URL(route.request().url()).origin === origin ? route.continue() : route.abort(),
        )
        await context.addInitScript(installObservers)
        const page = await context.newPage()
        const errors: string[] = []
        page.on('pageerror', (error) => errors.push(error.message))
        const direct = await page.goto(`${origin}/app/index.html`)
        expect(direct?.status()).toBe(403)
        await page.goto(origin)

        await page.getByRole('button', { name: 'Check separate frame' }).click()
        const status = page.locator('body')
        await expect(status).toHaveAttribute('data-rejected-sources', '1')
        expect(await status.getAttribute('data-generation')).toBeNull()
        await page.getByRole('button', { name: 'Load app' }).click()
        const app = page.frameLocator('#app')
        await expect(status).toHaveAttribute('data-generation', '1')
        await expect(app.locator('#route')).toHaveText('Overview')
        await assertSandbox(page, app)
        if (gatewayPort !== undefined) {
            await expect(app.getByText('Backend ready')).toBeVisible()
        }
        await assertChannelRotation(page, app)
        await assertInteractions(page, app)
        if (gatewayPort !== undefined) {
            await expect(app.getByText('Backend ready')).toBeVisible()
        }
        await assertNavigationReplayRejected(page, app)
        expect(errors).toEqual([])

        await Bun.write(
            evidenceFile,
            `${JSON.stringify(
                {
                    browser: 'chromium',
                    version: browser.version(),
                    architecture: process.arch,
                    checks: [
                        'direct-navigation-denied',
                        'opaque-sandbox',
                        'content-security-policy',
                        'packaged-assets',
                        'frame-source-binding',
                        'frame-navigation-replay-denied',
                        'install-and-generation-binding',
                        'stale-port-closed',
                        'theme-and-locale',
                        'dialog-keyboard-and-focus',
                        'deep-link',
                        'browser-history-navigation',
                        ...(gatewayPort === undefined ? [] : ['unix-health-through-bridge']),
                    ],
                },
                null,
                2,
            )}\n`,
        )
    } finally {
        await browser.close()
    }
} finally {
    await server.stop(true)
}
