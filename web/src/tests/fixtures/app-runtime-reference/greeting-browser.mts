import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { isAbsolute, join } from 'node:path'
import { chromium, expect } from '@playwright/test'

import { appUiAssetPolicy, appUiAssetType } from '../../../lib/AppUi/asset-policy.ts'
import { APP_UI_PREFIX } from '../../../lib/AppUi/paths.ts'
import { getAdminUiSecurityHeaders } from '../../../server/security-headers.ts'
import { defaultGreeting, readGreeting } from '../app-template/greeting.ts'

const timeout = 5_000
const token = 'greeting-test'
const installedAssets = new Set(['index.html', 'app.js', 'app.css'])
const hostDocument = `<!doctype html><html lang="en"><head><meta charset="utf-8">
<title>Greeting browser fixture</title><script defer src="/host.js"></script></head><body>
<button id="replace-frame" type="button">Replace app</button>
<button id="german-dark" type="button">German dark theme</button>
<div id="frame-slot"></div>
<dialog aria-label="Confirm greeting"><button id="confirm-save" type="button">Confirm</button></dialog>
</body></html>`

declare global {
    interface Window {
        fixtureGreetingPort?: {
            port: MessagePort
            installId: string
            installationGeneration: number
            generation: number
        }
    }
}

function observeAppPort() {
    if (window.parent === window) return
    const BrowserMessageChannel = globalThis.MessageChannel
    globalThis.MessageChannel = class extends BrowserMessageChannel {
        constructor() {
            super()
            this.port1.addEventListener('message', ({ data, ports }: MessageEvent<unknown>) => {
                if (
                    !data ||
                    typeof data !== 'object' ||
                    !('type' in data) ||
                    data.type !== 'runtime:bootstrap'
                )
                    return
                if (
                    !('installId' in data) ||
                    typeof data.installId !== 'string' ||
                    !('installationGeneration' in data) ||
                    typeof data.installationGeneration !== 'number' ||
                    !('generation' in data) ||
                    typeof data.generation !== 'number'
                )
                    return
                const [port] = ports
                if (!port || ports.length !== 1) return
                const { installId, installationGeneration, generation } = data
                window.fixtureGreetingPort = { port, installId, installationGeneration, generation }
            })
        }
    }
}

function serveFixture(ui: string, hostBundle: Blob) {
    let greeting = defaultGreeting
    let writes = 0
    const assetPrefix = APP_UI_PREFIX + token + '/'
    const server = Bun.serve({
        hostname: '127.0.0.1',
        port: 0,
        maxRequestBodySize: 4096,
        async fetch(request, listener) {
            const { pathname, search } = new URL(request.url)
            const origin = listener.url.origin
            if (search) return new Response(null, { status: 404 })
            if (pathname === '/fixture/greeting') {
                if (request.headers.get('sec-fetch-site') !== 'same-origin') {
                    return new Response(null, { status: 403 })
                }
                if (request.method === 'GET') return Response.json({ greeting })
                if (
                    request.method !== 'POST' ||
                    request.headers.get('origin') !== origin ||
                    request.headers.get('content-type') !== 'application/json'
                ) {
                    return new Response(null, { status: 403 })
                }
                const next = readGreeting(await request.json().catch(() => null))
                if (next === undefined) return new Response(null, { status: 400 })
                greeting = next
                writes += 1
                return Response.json({ greeting })
            }
            if (request.method !== 'GET') return new Response(null, { status: 404 })
            if (pathname === '/')
                return new Response(hostDocument, {
                    headers: {
                        ...getAdminUiSecurityHeaders('http', undefined, origin),
                        'Content-Type': 'text/html; charset=utf-8',
                    },
                })
            if (pathname === '/host.js')
                return new Response(hostBundle, {
                    headers: { 'Content-Type': 'text/javascript; charset=utf-8' },
                })
            if (!pathname.startsWith(assetPrefix)) return new Response(null, { status: 404 })
            const filename = pathname.slice(assetPrefix.length)
            if (!installedAssets.has(filename)) return new Response(null, { status: 404 })
            const document = filename === 'index.html'
            const mime = appUiAssetType(request, filename, document)
            if (!mime) return new Response(null, { status: 403 })
            return new Response(Bun.file(join(ui, filename)), {
                headers: {
                    'Content-Type': mime,
                    'Content-Security-Policy': appUiAssetPolicy(origin, token),
                    'Cache-Control': 'private, no-store',
                    'X-Content-Type-Options': 'nosniff',
                    'Referrer-Policy': 'no-referrer',
                    ...(!document && { 'Access-Control-Allow-Origin': 'null' }),
                },
            })
        },
    })
    return { server, writes: () => writes }
}

const [ui, report] = Bun.argv.slice(2)
if (!ui || !report || !isAbsolute(ui) || !isAbsolute(report)) {
    throw new Error('Usage: greeting-browser.mts <absolute-ui-directory> <absolute-report-path>')
}
const host = await Bun.build({
    entrypoints: [join(import.meta.dir, 'greeting-host.ts')],
    target: 'browser',
    format: 'iife',
})
if (!host.success || !host.outputs[0])
    throw new AggregateError(host.logs, 'Greeting browser host build failed')
const { server, writes } = serveFixture(ui, host.outputs[0])
const origin = server.url.origin

try {
    const browser = await chromium.launch({ timeout: 15_000 })
    try {
        const context = await browser.newContext({ serviceWorkers: 'block' })
        context.setDefaultTimeout(timeout)
        await context.route('**/*', (route) =>
            new URL(route.request().url()).origin === origin ? route.continue() : route.abort(),
        )
        await context.addInitScript(observeAppPort)
        const page = await context.newPage()
        const errors: string[] = []
        page.on('pageerror', (error) => errors.push(error.message))
        const direct = await page.goto(origin + APP_UI_PREFIX + token + '/index.html')
        assert.equal(direct?.status(), 403)
        await page.goto(origin)
        const frame = page.frameLocator('#greeting-app')
        await expect(page.locator('#greeting-app')).toHaveAttribute('sandbox', 'allow-scripts', {
            timeout,
        })
        await expect(frame.getByText(defaultGreeting)).toBeVisible({ timeout })
        assert.equal(await frame.locator('html').evaluate(() => self.origin), 'null')

        const accepted = await frame.locator('html').evaluate(() => {
            const channel = window.fixtureGreetingPort
            if (!channel) throw new Error('Missing fixture session port')
            const { port, ...binding } = channel
            return new Promise<boolean>((resolve) => {
                const listener = ({ data }: MessageEvent<unknown>) => {
                    if (
                        !data ||
                        typeof data !== 'object' ||
                        !('type' in data) ||
                        data.type !== 'apiResult' ||
                        !('requestId' in data) ||
                        data.requestId !== 'test-valid-read' ||
                        !('result' in data) ||
                        !data.result ||
                        typeof data.result !== 'object' ||
                        !('ok' in data.result)
                    )
                        return
                    clearTimeout(timer)
                    port.removeEventListener('message', listener)
                    resolve(data.result.ok === true)
                }
                const timer = setTimeout(() => {
                    port.removeEventListener('message', listener)
                    resolve(false)
                }, 2_000)
                port.addEventListener('message', listener)
                port.postMessage(
                    {
                        type: 'apiRequest',
                        ...binding,
                        installationGeneration: binding.installationGeneration + 1,
                        operationId: 'save-greeting',
                        requestId: 'test-wrong-generation',
                        idempotencyKey: 'test-wrong-generation',
                        payload: { greeting: 'Other generation' },
                    },
                    [],
                )
                port.postMessage(
                    {
                        type: 'apiRequest',
                        ...binding,
                        operationId: 'get-greeting',
                        requestId: 'test-valid-read',
                        idempotencyKey: 'test-valid-read',
                        payload: {},
                    },
                    [],
                )
            })
        })
        assert.equal(accepted, true)
        await expect(page.locator('body')).toHaveAttribute('data-app-rpcs', '2', { timeout })
        assert.equal(writes(), 0)

        const newGreeting = 'Gude from Chromium!'
        await frame.getByRole('textbox', { name: 'New greeting' }).fill(newGreeting)
        await frame.getByRole('button', { name: 'Save greeting' }).click()
        const dialog = page.getByRole('dialog', { name: 'Confirm greeting' })
        await expect(dialog).toBeVisible({ timeout })
        assert.equal(writes(), 0)
        await dialog.getByRole('button', { name: 'Confirm' }).click()
        await expect(frame.getByText(newGreeting)).toBeVisible({ timeout })
        await expect(frame.getByRole('status')).toHaveText('Greeting saved.', { timeout })
        assert.equal(writes(), 1)

        await page.getByRole('button', { name: 'German dark theme' }).click()
        await expect(frame.locator('html')).toHaveAttribute('lang', 'de', { timeout })
        await expect(frame.locator('html')).toHaveCSS('color-scheme', 'dark', { timeout })
        await frame.getByRole('button', { name: 'Details' }).click()
        await expect(
            frame.getByText('Dein Gruß wird in dieser App-Installation gespeichert.'),
        ).toBeVisible({ timeout })
        await page.getByRole('button', { name: 'Replace app' }).click()
        await expect(page.locator('body')).toHaveAttribute('data-generation', '2', { timeout })
        await expect(frame.getByText(newGreeting)).toBeVisible({ timeout })
        assert.equal(writes(), 1)
        assert.deepEqual(errors, [])
        const uiBundleSha256 = createHash('sha256')
            .update(await Bun.file(join(ui, 'app.js')).bytes())
            .digest('hex')
        await Bun.write(
            report,
            JSON.stringify(
                {
                    browser: 'chromium',
                    uiBundleSha256,
                    checks: [
                        'opaque-frame',
                        'direct-html-denied',
                        'wrong-generation-rejected',
                        'confirmed-greeting-update',
                        'host-theme-and-language',
                        'host-navigation',
                        'persisted-after-replacement',
                    ],
                },
                null,
                2,
            ) + '\n',
        )
    } finally {
        await browser.close()
    }
} finally {
    await server.stop(true)
}
