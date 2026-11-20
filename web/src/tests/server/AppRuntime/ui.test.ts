import { describe, expect, spyOn, test } from 'bun:test'
import { appUiAssetPolicy, appUiAssetType } from '@/lib/AppUi/asset-policy.ts'
import { appRpcLimits } from '@/server/AppRuntime/contract.ts'
import { getAdminUiSecurityHeaders } from '@/server/security-headers.ts'
import {
    appUiFrameSource,
    requireAppUiFrameGrant,
    serveAppUiAsset,
} from '@/server/AppRuntime/ui/assets.server.ts'
import {
    nativeAppUi,
    readAppUiCall,
    readAppUiJson,
    validUiPackagePath,
    type NativeAppUi,
} from '@/server/AppRuntime/ui/transport.server.ts'

const origin = 'https://appliance.example.test'
const app: NativeAppUi = {
    appId: 'rentnerproxy.greeting',
    installationId: 'greeting',
    generation: 2,
    uid: 20_001,
    archiveSha256: 'f'.repeat(64),
    name: 'Greeting',
    entrypoint: 'ui/index.html',
    slots: ['navigation'],
    permissionKeys: ['greeting-read'],
    routes: ['overview'],
    dialogs: [],
    events: [],
}
const iframe = {
    'sec-fetch-dest': 'iframe',
    'sec-fetch-mode': 'navigate',
    'sec-fetch-site': 'same-origin',
}

function differentSession(): Promise<string> {
    return Promise.resolve('different-session')
}

function jsonResponse(body: BodyInit): Response {
    return new Response(body, { headers: { 'Content-Type': 'application/json' } })
}

describe('app UI asset boundary', () => {
    test('claims only installed asset frames in the parent policy', () => {
        const policy = getAdminUiSecurityHeaders('https', undefined, origin)[
            'Content-Security-Policy'
        ]
        expect(policy).toContain('frame-src ' + origin + '/__app-ui/')
        expect(policy).toContain("frame-ancestors 'none'")
        expect(policy).not.toContain("frame-src 'self'")
        expect(getAdminUiSecurityHeaders('https')['Content-Security-Policy']).toContain(
            "frame-src 'none'",
        )
    })

    test('validates raw package paths and restricts each asset to its browser destination', () => {
        for (const path of ['../index.html', 'dir//a.js', 'a/./b', 'a/%2f/b', 'dir\\b.js', '']) {
            expect(validUiPackagePath(path)).toBe(false)
        }
        expect(validUiPackagePath('assets/de.41a.js')).toBe(true)
        expect(appUiAssetType(new Request(origin, { headers: iframe }), 'index.html', true)).toBe(
            'text/html; charset=utf-8',
        )
        const framePolicy = appUiAssetPolicy(origin, 'frame-token')
        expect(framePolicy).toContain('script-src ' + origin + '/__app-ui/frame-token/')
        expect(framePolicy).toContain("default-src 'none'")
        expect(framePolicy).toContain('sandbox allow-scripts')
        expect(framePolicy).not.toContain('allow-same-origin')
        const script = (originHeader: string) =>
            new Request(origin, {
                headers: {
                    origin: originHeader,
                    'sec-fetch-dest': 'script',
                    'sec-fetch-mode': 'cors',
                },
            })
        expect(appUiAssetType(script('null'), 'scripts/app.js', false)).toStartWith(
            'text/javascript',
        )
        expect(appUiAssetType(script(origin), 'scripts/app.js', false)).toBeNull()
        expect(appUiAssetType(script('null'), 'scripts/js', false)).toBeNull()
        expect(appUiAssetType(script('null'), 'scripts/App.JS', false)).toStartWith(
            'text/javascript',
        )
        expect(appUiAssetType(script('null'), 'files/image.svg', false)).toBeNull()
        expect(
            appUiAssetType(new Request(origin, { headers: iframe }), 'other.html', false),
        ).toBeNull()
    })

    test('binds an encrypted document URL to its origin, destination and session', async () => {
        const previous = process.env.APP_ENCRYPTION_KEY
        process.env.APP_ENCRYPTION_KEY = Buffer.alloc(32, 24).toString('base64')
        try {
            const sessionId = crypto.randomUUID()
            const expiry = new Date(Date.now() + 60 * 60_000)
            const { src, frameToken } = await appUiFrameSource(app, sessionId, expiry, origin)
            expect(src).not.toContain(sessionId)
            expect(src).not.toContain(frameToken)
            expect(src).toEndWith('/index.html')
            const url = new URL(src, origin)
            const assetToken = url.pathname.split('/')[2] ?? ''
            const signal = AbortSignal.timeout(1_000)
            await expect(
                requireAppUiFrameGrant(frameToken, app, sessionId, origin),
            ).resolves.toMatchObject({ sessionId, expiresAt: expiry.getTime() })
            await expect(
                requireAppUiFrameGrant(frameToken, app, crypto.randomUUID(), origin),
            ).rejects.toMatchObject({ code: 'frameRevoked', status: 401 })
            await expect(
                requireAppUiFrameGrant(assetToken, app, sessionId, origin),
            ).rejects.toMatchObject({ code: 'frameRevoked', status: 401 })
            await expect(
                requireAppUiFrameGrant(
                    frameToken,
                    { ...app, generation: app.generation + 1 },
                    sessionId,
                    origin,
                ),
            ).rejects.toMatchObject({ code: 'frameRevoked', status: 401 })
            await expect(
                serveAppUiAsset(new Request(url), url, origin, signal, differentSession),
            ).rejects.toMatchObject({ status: 403 })
            const embedded = new Request(url, { headers: iframe })
            await expect(
                serveAppUiAsset(
                    embedded,
                    url,
                    'https://other.example.test',
                    signal,
                    differentSession,
                ),
            ).rejects.toMatchObject({ status: 404 })
            await expect(
                serveAppUiAsset(embedded, url, origin, signal, differentSession),
            ).rejects.toMatchObject({ status: 403 })
            const expired = new URL(
                (await appUiFrameSource(app, sessionId, new Date(0), origin)).src,
                origin,
            )
            await expect(
                serveAppUiAsset(
                    new Request(expired, { headers: iframe }),
                    expired,
                    origin,
                    signal,
                    differentSession,
                ),
            ).rejects.toMatchObject({ status: 404 })
        } finally {
            if (previous === undefined) delete process.env.APP_ENCRYPTION_KEY
            else process.env.APP_ENCRYPTION_KEY = previous
        }
    })
})

test('bounds both chunked and declared JSON bodies before decoding', async () => {
    const signal = AbortSignal.timeout(1_000)
    await expect(readAppUiJson(Response.json({ value: 1 }), signal)).resolves.toEqual({ value: 1 })
    await expect(readAppUiJson(jsonResponse('bad JSON'), signal)).rejects.toMatchObject({
        status: 400,
    })
    await expect(readAppUiJson(jsonResponse(new Uint8Array(8)), signal, 4)).rejects.toMatchObject({
        status: 413,
    })
    await expect(
        readAppUiJson(
            new Response('{}', {
                headers: { 'Content-Type': 'application/json', 'Content-Length': '10' },
            }),
            signal,
            4,
        ),
    ).rejects.toMatchObject({ status: 413 })
    await expect(readAppUiJson(new Response('plain text'), signal)).rejects.toMatchObject({
        status: 400,
    })
})

test('preserves native rate limiting separately from an unavailable or stale app', async () => {
    const fetch = spyOn(globalThis, 'fetch')
    const signal = AbortSignal.timeout(1_000)
    try {
        fetch.mockResolvedValueOnce(new Response(null, { status: 429 }))
        await expect(nativeAppUi(app, signal)).rejects.toMatchObject({
            code: 'rateLimited',
            status: 429,
        })
        fetch.mockResolvedValueOnce(new Response(null, { status: 412 }))
        await expect(nativeAppUi(app, signal)).rejects.toMatchObject({
            code: 'staleGeneration',
            status: 409,
        })
    } finally {
        fetch.mockRestore()
    }
})

test('allows room for a call envelope around an exact-size app payload', async () => {
    const value = 'x'.repeat(appRpcLimits.jsonBytes - JSON.stringify({ value: '' }).length)
    const call = {
        installationId: 'greeting',
        generation: 2,
        frameToken: 'a'.repeat(16) + '.' + 'b'.repeat(128),
        requestId: 'ui-request',
        operationId: 'read-greeting',
        idempotencyKey: 'ui-call',
    }
    const request = (payload: { value: string }) =>
        new Request(origin, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ ...call, payload }),
        })
    const signal = AbortSignal.timeout(1_000)
    const parsed = await readAppUiCall(request({ value }), signal)
    expect(parsed.payload.value).toBe(value)
    await expect(readAppUiCall(request({ value: value + 'x' }), signal)).rejects.toMatchObject({
        status: 413,
    })
})
