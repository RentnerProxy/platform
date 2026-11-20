import '@tanstack/react-start/server-only'

import { SESSION_COOKIE_NAME } from '@/config/auth.config.ts'
import { APP_UI_PREFIX } from '@/lib/AppUi/paths.ts'
import { getSessionByTokenService } from '@/server/Auth/Access/sessions.service.ts'
import { getPublicOrigin } from '@/server/env.server.ts'
import { AppRuntimeProblem } from '../problem.ts'
import { executeAppUiCall } from './access.server.ts'
import { requireAppUiFrameGrant, serveAppUiAsset } from './assets.server.ts'
import {
    appUiCallInput,
    appUiEnabled,
    appUiSignal,
    readAppUiJson,
    uiProblems,
} from './transport.server.ts'

async function requestSessionId(request: Request): Promise<string | undefined> {
    const token = new Bun.CookieMap(request.headers.get('cookie') ?? '').get(SESSION_COOKIE_NAME)
    return token ? (await getSessionByTokenService(token))?.id : undefined
}

function safeResponseHeaders() {
    return {
        'Cache-Control': 'private, no-store',
        'Content-Security-Policy': "default-src 'none'; frame-ancestors 'none'; sandbox",
        'X-Content-Type-Options': 'nosniff',
        'X-Frame-Options': 'DENY',
        'Referrer-Policy': 'no-referrer',
    }
}

export async function serveAppUiHttp(request: Request, url: URL): Promise<Response> {
    let requestId: string | undefined
    try {
        const origin = getPublicOrigin()
        if (!appUiEnabled() || !origin) throw uiProblems.missing
        const signal = appUiSignal(request)
        if (url.pathname !== APP_UI_PREFIX + 'call')
            return await serveAppUiAsset(request, url, origin, signal, () =>
                requestSessionId(request),
            )
        if (
            request.method !== 'POST' ||
            url.search ||
            request.headers.get('origin') !== origin ||
            request.headers.get('sec-fetch-site') !== 'same-origin'
        )
            throw uiProblems.forbidden
        const sessionId = await requestSessionId(request)
        if (!sessionId) throw uiProblems.frameRevoked
        const input = appUiCallInput.safeParse(await readAppUiJson(request, signal))
        if (!input.success) throw uiProblems.invalid
        requestId = input.data.requestId
        const grant = await requireAppUiFrameGrant(
            input.data.frameToken,
            input.data,
            sessionId,
            origin,
        )
        const payload = await executeAppUiCall(sessionId, input.data, grant, signal)
        return Response.json({ ok: true, payload }, { headers: safeResponseHeaders() })
    } catch (error) {
        const problem = error instanceof AppRuntimeProblem ? error : uiProblems.unavailable
        return Response.json(
            { ok: false, problem: problem.document(requestId) },
            { status: problem.status, headers: safeResponseHeaders() },
        )
    }
}
