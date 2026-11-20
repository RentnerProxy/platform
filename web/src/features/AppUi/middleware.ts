import { createServerFn } from '@tanstack/react-start'
import { getRequest, setResponseHeader } from '@tanstack/react-start/server'
import type { AppUiProblem } from '@/lib/AppUi/contract.ts'
import { getCurrentSessionService } from '@/server/Auth/Access/sessions.service.ts'
import { getPublicOrigin } from '@/server/env.server.ts'
import { AppRuntimeProblem } from '@/server/AppRuntime/problem.ts'
import {
    activeAppUi,
    authorizeAppUi,
    listAuthorizedAppUis,
} from '@/server/AppRuntime/ui/access.server.ts'
import { appUiFrameSource } from '@/server/AppRuntime/ui/assets.server.ts'
import {
    appUiEnabled,
    appUiOpenInput,
    appUiSession,
    appUiSignal,
    uiProblems,
} from '@/server/AppRuntime/ui/transport.server.ts'

export const listAppUisHandler = createServerFn({ method: 'GET' })
    .validator((input: unknown) => appUiSession.parse(input))
    .handler(async ({ data }) => {
        setResponseHeader('Cache-Control', 'private, no-store')
        if (!appUiEnabled()) return []
        const session = await getCurrentSessionService().catch(() => null)
        return session?.id === data.sessionId
            ? listAuthorizedAppUis(session.id, appUiSignal(getRequest()))
            : []
    })

type OpenAppUi =
    { ok: true; src: string; frameToken: string } | { ok: false; problem: AppUiProblem }

export const openAppUiHandler = createServerFn({ method: 'POST' })
    .validator((input: unknown) => appUiOpenInput.parse(input))
    .handler(async ({ data }): Promise<OpenAppUi> => {
        setResponseHeader('Cache-Control', 'private, no-store')
        try {
            const request = getRequest()
            const origin = getPublicOrigin()
            if (!appUiEnabled() || !origin) throw uiProblems.missing
            if (request.headers.get('origin') !== origin) throw uiProblems.forbidden
            const session = await getCurrentSessionService()
            if (session?.id !== data.sessionId) throw uiProblems.frameRevoked
            const signal = appUiSignal(request)
            const app = await activeAppUi(data, signal)
            await authorizeAppUi(session.id, app, signal)
            return {
                ok: true,
                ...(await appUiFrameSource(app, session.id, session.expiresAt, origin)),
            }
        } catch (error) {
            const problem = error instanceof AppRuntimeProblem ? error : uiProblems.unavailable
            return { ok: false, problem: problem.document() }
        }
    })
