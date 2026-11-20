import { useEffect, useEffectEvent, useLayoutEffect, useRef, useState } from 'react'

import { appUiDefaultRoute, type AppUiDialogRequest } from '@/lib/AppUi/bridge.ts'
import type { AppUiSlot, AppUiSummary } from '@/lib/AppUi/contract.ts'
import { APP_UI_PREFIX } from '@/lib/AppUi/paths.ts'
import { bindAppUiFrame, type AppUiRevocation } from '@/lib/AppUi/session.ts'
import useTranslationStore from '@/shared/Language/Hooks/useTranslationStore.ts'
import { ModalActionButton } from '@/shared/Modal/Components/ModalActions.tsx'
import { useAppUi } from './AppUiProvider.tsx'
import { callAppUi } from '@/lib/AppUi/client.ts'
import { openAppUiHandler } from './middleware.ts'

type FrameProps = {
    app: AppUiSummary
    slot?: AppUiSlot | undefined
    hostId?: string | undefined
    route?: string | undefined
    onNavigate?: ((route: string) => void) | undefined
}

type AppFrameSource = { nonce: string; url: string; frameToken: string }

export default function AppUiFrame({ app, slot, hostId, route, onNavigate }: FrameProps) {
    const sessionId = useAppUi()?.sessionId
    const [localRoute, setLocalRoute] = useState<string>()
    const [attempt, setAttempt] = useState(0)
    const current =
        route ??
        (localRoute && app.routes.includes(localRoute) ? localRoute : appUiDefaultRoute(app))

    if (!sessionId) return null

    return (
        <AppUiMount
            key={JSON.stringify([
                sessionId,
                app.installationId,
                app.generation,
                slot,
                hostId,
                current,
                attempt,
            ])}
            sessionId={sessionId}
            app={app}
            slot={slot}
            hostId={hostId}
            route={current}
            onNavigate={onNavigate ?? setLocalRoute}
            onRetry={() => setAttempt((previous) => previous + 1)}
        />
    )
}

function AppUiMount({
    app,
    sessionId,
    slot,
    hostId,
    route,
    onNavigate,
    onRetry,
}: FrameProps & {
    sessionId: string
    route: string
    onNavigate: (route: string) => void
    onRetry: () => void
}) {
    const inventory = useAppUi()
    const { t } = useTranslationStore()
    const [source, setSource] = useState<AppFrameSource | 'disconnected' | 'revoked'>()
    const { installationId, generation } = app
    const refresh = useEffectEvent(() => {
        void inventory?.refresh().catch(() => undefined)
    })

    useEffect(() => {
        const controller = new AbortController()
        const signal = AbortSignal.any([controller.signal, AbortSignal.timeout(15_000)])
        const nonce = crypto.randomUUID()
        const fragment = new URLSearchParams({ nonce })
        if (slot) fragment.set('slot', slot)
        if (slot === 'proxyHostTab' && hostId) fragment.set('hostId', hostId)

        void openAppUiHandler({ data: { installationId, generation, sessionId }, signal })
            .then((result) => {
                if (controller.signal.aborted) return
                if (!result.ok) {
                    const { code, status } = result.problem
                    setSource(
                        code === 'frameRevoked' && status === 401 ? 'revoked' : 'disconnected',
                    )
                    if (code === 'staleGeneration' && status === 409) refresh()
                    return
                }
                const url = new URL(result.src, window.location.origin)
                if (
                    url.origin !== window.location.origin ||
                    !url.pathname.startsWith(APP_UI_PREFIX)
                ) {
                    setSource('disconnected')
                    return
                }
                url.hash = fragment.toString()
                setSource({ nonce, url: url.href, frameToken: result.frameToken })
            })
            .catch(() => {
                if (!controller.signal.aborted) setSource('disconnected')
            })

        return () => controller.abort()
    }, [generation, hostId, installationId, sessionId, slot])

    if (source === undefined)
        return <output className="block p-3 text-sm text-muted">{t('appUi.loading')}</output>
    if (typeof source === 'string') {
        return (
            <div className="flex flex-wrap items-center gap-3 rounded-xl border border-border p-3">
                <output className="text-sm text-muted">{t('appUi.unavailable')}</output>
                {source === 'disconnected' ? (
                    <ModalActionButton variant="secondary" onClick={onRetry}>
                        {t('common.retry')}
                    </ModalActionButton>
                ) : null}
            </div>
        )
    }
    return (
        <OpenedAppFrame
            key={source.nonce}
            app={app}
            source={source}
            route={route}
            slot={slot}
            onNavigate={onNavigate}
            onDisconnect={(reason) => {
                setSource(reason === 'revoked' ? 'revoked' : 'disconnected')
                if (reason === 'stale') void inventory?.refresh().catch(() => undefined)
            }}
        />
    )
}

function OpenedAppFrame({
    app,
    source,
    slot,
    route,
    onNavigate,
    onDisconnect,
}: {
    app: AppUiSummary
    source: AppFrameSource
    slot: AppUiSlot | undefined
    route: string
    onNavigate: (route: string) => void
    onDisconnect: (reason: Exclude<AppUiRevocation, 'unmounted'>) => void
}) {
    const ui = useAppUi()
    const { locale } = useTranslationStore()
    const theme = ui?.theme ?? 'light'
    const iframe = useRef<HTMLIFrameElement>(null)
    const bridge = useRef<ReturnType<typeof bindAppUiFrame> | null>(null)
    const currentContext = useEffectEvent(() => ({ theme, locale, route }))
    const navigate = useEffectEvent(onNavigate)
    const dialog = useEffectEvent(
        (request: AppUiDialogRequest, settle: (outcome: 'confirmed' | 'cancelled') => void) => {
            ui?.openDialog({
                appName: app.name,
                dialogId: request.dialogId,
                mount: source.nonce,
                settle,
            })
        },
    )
    const revoke = useEffectEvent((reason: AppUiRevocation) => {
        ui?.cancelDialog(source.nonce)
        if (reason !== 'unmounted') onDisconnect(reason)
    })

    const bind = useEffectEvent((element: HTMLIFrameElement) =>
        bindAppUiFrame(element, source.nonce, app, {
            onConnected: () => currentContext(),
            onNavigate: (target) => navigate(target),
            onDialog: (request, settle) => dialog(request, settle),
            onRevoked: (reason) => revoke(reason),
            onApiRequest: ({ requestId, operationId, idempotencyKey, payload }, signal) =>
                callAppUi({
                    data: {
                        installationId: app.installationId,
                        generation: app.generation,
                        frameToken: source.frameToken,
                        requestId,
                        operationId,
                        idempotencyKey,
                        payload,
                    },
                    signal,
                }),
        }),
    )

    useLayoutEffect(() => {
        const element = iframe.current
        if (!element) return
        const session = bind(element)
        bridge.current = session
        return () => {
            bridge.current = null
            session.close()
        }
    }, [])

    useEffect(() => {
        bridge.current?.sendContext({ theme, locale, route })
    }, [locale, route, theme])

    return (
        <iframe
            ref={iframe}
            src={source.url}
            title={app.name}
            sandbox="allow-scripts"
            referrerPolicy="no-referrer"
            className={`block w-full rounded-xl border border-border bg-surface ${slot === 'dashboardWidget' ? 'min-h-64' : 'min-h-96'}`}
        />
    )
}
