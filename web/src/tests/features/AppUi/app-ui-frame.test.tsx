import { expect, mock, test } from 'bun:test'
import { GlobalRegistrator } from '@happy-dom/global-registrator'
import type { UserThemeMode } from '@/config/Types/theme-config.types.ts'
import type { AppUiSummary } from '@/lib/AppUi/contract.ts'
import type { AppLanguage } from '@/shared/Language/Types/language.types.ts'
import withTestLanguage from '@/tests/Helpers/withTestLanguage.tsx'

if (!GlobalRegistrator.isRegistered) GlobalRegistrator.register({ url: 'https://platform.test/' })
Object.assign(globalThis, { IS_REACT_ACT_ENVIRONMENT: true })

const app: AppUiSummary = {
    appId: 'test.app',
    installationId: 'test-installation',
    generation: 7,
    name: 'Test app',
    routes: ['overview', 'details'],
    dialogs: [],
    slots: ['navigation'],
    events: [],
    permissionKeys: [],
}
let sessionId: string | null = 'test-session'
let theme: UserThemeMode = 'light'

const openFrame = mock(async () => ({
    ok: true as const,
    src: '/__app-ui/test-installation/index.html',
    frameToken: 'test-token',
}))
const context = mock(() => {})
const close = mock(() => {})
const bindFrame = mock(() => ({ sendContext: context, close }))

await mock.module('@/features/AppUi/AppUiProvider.tsx', () => ({
    useAppUi: () => ({ sessionId, theme }),
}))
await mock.module('@/features/AppUi/middleware.ts', () => ({ openAppUiHandler: openFrame }))
await mock.module('@/lib/AppUi/session.ts', () => ({ bindAppUiFrame: bindFrame }))

const { act } = await import('react')
const { createRoot } = await import('react-dom/client')
const { default: AppUiFrame } = await import('@/features/AppUi/AppUiFrame.tsx')

test('updates app context in place and retires the frame on generation or session changes', async () => {
    const container = document.createElement('div')
    const root = createRoot(container)
    const frame = () => container.querySelector('iframe')
    const render = async (
        route: string,
        language: AppLanguage = 'en',
        generation = app.generation,
    ) => {
        await act(async () => {
            root.render(
                withTestLanguage(
                    <AppUiFrame app={{ ...app, generation }} slot="navigation" route={route} />,
                    language,
                ),
            )
        })
    }

    try {
        await render('overview')
        const original = frame()
        const source = original?.getAttribute('src')
        expect(original).not.toBeNull()
        expect(original?.getAttribute('sandbox')).toBe('allow-scripts')

        theme = 'dark'
        await render('details', 'de')
        expect(frame()).toBe(original)
        expect(frame()?.getAttribute('src')).toBe(source)
        expect(context).toHaveBeenLastCalledWith({
            route: 'details',
            theme: 'dark',
            locale: 'de-DE',
        })

        await render('overview', 'de')
        expect(frame()).toBe(original)
        expect(context).toHaveBeenLastCalledWith({
            route: 'overview',
            theme: 'dark',
            locale: 'de-DE',
        })
        expect(openFrame).toHaveBeenCalledTimes(1)
        expect(bindFrame).toHaveBeenCalledTimes(1)
        expect(close).not.toHaveBeenCalled()

        await render('overview', 'de', 8)
        const updated = frame()
        expect(updated).not.toBeNull()
        expect(updated).not.toBe(original)
        expect(openFrame).toHaveBeenCalledTimes(2)
        expect(close).toHaveBeenCalledTimes(1)

        sessionId = 'other-session'
        await render('overview', 'de', 8)
        expect(frame()).not.toBeNull()
        expect(frame()).not.toBe(updated)
        expect(openFrame).toHaveBeenCalledTimes(3)
        expect(close).toHaveBeenCalledTimes(2)

        sessionId = null
        await render('overview', 'de', 8)
        expect(frame()).toBeNull()
        expect(openFrame).toHaveBeenCalledTimes(3)
        expect(close).toHaveBeenCalledTimes(3)
    } finally {
        await act(async () => root.unmount())
    }
})
