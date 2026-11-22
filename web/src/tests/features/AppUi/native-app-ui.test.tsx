import { expect, mock, test } from 'bun:test'
import { GlobalRegistrator } from '@happy-dom/global-registrator'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import type { AppUiSummary } from '@/lib/AppUi/contract.ts'
import { nativeAppPresentationSchema } from '@/lib/AppUi/native-presentation.ts'
import withTestLanguage from '@/tests/Helpers/withTestLanguage.tsx'

if (!GlobalRegistrator.isRegistered) GlobalRegistrator.register({ url: 'https://platform.test/' })
Object.assign(globalThis, { IS_REACT_ACT_ENVIRONMENT: true })

const example = {
    formatVersion: 1,
    pages: [
        {
            kind: 'form',
            route: 'overview',
            label: 'Overview',
            read: 'read-values',
            write: 'write-values',
            submitLabel: 'Save',
            fields: [{ field: 'greeting', label: 'Greeting', minLength: 1, maxLength: 120 }],
        },
        {
            kind: 'table',
            route: 'details',
            label: 'Details',
            read: 'read-values',
            columns: [{ field: 'greeting', label: 'Greeting' }],
        },
    ],
}
const view = nativeAppPresentationSchema.parse(example)
const app: AppUiSummary = {
    appId: 'example.app',
    installationId: 'example-installation',
    generation: 7,
    name: 'Example',
    native: true,
    routes: ['overview', 'details'],
    dialogs: [],
    slots: ['navigation'],
    events: [],
    permissionKeys: ['read', 'write'],
}
const open = mock(async () => ({
    ok: true as const,
    src: '/__app-ui/test/index.html',
    native: { presentation: view, operations: ['read-values'] },
    frameToken: 'token',
}))
const call = mock(async () => ({ ok: true as const, payload: { greeting: 'Gude!' } }))
await mock.module('@/features/AppUi/AppUiProvider.tsx', () => ({
    useAppUi: () => ({ sessionId: 'test-session', cancelDialog: () => {} }),
}))
await mock.module('@/features/AppUi/middleware.ts', () => ({ openAppUiHandler: open }))
await mock.module('@/lib/AppUi/client.ts', () => ({ callAppUi: call }))

const { act } = await import('react')
const { createRoot } = await import('react-dom/client')
const { default: App } = await import('@/features/AppUi/NativeAppUi.tsx')

test('renders app forms and tables in the host and reuses the view across routes', async () => {
    const container = document.createElement('div')
    document.body.append(container)
    const root = createRoot(container)
    const client = new QueryClient()
    const onNavigate = mock(() => {})
    const render = async (route: string, generation = app.generation) => {
        await act(async () =>
            root.render(
                withTestLanguage(
                    <QueryClientProvider client={client}>
                        <App app={{ ...app, generation }} route={route} onNavigate={onNavigate} />
                    </QueryClientProvider>,
                ),
            ),
        )
        const deadline = Date.now() + 2_000
        while (!container.querySelector('input[value="Gude!"]') && Date.now() < deadline) {
            // oxlint-disable-next-line no-await-in-loop -- Query observers publish their state asynchronously.
            await act(async () => await Bun.sleep(1))
        }
    }
    try {
        await render('overview')
        const greeting = container.querySelector('input[value="Gude!"]')
        expect(greeting).not.toBeNull()
        expect(greeting?.hasAttribute('readonly')).toBe(true)
        expect(container.querySelector('button[type=submit]')).toBeNull()
        expect(container.querySelector('iframe')).toBeNull()
        await act(async () => {
            const details = Array.from(container.querySelectorAll('nav button')).find(
                (button) => button.textContent === 'Details',
            )
            expect(details).toBeDefined()
            if (details instanceof HTMLButtonElement) details.click()
        })
        expect(onNavigate).toHaveBeenCalledWith('details')
        await render('details')
        expect(container.querySelector('input[value="Gude!"]')).toBe(greeting)
        expect(container.querySelector('table tbody')?.textContent).toContain('Gude!')
        expect(open).toHaveBeenCalledTimes(1)
        expect(call).toHaveBeenCalledTimes(1)

        await render('overview', 8)
        expect(container.querySelector('input[value="Gude!"]')).not.toBe(greeting)
        expect(open).toHaveBeenCalledTimes(2)
    } finally {
        await act(async () => root.unmount())
        client.clear()
        container.remove()
    }
})

test('native UI declarations allow only typed presentation fields', () => {
    const overview = example.pages[0]
    expect(
        nativeAppPresentationSchema.safeParse({
            ...example,
            pages: [{ ...overview, html: '<script>throw 1</script>' }],
        }).success,
    ).toBe(false)
    expect(
        nativeAppPresentationSchema.safeParse({
            ...example,
            pages: [{ ...overview, fields: [{ field: '__proto__', label: 'Invalid field' }] }],
        }).success,
    ).toBe(false)
})
