import { expect, mock, spyOn, test } from 'bun:test'
import { GlobalRegistrator } from '@happy-dom/global-registrator'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import type { callAppUi } from '@/lib/AppUi/client.ts'
import type { AppUiResult, AppUiSummary } from '@/lib/AppUi/contract.ts'
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
const openedApp = {
    ok: true as const,
    src: '/__app-ui/test/index.html',
    native: { presentation: view, operations: ['read-values'] },
    frameToken: 'token',
}
const open = mock(async () => openedApp)
const call = mock(async (_input: Parameters<typeof callAppUi>[0]): Promise<AppUiResult> => ({
    ok: true,
    payload: { greeting: 'Gude!' },
}))
const revoked: AppUiResult = {
    ok: false,
    problem: {
        type: 'urn:rentnerproxy:problem:frameRevoked',
        title: 'The app UI session has ended.',
        code: 'frameRevoked',
        status: 401,
        requestId: 'revoked-request',
    },
}
await mock.module('@rentnerkev/toasts', () => ({
    toast: { success: mock(() => {}), error: mock(() => {}) },
}))
await mock.module('@/features/AppUi/AppUiProvider.tsx', () => ({
    useAppUi: () => ({ sessionId: 'test-session', cancelDialog: () => {} }),
}))
await mock.module('@/features/AppUi/middleware.ts', () => ({ openAppUiHandler: open }))
await mock.module('@/lib/AppUi/client.ts', () => ({ callAppUi: call }))

const { act } = await import('react')
const { createRoot } = await import('react-dom/client')
const { default: App } = await import('@/features/AppUi/NativeAppUi.tsx')

async function waitFor(condition: () => boolean) {
    const deadline = Date.now() + 2_000
    while (!condition()) {
        if (Date.now() >= deadline) throw new Error('Timed out waiting for the app view')
        // oxlint-disable-next-line no-await-in-loop -- Query observers publish their state asynchronously.
        await act(async () => await Bun.sleep(1))
    }
}

function mountApp() {
    open.mockClear()
    call.mockClear()
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
    }
    const unmount = async () => {
        await act(async () => root.unmount())
        client.clear()
        container.remove()
    }
    return { container, render, unmount, onNavigate, client }
}

async function setGreeting(input: HTMLInputElement, value: string) {
    await act(async () => {
        Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value')!.set!.call(
            input,
            value,
        )
        input.dispatchEvent(new Event('input', { bubbles: true }))
    })
}

test('renders app forms and tables in the host and reuses the view across routes', async () => {
    const { container, render, unmount, onNavigate } = mountApp()
    try {
        await render('overview')
        await waitFor(() => container.querySelector('input[value="Gude!"]') !== null)
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
        await waitFor(() => container.querySelector('input[value="Gude!"]') !== null)
        expect(container.querySelector('input[value="Gude!"]')).not.toBe(greeting)
        expect(open).toHaveBeenCalledTimes(2)
    } finally {
        await unmount()
    }
})

test('refreshes a previously visited table after a successful save through a different operation', async () => {
    const { container, render, unmount } = mountApp()
    const presentation = nativeAppPresentationSchema.parse({
        ...example,
        pages: [example.pages[0], { ...example.pages[1], read: 'read-summary' }],
    })
    open.mockResolvedValueOnce({
        ...openedApp,
        native: { presentation, operations: ['read-values', 'write-values', 'read-summary'] },
    })
    try {
        await render('details')
        const tableText = () => container.querySelector('table tbody')?.textContent ?? ''
        await waitFor(() => tableText().includes('Gude!'))
        await render('overview')
        const field = () => container.querySelector<HTMLInputElement>('input[value="Gude!"]')
        await waitFor(() => field() !== null)
        await setGreeting(field()!, 'Gude neu!')
        const submit = container.querySelector<HTMLButtonElement>('button[type="submit"]')
        expect(submit?.disabled).toBe(false)
        const updated: AppUiResult = { ok: true, payload: { greeting: 'Gude neu!' } }
        call.mockResolvedValueOnce(updated)
            .mockResolvedValueOnce(updated)
            .mockResolvedValueOnce(updated)
        await act(async () => submit!.click())
        await waitFor(() => submit?.textContent === 'Save')
        expect(call.mock.calls.map(([input]) => input.data.operationId)).toEqual([
            'read-summary',
            'read-values',
            'write-values',
            'read-values',
        ])
        await render('details')
        await waitFor(() => tableText().includes('Gude neu!'))
        expect(call.mock.calls.at(-1)?.[0].data.operationId).toBe('read-summary')
        expect(open).toHaveBeenCalledTimes(1)
    } finally {
        await unmount()
    }
})

test('reopens the presentation and reuses the request identity after a revoked app token', async () => {
    const { container, render, unmount } = mountApp()
    open.mockResolvedValueOnce(openedApp).mockResolvedValueOnce({
        ...openedApp,
        frameToken: 'renewed',
    })
    call.mockResolvedValueOnce(revoked)
    try {
        await render('overview')
        await waitFor(() => container.querySelector('input[value="Gude!"]') !== null)
        const sent = call.mock.calls.map(([input]) => input.data)
        expect(sent.map(({ frameToken }) => frameToken)).toEqual(['token', 'renewed'])
        expect(sent[1]?.idempotencyKey).toBe(sent[0]?.idempotencyKey)
        expect(open).toHaveBeenCalledTimes(2)
    } finally {
        await unmount()
    }
})

test('releases the form when token renewal exceeds the save deadline', async () => {
    const { container, render, unmount, client } = mountApp()
    const appWithWrite = {
        ...openedApp,
        native: { ...openedApp.native, operations: ['read-values', 'write-values'] },
    }
    const renewal = Promise.withResolvers<typeof openedApp>()
    open.mockResolvedValueOnce(appWithWrite).mockImplementationOnce(() => renewal.promise)
    const expiry = new AbortController()
    const timeout = spyOn(AbortSignal, 'timeout')
    try {
        await render('overview')
        const field = () => container.querySelector<HTMLInputElement>('input[value="Gude!"]')
        await waitFor(() => field() !== null)
        await setGreeting(field()!, 'Gude neu!')
        const submit = container.querySelector<HTMLButtonElement>('button[type="submit"]')
        expect(submit?.disabled).toBe(false)
        timeout.mockReturnValue(expiry.signal)
        call.mockResolvedValueOnce(revoked)
        await act(async () => submit!.click())
        await waitFor(() => open.mock.calls.length === 2 && submit?.disabled === true)
        await act(async () =>
            expiry.abort(new DOMException('Save deadline exceeded', 'TimeoutError')),
        )
        await waitFor(() => submit?.disabled === false)
        expect(client.isFetching()).toBe(1)
        expect(call).toHaveBeenCalledTimes(2)
        await act(async () => renewal.resolve({ ...appWithWrite, frameToken: 'renewed' }))
        await waitFor(() => client.isFetching() === 0)
        expect(call).toHaveBeenCalledTimes(2)
    } finally {
        timeout.mockRestore()
        renewal.resolve(appWithWrite)
        await unmount()
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
