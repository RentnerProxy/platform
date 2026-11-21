import { expect, mock, spyOn, test } from 'bun:test'
import { GlobalRegistrator } from '@happy-dom/global-registrator'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import {
    APP_CATALOG_INSTALL_PATH,
    type CatalogInstall,
    type CatalogSnapshot,
} from '@/lib/AppCatalog/contract.ts'
import withTestLanguage from '@/tests/Helpers/withTestLanguage.tsx'

if (!GlobalRegistrator.isRegistered) GlobalRegistrator.register()
Object.assign(globalThis, { IS_REACT_ACT_ENVIRONMENT: true })

const selection = {
    appId: 'rentnerproxy.greeting',
    version: '1.0.0',
    archiveSha256: 'a'.repeat(64),
}
const pending = { ...selection, status: 'installing' } satisfies CatalogInstall
let snapshot: CatalogSnapshot = {
    state: 'ready',
    entries: [
        {
            ...selection,
            name: 'Greeting',
            publisher: 'RentnerProxy',
            summary: 'Save a greeting.',
            hasUi: true,
            availability: 'available',
        },
    ],
    install: null,
}
const refreshApps = mock(async () => [])

await mock.module('@/features/AppCatalog/middleware.ts', () => ({
    getAppCatalogHandler: () => Promise.resolve(snapshot),
}))
await mock.module('@/features/AppUi/AppUiProvider.tsx', () => ({
    useAppUi: () => ({ apps: [], sessionId: 'owner-session', refresh: refreshApps }),
}))

const { act } = await import('react')
const { createRoot } = await import('react-dom/client')
const { createMemoryHistory, createRootRoute, createRoute, createRouter, RouterContextProvider } =
    await import('@tanstack/react-router')
const { default: AppCatalogPage } = await import('@/features/AppCatalog/index.tsx')

async function waitFor(condition: () => boolean) {
    const deadline = Date.now() + 2_000
    while (!condition()) {
        if (Date.now() >= deadline) throw new Error('Timed out waiting for the catalog view')
        // oxlint-disable-next-line no-await-in-loop -- Observe each asynchronous render in order.
        await act(async () => {
            await Bun.sleep(10)
        })
    }
}

test('installs the signed selection and opens it when the app inventory needs a retry', async () => {
    const request = spyOn(globalThis, 'fetch').mockResolvedValue(
        Response.json(pending, { status: 202 }),
    )
    const routeRoot = createRootRoute()
    const router = createRouter({
        routeTree: routeRoot.addChildren([
            createRoute({ getParentRoute: () => routeRoot, path: '/app-catalog' }),
            createRoute({
                getParentRoute: () => routeRoot,
                path: '/apps/$installationId/{-$routeId}',
            }),
        ]),
        history: createMemoryHistory({ initialEntries: ['/app-catalog'] }),
    })
    const client = new QueryClient()
    const container = document.createElement('div')
    document.body.append(container)
    const root = createRoot(container)
    const button = (label: string) =>
        Array.from(container.querySelectorAll('button')).find(
            (candidate) => candidate.textContent === label,
        )
    const openLink = () =>
        container.querySelector<HTMLAnchorElement>('a[href="/apps/greeting-test"]')

    try {
        await router.load()
        await act(async () => {
            root.render(
                withTestLanguage(
                    <QueryClientProvider client={client}>
                        <RouterContextProvider router={router}>
                            <AppCatalogPage />
                        </RouterContextProvider>
                    </QueryClientProvider>,
                ),
            )
        })
        await waitFor(() => button('Install')?.disabled === false)
        expect(container.querySelector('h2')?.textContent).toBe('Greeting')
        snapshot = { ...snapshot, install: pending }
        await act(async () => button('Install')!.click())
        await waitFor(
            () =>
                container.textContent?.includes('Installing app…') === true &&
                button('Refresh catalog')?.disabled === false,
        )
        expect(button('Install')?.disabled).toBe(true)
        expect(request).toHaveBeenCalledTimes(1)
        expect(request).toHaveBeenCalledWith(
            APP_CATALOG_INSTALL_PATH,
            expect.objectContaining({ method: 'POST', body: JSON.stringify(selection) }),
        )

        snapshot = {
            ...snapshot,
            install: { ...selection, status: 'installed', installationId: 'greeting-test' },
        }
        await act(async () => button('Refresh catalog')!.click())
        await waitFor(() => openLink() !== null && refreshApps.mock.calls.length === 1)
        expect(openLink()?.textContent).toBe('Open app')
        await act(async () => openLink()!.click())
        await waitFor(() => router.state.location.pathname === '/apps/greeting-test')
        expect(refreshApps).toHaveBeenCalledTimes(2)
    } finally {
        await act(async () => root.unmount())
        client.clear()
        container.remove()
        request.mockRestore()
    }
})
