import { expect, mock, spyOn, test } from 'bun:test'
import { GlobalRegistrator } from '@happy-dom/global-registrator'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import {
    APP_CATALOG_INSTALL_PATH,
    APP_CATALOG_LIFECYCLE_PATH,
    type CatalogInstall,
    type CatalogInstallation,
    type CatalogLifecycleInput,
    type CatalogSnapshot,
} from '@/lib/AppCatalog/contract.ts'
import { unavailableCatalog } from '@/lib/AppCatalog/installProgress.ts'
import type { AppUiSummary } from '@/lib/AppUi/contract.ts'
import withTestLanguage from '@/tests/Helpers/withTestLanguage.tsx'

if (!GlobalRegistrator.isRegistered) GlobalRegistrator.register()
Object.assign(globalThis, { IS_REACT_ACT_ENVIRONMENT: true })

const selection = {
    appId: 'rentnerproxy.greeting',
    version: '1.0.0',
    archiveSha256: 'a'.repeat(64),
}
const pending = { ...selection, status: 'installing' } satisfies CatalogInstall
const { version, archiveSha256 } = selection
const current = {
    ...selection,
    installationId: 'greeting-test',
    generation: 1,
    state: 'running',
    update: null,
    previous: null,
} satisfies CatalogInstallation
const ready: CatalogSnapshot = {
    ...unavailableCatalog,
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
}
let snapshot = ready
let apps: AppUiSummary[] = []
const refreshApps = mock(async () => [])

await mock.module('@/features/AppCatalog/middleware.ts', () => ({
    getAppCatalogHandler: () => Promise.resolve(snapshot),
}))
await mock.module('@/features/AppUi/AppUiProvider.tsx', () => ({
    useAppUi: () => ({ apps, sessionId: 'owner-session', refresh: refreshApps }),
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

async function mountCatalog() {
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
    return {
        router,
        container,
        button,
        async unmount() {
            await act(async () => root.unmount())
            client.clear()
            container.remove()
        },
    }
}

test('installs the signed selection and opens it after authorized app discovery', async () => {
    snapshot = ready
    apps = []
    refreshApps.mockClear()
    const request = spyOn(globalThis, 'fetch').mockResolvedValue(
        Response.json(pending, { status: 202 }),
    )
    const { router, container, button, unmount } = await mountCatalog()
    const openLink = () =>
        container.querySelector<HTMLAnchorElement>('a[href="/apps/greeting-test"]')

    try {
        await waitFor(() => button('Install')?.disabled === false)
        expect(container.querySelector('h3')?.textContent).toBe('Greeting')
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
            installations: [current],
        }
        apps = [
            {
                appId: selection.appId,
                installationId: current.installationId,
                generation: current.generation,
                name: 'Greeting',
                slots: [],
                routes: [],
                dialogs: [],
                events: [],
                permissionKeys: [],
            },
        ]
        await act(async () => button('Refresh catalog')!.click())
        await waitFor(() => openLink() !== null && refreshApps.mock.calls.length === 1)
        expect(openLink()?.textContent).toBe('Open app')
        await act(async () => openLink()!.click())
        await waitFor(() => router.state.location.pathname === '/apps/greeting-test')
        expect(refreshApps).toHaveBeenCalledTimes(1)
    } finally {
        await unmount()
        request.mockRestore()
    }
})

test('updates to the offered signed version and reflects the confirmed generation', async () => {
    const target = { version: '1.1.0', archiveSha256: 'b'.repeat(64) }
    const update = {
        action: 'update',
        installationId: current.installationId,
        expected: { generation: current.generation, version, archiveSha256 },
        target,
    } satisfies CatalogLifecycleInput
    const operation = { ...update, status: 'pending' as const }
    snapshot = { ...ready, installations: [{ ...current, update: target }] }
    apps = []
    refreshApps.mockClear()
    const post = spyOn(globalThis, 'fetch').mockResolvedValueOnce(
        Response.json(operation, { status: 202 }),
    )
    const { container, button, unmount } = await mountCatalog()
    try {
        await waitFor(() => button('Update to 1.1.0')?.disabled === false)
        expect(button('Install')).toBeUndefined()
        snapshot = { ...snapshot, lifecycle: operation }
        await act(async () => button('Update to 1.1.0')!.click())
        await waitFor(() => container.textContent?.includes('Updating app…') === true)
        expect(post).toHaveBeenCalledWith(
            APP_CATALOG_LIFECYCLE_PATH,
            expect.objectContaining({ method: 'POST', body: JSON.stringify(update) }),
        )
        snapshot = {
            ...snapshot,
            installations: [
                {
                    ...current,
                    ...target,
                    generation: current.generation + 1,
                    previous: { version, archiveSha256 },
                },
            ],
            lifecycle: { ...update, status: 'succeeded' },
        }
        await waitFor(() => button('Refresh catalog')?.disabled === false)
        await act(async () => button('Refresh catalog')!.click())
        await waitFor(() => button('Roll back')?.disabled === false)
        expect(button('Update to 1.1.0')).toBeUndefined()
        expect(container.textContent).toContain('App updated.')
        expect(refreshApps).toHaveBeenCalledTimes(1)
        await act(async () => button('Roll back')!.click())
        expect(document.querySelector('[role="dialog"]')?.textContent).toContain('version 1.0.0')
        expect(post).toHaveBeenCalledTimes(1)
    } finally {
        await unmount()
        post.mockRestore()
    }
})

test('manages a local app while the catalog is unavailable and confirms retained-data uninstall', async () => {
    snapshot = { ...unavailableCatalog, installations: [current] }
    apps = []
    const deactivate = {
        action: 'deactivate',
        installationId: current.installationId,
        expected: { generation: 1, version, archiveSha256 },
    } satisfies CatalogLifecycleInput
    const uninstall = { ...deactivate, action: 'uninstall' } satisfies CatalogLifecycleInput
    const pendingDeactivation = { ...deactivate, status: 'pending' as const }
    const pendingUninstall = { ...uninstall, status: 'pending' as const }
    const post = spyOn(globalThis, 'fetch')
        .mockResolvedValueOnce(Response.json(pendingDeactivation, { status: 202 }))
        .mockResolvedValueOnce(Response.json(pendingUninstall, { status: 202 }))
    const { container, button, unmount } = await mountCatalog()

    try {
        await waitFor(() => button('Deactivate')?.disabled === false)
        expect(container.textContent).toContain('The app catalog is currently unavailable.')
        expect(container.textContent).toContain(selection.appId)
        snapshot = { ...snapshot, lifecycle: pendingDeactivation }
        await act(async () => button('Deactivate')!.click())
        await waitFor(() => container.textContent?.includes('Deactivating app…') === true)
        expect(button('Uninstall')?.disabled).toBe(true)
        expect(post).toHaveBeenNthCalledWith(
            1,
            APP_CATALOG_LIFECYCLE_PATH,
            expect.objectContaining({ body: JSON.stringify(deactivate) }),
        )

        snapshot = {
            ...snapshot,
            installations: [{ ...current, state: 'disabled' }],
            lifecycle: { ...deactivate, status: 'succeeded' },
        }
        await waitFor(() => button('Refresh catalog')?.disabled === false)
        await act(async () => button('Refresh catalog')!.click())
        await waitFor(() => button('Reactivate')?.disabled === false)
        expect(container.textContent).toContain('App deactivated.')

        await act(async () => button('Uninstall')!.click())
        const dialog = document.querySelector('[role="dialog"]')
        expect(dialog?.textContent).toContain('its data will be kept for reinstallation')
        expect(post).toHaveBeenCalledTimes(1)
        const confirm = [...(dialog?.querySelectorAll('button') ?? [])].find(
            (candidate) => candidate.textContent === 'Uninstall',
        )
        expect(confirm).toBeDefined()
        snapshot = { ...snapshot, lifecycle: pendingUninstall }
        await act(async () => confirm!.click())
        await waitFor(() => container.textContent?.includes('Uninstalling app…') === true)
        expect(post).toHaveBeenNthCalledWith(
            2,
            APP_CATALOG_LIFECYCLE_PATH,
            expect.objectContaining({ body: JSON.stringify(uninstall) }),
        )

        snapshot = {
            ...snapshot,
            installations: [{ ...current, state: 'removed' }],
            lifecycle: { ...uninstall, status: 'succeeded' },
        }
        await waitFor(() => button('Refresh catalog')?.disabled === false)
        await act(async () => button('Refresh catalog')!.click())
        await waitFor(() => button('Delete retained data')?.disabled === false)
        expect(container.textContent).toContain('Retained app data')
        expect(container.textContent).toContain('App uninstalled. Its data was kept.')
        await act(async () => button('Delete retained data')!.click())
        expect(document.querySelector('[role="dialog"]')?.textContent).toContain(
            'This cannot be undone.',
        )
        expect(post).toHaveBeenCalledTimes(2)
    } finally {
        await unmount()
        post.mockRestore()
    }
})
