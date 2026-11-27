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
    name: null,
    providers: null,
    grants: null,
    update: null,
    updateRequiresApproval: false,
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
            providers: [],
            grants: [],
            permissionKeys: [],
            availability: 'available',
            cached: false,
        },
    ],
}
let snapshot = ready
let apps: AppUiSummary[] = []
const refreshApps = mock(async () => [])

const proxyHosts = [
    { id: '2f9c4b1e-6a3d-4e8f-9b7c-0d1e2f3a4b5c', hostname: 'app.example.com', enabled: true },
    { id: '8a7b6c5d-4e3f-4a1b-9c8d-7e6f5a4b3c2d', hostname: 'old.example.com', enabled: false },
]

await mock.module('@/features/AppCatalog/middleware.ts', () => ({
    getAppCatalogHandler: () => Promise.resolve(snapshot),
    getAppCatalogProxyHostsHandler: () => Promise.resolve(proxyHosts),
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

test('recovers a completed lifecycle action when its POST response is lost', async () => {
    const action = {
        action: 'deactivate',
        installationId: current.installationId,
        expected: { generation: current.generation, version, archiveSha256 },
    } satisfies CatalogLifecycleInput
    snapshot = { ...ready, installations: [current] }
    apps = []
    const post = spyOn(globalThis, 'fetch').mockRejectedValueOnce(
        new TypeError('The response was lost'),
    )
    const { container, button, unmount } = await mountCatalog()
    try {
        await waitFor(() => button('Deactivate')?.disabled === false)
        await act(async () => {
            button('Deactivate')!.click()
            snapshot = {
                ...snapshot,
                installations: [{ ...current, state: 'disabled' }],
                lifecycle: { ...action, status: 'succeeded' },
            }
        })
        await waitFor(() => button('Reactivate')?.disabled === false)
        expect(container.textContent).toContain('App deactivated.')
        expect(container.textContent).not.toContain('The app action could not be completed.')
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

test('explains newer releases that the appliance cannot offer for an installed app', async () => {
    const listed = ready.entries[0]!
    const offered = { version: '1.0.1', archiveSha256: 'b'.repeat(64) }
    snapshot = {
        ...ready,
        entries: [
            listed,
            { ...listed, ...offered },
            {
                ...listed,
                version: '1.0.2',
                archiveSha256: 'c'.repeat(64),
                availability: 'grantsRequired',
            },
        ],
        installations: [{ ...current, update: offered }],
    }
    apps = []
    const { container, button, unmount } = await mountCatalog()
    try {
        await waitFor(() => button('Update to 1.0.1')?.disabled === false)
        expect(container.textContent).toContain(
            'Version 1.0.2 requests access this appliance cannot grant, so it is not offered.',
        )
        expect(button('Install')).toBeUndefined()

        snapshot = {
            ...snapshot,
            entries: [
                listed,
                {
                    ...listed,
                    version: '2.0.0',
                    archiveSha256: 'd'.repeat(64),
                    availability: 'incompatible',
                },
            ],
            installations: [current],
        }
        await act(async () => button('Refresh catalog')!.click())
        await waitFor(
            () =>
                container.textContent?.includes(
                    'Version 2.0.0 is incompatible with this appliance, so it is not offered.',
                ) === true,
        )
        expect(button('Update to 1.0.1')).toBeUndefined()
        expect(container.textContent).not.toContain('cannot grant')
    } finally {
        await unmount()
    }
})

const readHosts = { id: 'proxy.hosts.read.v1', scope: 'proxyHosts' }
const notify = { id: 'notifications.publish.v1', scope: 'installation' }
const support = [
    { id: 'app.events.subscribe', scope: 'installation' },
    { id: 'app.audit.record', scope: 'installation' },
]
const requesting = (...capabilities: { id: string; scope: string }[]) =>
    [...capabilities, ...support].map((capability) => ({ capability, allowService: true }))

function openDialog() {
    return document.querySelector<HTMLElement>('[role="dialog"]')
}

function dialogButton(label: string) {
    return Array.from(openDialog()?.querySelectorAll('button') ?? []).find(
        (candidate) => candidate.textContent === label,
    )
}

async function pick(trigger: HTMLButtonElement, label: string) {
    await act(async () => {
        trigger.dispatchEvent(
            new MouseEvent('click', { bubbles: true, button: 0, cancelable: true }),
        )
    })
    await waitFor(() => document.querySelector('[role="option"]') !== null)
    const option = Array.from(document.querySelectorAll<HTMLElement>('[role="option"]')).find(
        (candidate) => candidate.textContent?.includes(label),
    )
    expect(option).toBeDefined()
    await act(async () => {
        option!.dispatchEvent(
            new PointerEvent('pointerup', { bubbles: true, button: 0, pointerType: 'mouse' }),
        )
        option!.dispatchEvent(new MouseEvent('click', { bubbles: true, cancelable: true }))
    })
}

test('installs a release with capabilities only after the Owner approves its access', async () => {
    snapshot = {
        ...ready,
        entries: [{ ...ready.entries[0]!, grants: requesting(readHosts, notify) }],
    }
    apps = []
    const post = spyOn(globalThis, 'fetch').mockResolvedValue(
        Response.json(pending, { status: 202 }),
    )
    const { button, unmount } = await mountCatalog()
    try {
        await waitFor(() => button('Install')?.disabled === false)
        await act(async () => button('Install')!.click())
        await waitFor(() => openDialog()?.textContent?.includes('Review requested access') === true)
        expect(openDialog()!.textContent).toContain('Read proxy hosts')
        expect(openDialog()!.textContent).toContain('Receive change events')
        expect(dialogButton('Approve and install')?.disabled).toBe(true)
        // Declining sends nothing.
        await act(async () => dialogButton('Decline')!.click())
        await waitFor(() => openDialog() === null)
        expect(post).not.toHaveBeenCalled()

        await act(async () => button('Install')!.click())
        await waitFor(
            () =>
                openDialog()?.querySelector<HTMLButtonElement>('button[role="combobox"]')
                    ?.disabled === false,
        )
        await pick(
            openDialog()!.querySelector<HTMLButtonElement>('button[role="combobox"]')!,
            'app.example.com',
        )
        await waitFor(() => dialogButton('Approve and install')?.disabled === false)
        await act(async () => dialogButton('Approve and install')!.click())
        await waitFor(() => post.mock.calls.length === 1)
        expect(post).toHaveBeenCalledWith(
            APP_CATALOG_INSTALL_PATH,
            expect.objectContaining({
                method: 'POST',
                body: JSON.stringify({
                    ...selection,
                    approval: [
                        {
                            capability: readHosts,
                            resourceId: proxyHosts[0]!.id,
                            allowService: true,
                        },
                        { capability: notify, allowService: true },
                        { capability: support[0], allowService: true },
                        { capability: support[1], allowService: true },
                    ],
                }),
            }),
        )
        await waitFor(() => openDialog() === null)
    } finally {
        await unmount()
        post.mockRestore()
    }
})

test('reviews an update that requests more access and revokes approved access', async () => {
    const target = { version: '1.1.0', archiveSha256: 'b'.repeat(64) }
    const approved = [
        { capability: support[1]!, resourceId: current.installationId, allowService: true },
        { capability: support[0]!, resourceId: current.installationId, allowService: true },
        { capability: readHosts, resourceId: proxyHosts[0]!.id, allowService: true },
    ]
    const installation = { ...current, grants: approved, update: target }
    const expected = { generation: current.generation, version, archiveSha256 }
    snapshot = {
        ...ready,
        entries: [
            { ...ready.entries[0]!, grants: requesting(readHosts) },
            { ...ready.entries[0]!, ...target, grants: requesting(readHosts, notify) },
        ],
        installations: [{ ...installation, updateRequiresApproval: true }],
    }
    apps = []
    const receipt = (action: CatalogLifecycleInput['action'], extra: object) =>
        Response.json(
            {
                action,
                installationId: current.installationId,
                expected,
                ...extra,
                status: 'pending',
            },
            { status: 202 },
        )
    const post = spyOn(globalThis, 'fetch')
        .mockResolvedValueOnce(receipt('update', { target }))
        .mockResolvedValueOnce(receipt('revoke', {}))
    const { container, button, unmount } = await mountCatalog()
    try {
        await waitFor(() => button('Review update to 1.1.0')?.disabled === false)
        expect(container.textContent).toContain(
            'Version 1.1.0 requests additional access. Review it before updating.',
        )
        expect(container.textContent).toContain('Read proxy hosts: app.example.com')
        await act(async () => button('Review update to 1.1.0')!.click())
        // The approved host is preselected, so only the new capability needs a decision.
        await waitFor(() => dialogButton('Approve and update to 1.1.0')?.disabled === false)
        expect(openDialog()!.textContent).toContain('Send notifications')
        await act(async () => dialogButton('Approve and update to 1.1.0')!.click())
        await waitFor(() => post.mock.calls.length === 1)
        expect(post).toHaveBeenLastCalledWith(
            APP_CATALOG_LIFECYCLE_PATH,
            expect.objectContaining({
                body: JSON.stringify({
                    action: 'update',
                    installationId: current.installationId,
                    expected,
                    target,
                    approval: [
                        {
                            capability: readHosts,
                            resourceId: proxyHosts[0]!.id,
                            allowService: true,
                        },
                        { capability: notify, allowService: true },
                        { capability: support[0], allowService: true },
                        { capability: support[1], allowService: true },
                    ],
                }),
            }),
        )

        snapshot = {
            ...snapshot,
            installations: [installation],
            lifecycle: {
                action: 'update',
                installationId: current.installationId,
                expected,
                target,
                status: 'succeeded',
            },
        }
        await act(async () => button('Refresh catalog')!.click())
        await waitFor(() => button('Update to 1.1.0')?.disabled === false)
        const revoke = Array.from(container.querySelectorAll('button')).filter(
            (candidate) => candidate.textContent === 'Revoke',
        )
        expect(revoke).toHaveLength(3)
        // Capabilities come before support grants.
        await act(async () => revoke[0]!.click())
        await waitFor(
            () => openDialog()?.textContent?.includes('Revoke “Read proxy hosts') === true,
        )
        expect(post).toHaveBeenCalledTimes(1)
        await act(async () => dialogButton('Revoke grants')!.click())
        await waitFor(() => post.mock.calls.length === 2)
        expect(post).toHaveBeenLastCalledWith(
            APP_CATALOG_LIFECYCLE_PATH,
            expect.objectContaining({
                body: JSON.stringify({
                    action: 'revoke',
                    installationId: current.installationId,
                    expected,
                    grants: [{ capability: readHosts, resourceId: proxyHosts[0]!.id }],
                }),
            }),
        )

        snapshot = {
            ...snapshot,
            lifecycle: {
                action: 'revoke',
                installationId: current.installationId,
                expected,
                status: 'failed',
                error: 'revokedAppStopped',
            },
        }
        await act(async () => button('Refresh catalog')!.click())
        await waitFor(
            () =>
                container.textContent?.includes(
                    'The access was revoked, but the running app could not apply the change',
                ) === true,
        )
    } finally {
        await unmount()
        post.mockRestore()
    }
})

test('reports a dependency that blocks an uninstall apart from a conflict', async () => {
    const uninstall = {
        action: 'uninstall',
        installationId: current.installationId,
        expected: { generation: current.generation, version, archiveSha256 },
    } satisfies CatalogLifecycleInput
    snapshot = { ...ready, installations: [current] }
    apps = []
    const post = spyOn(globalThis, 'fetch').mockResolvedValueOnce(
        Response.json({ ...uninstall, status: 'pending' }, { status: 202 }),
    )
    const { container, button, unmount } = await mountCatalog()
    try {
        await waitFor(() => button('Uninstall')?.disabled === false)
        await act(async () => button('Uninstall')!.click())
        const confirm = [
            ...(document.querySelector('[role="dialog"]')?.querySelectorAll('button') ?? []),
        ].find((candidate) => candidate.textContent === 'Uninstall')
        expect(confirm).toBeDefined()
        snapshot = {
            ...snapshot,
            lifecycle: { ...uninstall, status: 'failed', error: 'dependencyBlocked' },
        }
        await act(async () => confirm!.click())
        await waitFor(
            () => container.textContent?.includes('Something still depends on this app') === true,
        )
        expect(container.textContent).toContain('The app action could not be completed.')
        expect(container.textContent).not.toContain('another action is running')
        expect(post).toHaveBeenCalledTimes(1)
        expect(post).toHaveBeenCalledWith(
            APP_CATALOG_LIFECYCLE_PATH,
            expect.objectContaining({ body: JSON.stringify(uninstall) }),
        )
        await waitFor(() => button('Uninstall')?.disabled === false)
    } finally {
        await unmount()
        post.mockRestore()
    }
})

test('shows uncached packages as requiring their source after a package source outage', async () => {
    const listed = ready.entries[0]!
    const stored = {
        ...listed,
        appId: 'example.stored',
        name: 'Stored app',
        archiveSha256: 'e'.repeat(64),
        cached: true,
    }
    const requiresSource =
        'Not stored on this appliance. Installing it requires its package source.'
    snapshot = {
        ...ready,
        entries: [listed, stored],
        install: { ...selection, status: 'failed', error: 'packageSourceUnavailable' },
    }
    apps = []
    const { container, button, unmount } = await mountCatalog()
    try {
        await waitFor(() => button('Retry installation')?.disabled === false)
        expect(container.textContent).toContain(
            'The package source could not be reached, so the release could not be downloaded.',
        )
        const cards = [...container.querySelectorAll('li')]
        const card = (name: string) => cards.find((item) => item.textContent?.includes(name))
        expect(card('Greeting')?.textContent).toContain(requiresSource)
        expect(card('Stored app')?.textContent).not.toContain(requiresSource)
        expect(button('Install')?.disabled).toBe(false)

        snapshot = { ...snapshot, state: 'stale', install: null }
        await act(async () => button('Refresh catalog')!.click())
        await waitFor(
            () =>
                container.textContent?.includes('The catalog is out of date.') === true &&
                button('Refresh catalog')?.disabled === false,
        )
        expect(container.textContent?.split(requiresSource)).toHaveLength(2)
        expect(button('Install')?.disabled).toBe(true)
    } finally {
        await unmount()
    }
})

test('names the unreachable sources of a failed update and the verified app name', async () => {
    const target = { version: '1.1.0', archiveSha256: 'b'.repeat(64) }
    const update = {
        action: 'update',
        installationId: current.installationId,
        expected: { generation: current.generation, version, archiveSha256 },
        target,
    } satisfies CatalogLifecycleInput
    snapshot = {
        ...ready,
        entries: [ready.entries[0]!, { ...ready.entries[0]!, ...target, name: 'Greeting 1.1' }],
        installations: [{ ...current, name: 'Verified Greeting', update: target }],
        lifecycle: { ...update, status: 'failed', error: 'networkUnavailable' },
    }
    apps = []
    const { container, button, unmount } = await mountCatalog()
    try {
        await waitFor(() => button('Update to 1.1.0')?.disabled === false)
        expect(container.querySelector('h3')?.textContent).toBe('Verified Greeting')
        expect(container.textContent).toContain(
            'Neither the app catalog nor the package source could be reached.',
        )
        expect(container.textContent).toContain(
            'Version 1.1.0 is not stored on this appliance. Updating requires its package source.',
        )

        snapshot = {
            ...snapshot,
            entries: [ready.entries[0]!, { ...ready.entries[0]!, ...target, cached: true }],
            lifecycle: { ...update, status: 'failed', error: 'catalogUnavailable' },
        }
        await act(async () => button('Refresh catalog')!.click())
        await waitFor(
            () =>
                container.textContent?.includes(
                    'The signed app catalog could not be reached, so the version could not be verified.',
                ) === true,
        )
        expect(container.textContent).not.toContain('Updating requires its package source.')
    } finally {
        await unmount()
    }
})
