import { describe, expect, spyOn, test } from 'bun:test'
import {
    APP_CATALOG_INSTALL_PATH,
    APP_CATALOG_LIFECYCLE_PATH,
    catalogSnapshotSchema,
    type CatalogInstall,
    type CatalogLifecycle,
    type CatalogLifecycleInput,
    type CatalogSelector,
    type CatalogSnapshot,
} from '@/lib/AppCatalog/contract.ts'
import {
    createCatalogInstallHandler,
    createCatalogLifecycleHandler,
} from '@/server/AppRuntime/catalog/http.server.ts'
import {
    nativeAppCatalog,
    nativeCatalogInstall,
    nativeCatalogLifecycle,
    nativeCatalogTargetCheck,
} from '@/server/AppRuntime/catalog/transport.server.ts'
import { uiProblems } from '@/server/AppRuntime/ui/transport.server.ts'
import { AuthDomainError } from '@/server/Auth/Core/errors.server.ts'
import { RateLimitError } from '@/server/Valkey/rate-limiter.service.ts'

const origin = 'https://appliance.example.test'
const release = {
    appId: 'rentnerproxy.greeting',
    version: '1.0.0-beta.2',
    archiveSha256: 'f'.repeat(64),
} satisfies CatalogSelector
const pending = { ...release, status: 'installing' } satisfies CatalogInstall
const entry = {
    ...release,
    name: 'Greeting',
    summary: 'Say hello.',
    publisher: 'RentnerProxy',
    hasUi: true,
    providers: ['monitoring' as const],
    availability: 'available' as const,
}
const installation = {
    ...release,
    generation: 3,
    installationId: 'greeting-test',
    state: 'running' as const,
    providers: null,
    update: null,
    previous: null,
}

const { version, archiveSha256 } = release
const operation = {
    action: 'update',
    installationId: 'greeting-test',
    expected: { generation: 1, version, archiveSha256 },
    target: { version: '2.0.0', archiveSha256: 'a'.repeat(64) },
} satisfies CatalogLifecycleInput
const pendingOperation = { ...operation, status: 'pending' } satisfies CatalogLifecycle

function request(input: unknown, requestedOrigin = origin) {
    return new Request(origin + APP_CATALOG_INSTALL_PATH, {
        method: 'POST',
        headers: { Origin: requestedOrigin, 'Content-Type': 'application/json' },
        body: JSON.stringify(input),
    })
}

function handler(
    overrides: Partial<NonNullable<Parameters<typeof createCatalogInstallHandler>[0]>> = {},
) {
    const calls: string[] = []
    return {
        calls,
        handle: createCatalogInstallHandler({
            enabled: () => true,
            origin: () => origin,
            ownerId: () => {
                calls.push('owner')
                return Promise.resolve('owner-id')
            },
            limit: (id) => {
                calls.push(id)
                return Promise.resolve()
            },
            install: (input) => {
                calls.push('install')
                expect(input).toEqual(release)
                return Promise.resolve(pending)
            },
            ...overrides,
        }),
    }
}

describe('app catalog installation HTTP boundary', () => {
    test('rejects foreign origins before resolving the session or calling native code', async () => {
        const { calls, handle } = handler()
        expect((await handle(request(release, 'https://other.example.test'))).status).toBe(403)
        expect(calls).toEqual([])
    })

    test.each([
        ['authentication_required', 401],
        ['owner_required', 403],
    ] as const)('rejects %s before forwarding', async (code, status) => {
        const { calls, handle } = handler({
            ownerId: () => Promise.reject(new AuthDomainError(code, 'internal auth error')),
        })
        const response = await handle(request(release))
        expect(response.status).toBe(status)
        expect(await response.json()).toEqual({ error: 'forbidden' })
        expect(calls).toEqual([])
    })

    test('bounds the body and requires an exact, well-formed selector', async () => {
        const { calls, handle } = handler()
        expect((await handle(request({ ...release, extra: 'x'.repeat(1_024) }))).status).toBe(413)
        expect(
            (await handle(request({ ...release, packageUrl: 'https://other.test/app' }))).status,
        ).toBe(400)
        expect((await handle(request({ ...release, version: '1.0.0-01' }))).status).toBe(400)
        expect((await handle(request({ ...release, archiveSha256: 'f'.repeat(63) }))).status).toBe(
            400,
        )
        expect(calls).toEqual(['owner', 'owner', 'owner', 'owner'])
    })

    test('rate-limits owners and returns safe conflict codes without forwarding arbitrary data', async () => {
        const limited = handler({
            limit: () => Promise.reject(new RateLimitError(11, 10, 1_001, 'app-catalog-install')),
        })
        const limitedResponse = await limited.handle(request(release))
        expect(limitedResponse.status).toBe(429)
        expect(limitedResponse.headers.get('Retry-After')).toBe('2')
        expect(limited.calls).toEqual(['owner'])

        const conflict = handler({ install: () => Promise.reject(uiProblems.conflict) })
        const conflictResponse = await conflict.handle(request(release))
        expect(conflictResponse.status).toBe(409)
        expect(await conflictResponse.json()).toEqual({ error: 'conflict' })
        const unavailable = handler({ install: () => Promise.reject(new Error('private details')) })
        const unavailableResponse = await unavailable.handle(request(release))
        expect(unavailableResponse.status).toBe(503)
        expect(await unavailableResponse.json()).toEqual({ error: 'unavailable' })
    })

    test('rechecks owner access before admitting an installation', async () => {
        let owner = true
        const { calls, handle } = handler({
            ownerId: async () => {
                if (!owner) throw new AuthDomainError('owner_required', 'Role changed')
                return 'owner-id'
            },
            limit: async () => {
                owner = false
            },
        })
        expect((await handle(request(release))).status).toBe(403)
        expect(calls).toEqual([])
    })

    test('forwards exact release selection after authorization and responds with progress', async () => {
        const { calls, handle } = handler()
        const response = await handle(request(release))
        expect(response.status).toBe(202)
        expect(response.headers.get('Cache-Control')).toBe('private, no-store')
        expect(await response.json()).toEqual(pending)
        expect(calls).toEqual(['owner', 'owner-id', 'owner', 'install'])
    })
})

describe('native signed catalog wire contract', () => {
    test('validates release fields and installation state within the catalog limit', () => {
        const snapshot = {
            state: 'ready',
            entries: [entry],
            install: pending,
            installations: [],
            lifecycle: null,
        }
        expect(catalogSnapshotSchema.safeParse(snapshot).success).toBe(true)
        expect(
            catalogSnapshotSchema.safeParse({
                ...snapshot,
                entries: [{ ...entry, name: '🌿'.repeat(80) }],
            }).success,
        ).toBe(true)
        expect(
            catalogSnapshotSchema.safeParse({
                ...snapshot,
                entries: [{ ...entry, name: '🌿'.repeat(81) }],
            }).success,
        ).toBe(false)
        expect(
            catalogSnapshotSchema.safeParse({
                ...snapshot,
                entries: Array.from({ length: 4_097 }, () => ({ ...entry })),
            }).success,
        ).toBe(false)
        expect(
            catalogSnapshotSchema.safeParse({
                ...snapshot,
                install: { ...release, status: 'installed' },
            }).success,
        ).toBe(false)
        const failedOperation = { ...operation, status: 'failed', error: 'dependencyBlocked' }
        expect(
            catalogSnapshotSchema.safeParse({
                ...snapshot,
                installations: [installation],
                lifecycle: failedOperation,
            }).success,
        ).toBe(true)
        expect(
            catalogSnapshotSchema.safeParse({
                ...snapshot,
                lifecycle: { ...failedOperation, error: 'dependency' },
            }).success,
        ).toBe(false)
    })

    test('carries signed provider profiles for listed releases and installations', () => {
        const snapshot = {
            state: 'stale',
            entries: [entry],
            install: null,
            installations: [installation, { ...installation, providers: ['dns', 'oidc'] }],
            lifecycle: null,
        }
        expect(catalogSnapshotSchema.safeParse(snapshot).success).toBe(true)
        for (const providers of [undefined, ['monitoring', 'monitoring'], ['unknown']]) {
            const { providers: _, ...withoutProviders } = entry
            const changed = providers ? { ...entry, providers } : withoutProviders
            expect(
                catalogSnapshotSchema.safeParse({ ...snapshot, entries: [changed] }).success,
            ).toBe(false)
        }
        const { providers: _, ...unlisted } = installation
        expect(
            catalogSnapshotSchema.safeParse({ ...snapshot, installations: [unlisted] }).success,
        ).toBe(false)
    })

    test('checks installations against a verified target environment over the app UI socket', async () => {
        const signal = AbortSignal.timeout(1_000)
        const environment = {
            runtimeProfile: 'rentnerproxy-linux-v1',
            platformApi: '1.1.0',
            appProtocol: '1.0.0',
            uiBridge: null,
            engineCapabilities: ['caddy.crowdsec.v1'],
        }
        const checked = {
            installationId: 'greeting-test',
            appId: release.appId,
            version: release.version,
            archiveSha256: release.archiveSha256,
            state: 'disabled' as const,
            providers: ['monitoring' as const],
            target: 'incompatible' as const,
        }
        const replies = spyOn(globalThis, 'fetch')
            .mockResolvedValueOnce(Response.json({ installations: [checked] }))
            .mockResolvedValueOnce(
                Response.json({ installations: [{ ...checked, state: 'removed' }] }),
            )
            .mockResolvedValueOnce(Response.json({ installations: [checked, checked] }))
        try {
            await expect(nativeCatalogTargetCheck(environment, signal)).resolves.toEqual({
                installations: [checked],
            })
            await expect(nativeCatalogTargetCheck(environment, signal)).rejects.toBe(
                uiProblems.unavailable,
            )
            await expect(nativeCatalogTargetCheck(environment, signal)).rejects.toBe(
                uiProblems.unavailable,
            )
            expect(replies).toHaveBeenNthCalledWith(
                1,
                'http://localhost/v1/catalog/target-check',
                expect.objectContaining({
                    unix: '/run/rentnerproxy/app-ui/web.sock',
                    method: 'POST',
                    body: JSON.stringify(environment),
                }),
            )
        } finally {
            replies.mockRestore()
        }
    })

    test('uses the existing app UI socket and rejects a mismatched install acknowledgment', async () => {
        const signal = AbortSignal.timeout(1_000)
        const snapshot = {
            state: 'ready',
            entries: [entry],
            install: null,
            installations: [],
            lifecycle: null,
        } satisfies CatalogSnapshot
        const replies = spyOn(globalThis, 'fetch')
            .mockResolvedValueOnce(Response.json(snapshot))
            .mockResolvedValueOnce(Response.json(pending, { status: 202 }))
            .mockResolvedValueOnce(Response.json({ ...pending, archiveSha256: 'e'.repeat(64) }))
        try {
            await expect(nativeAppCatalog(signal)).resolves.toEqual(snapshot)
            await expect(nativeCatalogInstall(release, signal)).resolves.toEqual(pending)
            await expect(nativeCatalogInstall(release, signal)).rejects.toBe(uiProblems.unavailable)
            expect(replies).toHaveBeenNthCalledWith(
                1,
                'http://localhost/v1/catalog',
                expect.objectContaining({
                    unix: '/run/rentnerproxy/app-ui/web.sock',
                    redirect: 'error',
                }),
            )
            expect(replies).toHaveBeenNthCalledWith(
                2,
                'http://localhost/v1/catalog/install',
                expect.objectContaining({ method: 'POST', body: JSON.stringify(release) }),
            )
        } finally {
            replies.mockRestore()
        }
    })

    test('requires a matching pending native lifecycle acknowledgment', async () => {
        const signal = AbortSignal.timeout(1_000)
        const replies = spyOn(globalThis, 'fetch')
            .mockResolvedValueOnce(Response.json(pendingOperation, { status: 202 }))
            .mockResolvedValueOnce(
                Response.json({
                    ...pendingOperation,
                    target: { ...operation.target, version: '2.1.0' },
                }),
            )
            .mockResolvedValueOnce(Response.json({ ...pendingOperation, status: 'succeeded' }))
        try {
            await expect(nativeCatalogLifecycle(operation, signal)).resolves.toEqual(
                pendingOperation,
            )
            await expect(nativeCatalogLifecycle(operation, signal)).rejects.toBe(
                uiProblems.unavailable,
            )
            await expect(nativeCatalogLifecycle(operation, signal)).rejects.toBe(
                uiProblems.unavailable,
            )
            expect(replies).toHaveBeenNthCalledWith(
                1,
                'http://localhost/v1/catalog/lifecycle',
                expect.objectContaining({ method: 'POST', body: JSON.stringify(operation) }),
            )
        } finally {
            replies.mockRestore()
        }
    })
})

test('guards lifecycle mutations with the existing owner and same-origin boundary', async () => {
    const lifecycle = spyOn({ submit: nativeCatalogLifecycle }, 'submit').mockResolvedValue(
        pendingOperation,
    )
    const ownerId = spyOn(
        {
            async get() {
                return 'owner-id'
            },
        },
        'get',
    )
    const handle = createCatalogLifecycleHandler({
        enabled: () => true,
        origin: () => origin,
        ownerId,
        limit: async () => {},
        lifecycle,
    })
    const post = (input: unknown, requestedOrigin = origin) =>
        handle(
            new Request(origin + APP_CATALOG_LIFECYCLE_PATH, {
                method: 'POST',
                headers: { Origin: requestedOrigin, 'Content-Type': 'application/json' },
                body: JSON.stringify(input),
            }),
        )

    expect((await post(operation, 'https://other.example.test')).status).toBe(403)
    expect(ownerId).toHaveBeenCalledTimes(0)
    expect((await post({ ...operation, target: undefined })).status).toBe(400)
    expect((await post({ ...operation, action: 'uninstall', purge: true })).status).toBe(400)
    expect(
        (await post({ ...operation, expected: { ...operation.expected, generation: 0 } })).status,
    ).toBe(400)
    expect(lifecycle).toHaveBeenCalledTimes(0)

    ownerId.mockRejectedValueOnce(new AuthDomainError('owner_required', 'Role changed'))
    expect((await post(operation)).status).toBe(403)
    const response = await post(operation)
    expect(response.status).toBe(202)
    expect(response.headers.get('Cache-Control')).toBe('private, no-store')
    expect(await response.json()).toEqual(pendingOperation)
    expect(lifecycle).toHaveBeenCalledWith(operation, expect.any(AbortSignal))
})
