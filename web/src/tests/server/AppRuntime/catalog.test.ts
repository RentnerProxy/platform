import { describe, expect, spyOn, test } from 'bun:test'
import {
    APP_CATALOG_INSTALL_PATH,
    catalogSnapshotSchema,
    type CatalogInstall,
    type CatalogSelector,
    type CatalogSnapshot,
} from '@/lib/AppCatalog/contract.ts'
import { createCatalogInstallHandler } from '@/server/AppRuntime/catalog/http.server.ts'
import {
    nativeAppCatalog,
    nativeCatalogInstall,
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
    availability: 'available' as const,
}

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
        const snapshot = { state: 'ready', entries: [entry], install: pending }
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
    })

    test('uses the existing app UI socket and rejects a mismatched install acknowledgment', async () => {
        const signal = AbortSignal.timeout(1_000)
        const snapshot = {
            state: 'ready',
            entries: [entry],
            install: null,
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
})
