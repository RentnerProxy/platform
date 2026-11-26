import { describe, expect, mock, spyOn, test } from 'bun:test'
import {
    APP_CATALOG_INSTALL_RATE_LIMIT,
    APP_CATALOG_REVOKE_RATE_LIMIT,
} from '@/config/app-catalog.config.ts'
import { auditEventInputSchema } from '@/features/Admin/AuditLogs/validation.ts'
import {
    APP_CATALOG_INSTALL_PATH,
    APP_CATALOG_LIFECYCLE_PATH,
    APP_CATALOG_MAX_GRANTS,
    catalogLifecycleInputSchema,
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
    grants: [
        {
            capability: { id: 'app.provider.register', scope: 'providerProfiles' },
            resourceId: 'monitoring',
            allowService: true,
        },
        { capability: { id: 'proxy.hosts.read.v1', scope: 'proxyHosts' }, allowService: true },
    ],
    permissionKeys: ['view'],
    availability: 'available' as const,
    cached: false,
}
const installation = {
    ...release,
    generation: 3,
    installationId: 'greeting-test',
    state: 'running' as const,
    name: 'Greeting',
    providers: null,
    grants: null,
    update: null,
    updateRequiresApproval: false,
    previous: null,
}
const host = '0b6f3c0e-8d1a-4f43-9c2e-1d7a5b9e4f21'
const approval = [
    {
        capability: { id: 'app.provider.register', scope: 'providerProfiles' },
        resourceId: 'monitoring',
        allowService: true,
    },
    {
        capability: { id: 'proxy.hosts.read.v1', scope: 'proxyHosts' },
        resourceId: host,
        allowService: false,
        permissionKey: 'view',
    },
]

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
        expect((await handle(request({ ...release, extra: 'x'.repeat(64 * 1_024) }))).status).toBe(
            413,
        )
        expect((await handle(request({ ...release, extra: 'x'.repeat(1_024) }))).status).toBe(400)
        expect(
            (await handle(request({ ...release, packageUrl: 'https://other.test/app' }))).status,
        ).toBe(400)
        expect((await handle(request({ ...release, version: '1.0.0-01' }))).status).toBe(400)
        expect((await handle(request({ ...release, archiveSha256: 'f'.repeat(63) }))).status).toBe(
            400,
        )
        expect(calls).toEqual(['owner', 'owner', 'owner', 'owner', 'owner'])
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

    test('forwards an approval within 64 KiB and audits the accepted decision', async () => {
        const audited: unknown[] = []
        const install = mock((input: unknown) => {
            expect(input).toEqual({ ...release, approval })
            return Promise.resolve(pending)
        })
        const { calls, handle } = handler({
            install,
            audit: async (event) => {
                audited.push(event)
            },
        })
        const response = await handle(request({ ...release, approval }))
        expect(response.status).toBe(202)
        // The receipt never repeats the approval.
        expect(await response.json()).toEqual(pending)
        expect(calls).toEqual(['owner', 'owner-id', 'owner'])
        expect(audited).toEqual([
            {
                actorUserId: 'owner-id',
                actorKind: 'user',
                action: 'accept',
                resource: 'app-grants',
                targetId: null,
                result: 'success',
                metadata: { count: 2, appId: release.appId },
            },
        ])
        // The audit allowlist accepts the decision for an Owner's user ID.
        expect(
            auditEventInputSchema.safeParse({
                ...(audited[0] as object),
                actorUserId: crypto.randomUUID(),
            }).success,
        ).toBe(true)
        // The largest approval fits, a larger body does not.
        const largest = Array.from({ length: APP_CATALOG_MAX_GRANTS }, (_, index) => ({
            ...approval[1],
            resourceId: `${'a'.repeat(28)}${String(index).padStart(8, '0')}`,
        }))
        install.mockImplementation(() => Promise.resolve(pending))
        expect((await handle(request({ ...release, approval: largest }))).status).toBe(202)
        const tooMany = [...largest, approval[0]]
        expect((await handle(request({ ...release, approval: tooMany }))).status).toBe(400)
        expect(
            (await handle(request({ ...release, approval, padding: 'x'.repeat(64 * 1_024) })))
                .status,
        ).toBe(413)
    })

    test('refuses malformed approvals before calling native code and maps refusals to 422', async () => {
        const { calls, handle } = handler()
        const malformed = [
            [{ ...approval[0], resourceId: 'Monitoring' }],
            [{ ...approval[0], capability: { id: 'app.provider.register' } }],
            [{ ...approval[0], extra: true }],
            [{ ...approval[1], permissionKey: 'View' }],
            { ...approval[0] },
        ]
        const statuses = await Promise.all(
            malformed.map(
                async (value) => (await handle(request({ ...release, approval: value }))).status,
            ),
        )
        expect(statuses).toEqual([400, 400, 400, 400, 400])
        expect(calls).toEqual(['owner', 'owner', 'owner', 'owner', 'owner'])
        const refused = handler({ install: () => Promise.reject(uiProblems.approvalRequired) })
        const response = await refused.handle(request({ ...release, approval }))
        expect(response.status).toBe(422)
        expect(await response.json()).toEqual({ error: 'approvalRequired' })
    })

    test('rejects admins and viewers with an approval before any native call', async () => {
        const audit = mock(async () => {})
        const { calls, handle } = handler({
            ownerId: () => Promise.reject(new AuthDomainError('owner_required', 'Admin')),
            audit,
        })
        const response = await handle(request({ ...release, approval }))
        expect(response.status).toBe(403)
        expect(calls).toEqual([])
        expect(audit).not.toHaveBeenCalled()
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

    test('carries requested grants, approved grants and whether an update needs approval', () => {
        const approved = {
            ...installation,
            grants: [
                {
                    capability: { id: 'app.audit.record', scope: 'installation' },
                    resourceId: installation.installationId,
                    allowService: true,
                },
                { ...approval[1] },
            ],
            update: { version: '2.0.0', archiveSha256: 'a'.repeat(64) },
            updateRequiresApproval: true,
        }
        const snapshot = {
            state: 'ready',
            entries: [entry, { ...entry, version: '1.0.0', grants: [], permissionKeys: [] }],
            install: { ...release, status: 'failed', error: 'approvalRequired' },
            installations: [installation, approved],
            lifecycle: { ...operation, status: 'failed', error: 'approvalRequired' },
        }
        expect(catalogSnapshotSchema.safeParse(snapshot).success).toBe(true)
        const { grants: _, ...withoutGrants } = entry
        const { permissionKeys: __, ...withoutKeys } = entry
        const { updateRequiresApproval: ___, ...withoutFlag } = installation
        for (const invalid of [
            { ...snapshot, entries: [withoutGrants] },
            { ...snapshot, entries: [withoutKeys] },
            { ...snapshot, installations: [withoutFlag] },
            { ...snapshot, entries: [{ ...entry, grants: [{ ...entry.grants[0], extra: 1 }] }] },
            {
                ...snapshot,
                installations: [
                    { ...approved, grants: [{ ...approved.grants[0], resourceId: undefined }] },
                ],
            },
            {
                ...snapshot,
                installations: [
                    {
                        ...installation,
                        grants: Array.from({ length: 129 }, () => approved.grants[0]),
                    },
                ],
            },
        ]) {
            expect(catalogSnapshotSchema.safeParse(invalid).success).toBe(false)
        }
    })

    test('accepts revocations and approvals only on their actions', () => {
        const revoke = {
            action: 'revoke',
            installationId: 'greeting-test',
            expected: operation.expected,
            grants: [{ capability: approval[1]!.capability, resourceId: host }],
        }
        expect(catalogLifecycleInputSchema.safeParse(revoke).success).toBe(true)
        expect(catalogLifecycleInputSchema.safeParse({ ...operation, approval }).success).toBe(true)
        for (const invalid of [
            { ...revoke, grants: [] },
            { ...revoke, grants: undefined },
            { ...revoke, grants: [revoke.grants[0], revoke.grants[0]] },
            { ...revoke, target: operation.target },
            { ...revoke, approval },
            { ...operation, grants: revoke.grants },
            { ...operation, action: 'rollback', approval },
            { ...operation, action: 'deactivate', target: undefined, approval },
        ]) {
            expect(catalogLifecycleInputSchema.safeParse(invalid).success).toBe(false)
        }
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

    test('carries the local package state, verified names and source outages', () => {
        const snapshot = {
            state: 'ready',
            entries: [entry, { ...entry, version: '1.0.0', cached: true }],
            install: null,
            installations: [installation, { ...installation, name: null }],
            lifecycle: null,
        }
        expect(catalogSnapshotSchema.safeParse(snapshot).success).toBe(true)
        const { cached: _, ...withoutCache } = entry
        const { name: __, ...withoutName } = installation
        for (const invalid of [
            { ...snapshot, entries: [withoutCache] },
            { ...snapshot, installations: [withoutName] },
            { ...snapshot, installations: [{ ...installation, name: 'x'.repeat(81) }] },
        ]) {
            expect(catalogSnapshotSchema.safeParse(invalid).success).toBe(false)
        }
        for (const error of [
            'catalogUnavailable',
            'packageSourceUnavailable',
            'networkUnavailable',
        ]) {
            expect(
                catalogSnapshotSchema.safeParse({
                    ...snapshot,
                    install: { ...release, status: 'failed', error },
                    lifecycle: { ...operation, status: 'failed', error },
                }).success,
            ).toBe(true)
        }
        expect(
            catalogSnapshotSchema.safeParse({
                ...snapshot,
                install: { ...release, status: 'failed', error: 'sourceUnavailable' },
            }).success,
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

test('forwards revocations and approved updates to the core and audits the Owner decision', async () => {
    const revoke = {
        action: 'revoke',
        installationId: 'greeting-test',
        expected: operation.expected,
        grants: [{ capability: approval[1]!.capability, resourceId: host }],
    } satisfies CatalogLifecycleInput
    const { grants: _, ...receipt } = revoke
    const lifecycle = mock((input: CatalogLifecycleInput) =>
        Promise.resolve(
            input.action === 'revoke'
                ? { ...receipt, status: 'pending' as const }
                : pendingOperation,
        ),
    )
    const audited: unknown[] = []
    let owner = true
    const handle = createCatalogLifecycleHandler({
        enabled: () => true,
        origin: () => origin,
        ownerId: async () => {
            if (!owner) throw new AuthDomainError('owner_required', 'Viewer')
            return 'owner-id'
        },
        limit: async () => {},
        lifecycle,
        audit: async (event) => {
            audited.push(event)
        },
    })
    const post = (input: unknown) =>
        handle(
            new Request(origin + APP_CATALOG_LIFECYCLE_PATH, {
                method: 'POST',
                headers: { Origin: origin, 'Content-Type': 'application/json' },
                body: JSON.stringify(input),
            }),
        )

    owner = false
    expect((await post(revoke)).status).toBe(403)
    expect((await post({ ...operation, approval })).status).toBe(403)
    expect(lifecycle).not.toHaveBeenCalled()
    owner = true
    const revoked = await post(revoke)
    expect(revoked.status).toBe(202)
    expect(await revoked.json()).toEqual({ ...receipt, status: 'pending' })
    expect(lifecycle).toHaveBeenLastCalledWith(revoke, expect.any(AbortSignal))
    expect((await post({ ...operation, approval })).status).toBe(202)
    expect(lifecycle).toHaveBeenLastCalledWith({ ...operation, approval }, expect.any(AbortSignal))
    expect(audited).toEqual([
        expect.objectContaining({
            action: 'delete',
            resource: 'app-grants',
            metadata: { count: 1, installationId: 'greeting-test' },
        }),
        expect.objectContaining({
            action: 'accept',
            resource: 'app-grants',
            metadata: { count: 2, installationId: 'greeting-test' },
        }),
    ])
    // A plain lifecycle action records no grant decision.
    expect((await post(operation)).status).toBe(202)
    expect(audited).toHaveLength(2)
    lifecycle.mockImplementationOnce(() => Promise.reject(uiProblems.approvalRequired))
    const refused = await post(operation)
    expect(refused.status).toBe(422)
    expect(await refused.json()).toEqual({ error: 'approvalRequired' })
})

test('maps a native approval refusal and accepts receipts that never repeat the approval', async () => {
    const signal = AbortSignal.timeout(1_000)
    const replies = spyOn(globalThis, 'fetch')
        .mockResolvedValueOnce(Response.json({ error: 'approvalRequired' }, { status: 422 }))
        .mockResolvedValueOnce(Response.json(pendingOperation, { status: 202 }))
        .mockResolvedValueOnce(Response.json({}, { status: 422 }))
    try {
        await expect(nativeCatalogLifecycle({ ...operation, approval }, signal)).rejects.toBe(
            uiProblems.approvalRequired,
        )
        await expect(nativeCatalogLifecycle({ ...operation, approval }, signal)).resolves.toEqual(
            pendingOperation,
        )
        expect(replies).toHaveBeenNthCalledWith(
            2,
            'http://localhost/v1/catalog/lifecycle',
            expect.objectContaining({ body: JSON.stringify({ ...operation, approval }) }),
        )
        await expect(nativeCatalogInstall({ ...release, approval }, signal)).rejects.toBe(
            uiProblems.approvalRequired,
        )
    } finally {
        replies.mockRestore()
    }
})

test('limits revocations in their own bucket so installs and updates never hold them back', async () => {
    const revoke = {
        action: 'revoke',
        installationId: 'greeting-test',
        expected: operation.expected,
        grants: [{ capability: approval[1]!.capability, resourceId: host }],
    } satisfies CatalogLifecycleInput
    const { grants: _, ...receipt } = revoke
    const used = new Map<string, number>()
    const scopes: string[] = []
    const handle = createCatalogLifecycleHandler({
        enabled: () => true,
        origin: () => origin,
        ownerId: async () => 'owner-id',
        limit: async (identifier, policy = APP_CATALOG_INSTALL_RATE_LIMIT) => {
            expect(identifier).toBe('owner-id')
            scopes.push(policy.scope)
            const count = (used.get(policy.scope) ?? 0) + 1
            used.set(policy.scope, count)
            if (count > policy.limit)
                throw new RateLimitError(count, policy.limit, policy.windowMs, policy.scope)
        },
        lifecycle: async (input) =>
            input.action === 'revoke' ? { ...receipt, status: 'pending' } : pendingOperation,
        audit: async () => {},
    })
    const post = (input: unknown) =>
        handle(
            new Request(origin + APP_CATALOG_LIFECYCLE_PATH, {
                method: 'POST',
                headers: { Origin: origin, 'Content-Type': 'application/json' },
                body: JSON.stringify(input),
            }),
        )
    const { limit } = APP_CATALOG_INSTALL_RATE_LIMIT
    const updates = await Promise.all(
        Array.from({ length: limit }, async () => (await post(operation)).status),
    )
    expect(updates).toEqual(Array.from({ length: limit }, () => 202))
    expect((await post(operation)).status).toBe(429)
    // The install and update bucket is exhausted; a revocation is still admitted.
    expect((await post(revoke)).status).toBe(202)
    expect(scopes.at(-1)).toBe(APP_CATALOG_REVOKE_RATE_LIMIT.scope)
    expect(scopes.filter((scope) => scope === APP_CATALOG_INSTALL_RATE_LIMIT.scope)).toHaveLength(
        limit + 1,
    )
    expect(APP_CATALOG_REVOKE_RATE_LIMIT.scope).not.toBe(APP_CATALOG_INSTALL_RATE_LIMIT.scope)
})
