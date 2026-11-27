import { afterEach, beforeEach, describe, expect, test } from 'bun:test'

import { PERMISSIONS } from '@/config/permissions.config.ts'
import {
    APP_RUNTIME_SUPPORT_CAPABILITIES,
    isAppRuntimeAuthorized,
    isAppRuntimeGrantTarget,
    isAppRuntimeSupportCapability,
    qualifyAppRuntimePermission,
    requireAppRuntimePermission,
} from '@/server/AppRuntime/authority-policy.server.ts'
import {
    appProviderProfiles,
    appProviderProfilesSchema,
    appProviderRegistrationsSchema,
} from '@/server/AppRuntime/contract.ts'
import {
    appRuntimeEventCursorContext,
    createAppRuntimeEventCursor,
    readAppRuntimeEventCursor,
} from '@/server/AppRuntime/events.server.ts'
import type {
    AppRuntimeGrant,
    AppRuntimePrincipal,
} from '@/server/AppRuntime/Types/authority.types.ts'

const readCapability = { id: 'proxy.hosts.read.v1', scope: 'proxyHosts' } as const
const ownedCapability = { id: 'proxy.hosts.manage-owned.v1', scope: 'ownedProxyHosts' } as const
/** A grant for all proxy hosts, or one that wrongly names a single host. */
function allHosts(id: string, resourceId = 'all'): AppRuntimeGrant {
    return { capability: { id, scope: 'allProxyHosts' }, resourceId, allowService: true }
}
const appId = 'test.integration'
const installationId = 'instance-a'
const servicePrincipal: AppRuntimePrincipal = {
    kind: 'service',
    identity: { appId, installationId, generation: 1, uid: 21_001 },
    expiresAt: new Date(Date.now() + 60_000),
    authorizationEpoch: 4n,
    grants: [
        {
            capability: readCapability,
            resourceId: 'host-a',
            allowService: true,
        },
    ],
    permissions: [],
    appPermissions: [],
    delegationId: null,
    sessionId: null,
    user: null,
}
const userPrincipal: AppRuntimePrincipal = {
    ...servicePrincipal,
    kind: 'user',
    delegationId: 'delegation-a',
    sessionId: 'session-a',
    permissions: [PERMISSIONS.APP_ACCESS, PERMISSIONS.PROXY_HOSTS_VIEW],
    user: {
        id: 'user-a',
        displayName: 'App User',
        email: 'user@example.invalid',
        profileImageVersion: null,
        roles: ['operator'],
        permissions: [PERMISSIONS.APP_ACCESS, PERMISSIONS.PROXY_HOSTS_VIEW],
        language: 'en',
        themeMode: 'light',
    },
}

describe('app runtime authorization', () => {
    test('requires the exact capability scope and resource and explicit autonomous permission', () => {
        expect(isAppRuntimeAuthorized(servicePrincipal, readCapability, 'host-a')).toBe(true)
        expect(isAppRuntimeAuthorized(servicePrincipal, readCapability, 'host-b')).toBe(false)
        expect(
            isAppRuntimeAuthorized(
                servicePrincipal,
                { ...readCapability, scope: 'installation' },
                'host-a',
            ),
        ).toBe(false)

        const delegatedOnly = { ...userPrincipal.grants[0]!, allowService: false }
        expect(
            isAppRuntimeAuthorized(
                { ...servicePrincipal, grants: [delegatedOnly] },
                readCapability,
                'host-a',
            ),
        ).toBe(false)
        expect(
            isAppRuntimeAuthorized(
                { ...userPrincipal, grants: [delegatedOnly] },
                readCapability,
                'host-a',
            ),
        ).toBe(true)
        expect(
            isAppRuntimeAuthorized(
                { ...userPrincipal, permissions: [PERMISSIONS.APP_ACCESS] },
                readCapability,
                'host-a',
            ),
        ).toBe(false)
        expect(
            isAppRuntimeAuthorized(
                { ...userPrincipal, expiresAt: new Date(0) },
                readCapability,
                'host-a',
            ),
        ).toBe(false)
    })

    test('rechecks action-specific Platform permissions for managed hosts', () => {
        const grant: AppRuntimeGrant = {
            capability: ownedCapability,
            resourceId: 'host-a',
            allowService: false,
        }
        const principal = {
            ...userPrincipal,
            grants: [grant],
            permissions: [...userPrincipal.permissions, PERMISSIONS.PROXY_HOSTS_UPDATE],
        }
        expect(
            isAppRuntimeAuthorized(principal, ownedCapability, 'host-a', [
                PERMISSIONS.PROXY_HOSTS_UPDATE,
            ]),
        ).toBe(true)
        expect(
            isAppRuntimeAuthorized(principal, ownedCapability, 'host-a', [
                PERMISSIONS.PROXY_HOSTS_DELETE,
            ]),
        ).toBe(false)
    })

    test('matches installed app permission namespace and role key before allowing delegated secret access', () => {
        const secret = APP_RUNTIME_SUPPORT_CAPABILITIES.secret
        const grant: AppRuntimeGrant = {
            capability: secret,
            resourceId: 'credential-a',
            allowService: true,
            permissionKey: 'use-secret',
        }
        const principal = { ...userPrincipal, grants: [grant] }
        expect(isAppRuntimeAuthorized(principal, secret, 'credential-a')).toBe(false)
        expect(
            isAppRuntimeAuthorized(
                {
                    ...principal,
                    appPermissions: [
                        qualifyAppRuntimePermission('other.integration', 'use-secret'),
                    ],
                },
                secret,
                'credential-a',
            ),
        ).toBe(false)

        const authorized = {
            ...principal,
            appPermissions: [qualifyAppRuntimePermission(appId, 'use-secret')],
        }
        expect(isAppRuntimeAuthorized(authorized, secret, 'credential-a')).toBe(true)
        expect(() => requireAppRuntimePermission(authorized, 'use-secret')).not.toThrow()
        expect(() => requireAppRuntimePermission(servicePrincipal, 'use-secret')).toThrow()
        expect(
            isAppRuntimeAuthorized(
                { ...servicePrincipal, grants: [grant] },
                secret,
                'credential-a',
            ),
        ).toBe(true)
    })

    test('a grant for all proxy hosts covers every host only for reading and probing', () => {
        const probe = { id: 'diagnostics.upstream.probe.v1', scope: 'proxyHosts' } as const
        const host = '2f9c4b1e-6a3d-4e8f-9b7c-0d1e2f3a4b5c'
        const reading = { ...servicePrincipal, grants: [allHosts(readCapability.id)] }
        // Hosts created after the approval are covered, under any ID the app sees.
        expect(isAppRuntimeAuthorized(reading, readCapability, host)).toBe(true)
        expect(isAppRuntimeAuthorized(reading, readCapability, 'owned-host')).toBe(true)
        expect(isAppRuntimeAuthorized(reading, probe, host)).toBe(false)
        expect(
            isAppRuntimeAuthorized(
                { ...servicePrincipal, grants: [allHosts(probe.id)] },
                probe,
                host,
            ),
        ).toBe(true)
        // Managing hosts and every other capability stay per resource.
        const managing = { ...servicePrincipal, grants: [allHosts(ownedCapability.id)] }
        expect(isAppRuntimeAuthorized(managing, ownedCapability, 'owned-host')).toBe(false)
        for (const grant of [
            allHosts(ownedCapability.id),
            allHosts('access.logs.read.v1'),
            allHosts(readCapability.id, host),
        ])
            expect(
                isAppRuntimeGrantTarget(grant.capability, grant.resourceId, installationId),
            ).toBe(false)
        expect(
            isAppRuntimeGrantTarget(allHosts(readCapability.id).capability, 'all', installationId),
        ).toBe(true)
        // On behalf of a user, the grant needs the user's permission to view proxy hosts.
        const user = { ...userPrincipal, grants: [allHosts(readCapability.id)] }
        expect(isAppRuntimeAuthorized(user, readCapability, host)).toBe(true)
        expect(
            isAppRuntimeAuthorized(
                { ...user, permissions: [PERMISSIONS.APP_ACCESS] },
                readCapability,
                host,
            ),
        ).toBe(false)
        expect(
            isAppRuntimeAuthorized(
                {
                    ...servicePrincipal,
                    grants: [{ ...allHosts(readCapability.id), allowService: false }],
                },
                readCapability,
                host,
            ),
        ).toBe(false)
    })
})

describe('app runtime cursor authority', () => {
    const originalEncryptionKey = process.env.APP_ENCRYPTION_KEY

    beforeEach(() => {
        process.env.APP_ENCRYPTION_KEY = Buffer.alloc(32, 113).toString('base64')
    })

    afterEach(() => {
        if (originalEncryptionKey === undefined) delete process.env.APP_ENCRYPTION_KEY
        else process.env.APP_ENCRYPTION_KEY = originalEncryptionKey
    })

    test('authenticates sequence, generation, delegation, and effective authorization with bounded lifetime', async () => {
        const now = Date.now()
        const context = appRuntimeEventCursorContext(userPrincipal)
        const cursor = await createAppRuntimeEventCursor(451n, now + 500, context)
        expect(cursor).toMatch(/^[a-zA-Z0-9_-]{1,256}$/)
        await expect(readAppRuntimeEventCursor(cursor, now, context)).resolves.toBe(451n)
        await expect(readAppRuntimeEventCursor(cursor, now + 500, context)).rejects.toMatchObject({
            code: 'cursor_expired',
        })
        const tampered = Buffer.from(cursor, 'base64url')
        tampered[10] = (tampered[10] ?? 0) ^ 1
        await expect(
            readAppRuntimeEventCursor(tampered.toString('base64url'), now, context),
        ).rejects.toMatchObject({ code: 'cursor_expired' })

        const invalidContexts = [
            { ...userPrincipal, identity: { ...userPrincipal.identity, generation: 2 } },
            {
                ...userPrincipal,
                identity: { ...userPrincipal.identity, installationId: 'instance-b' },
            },
            { ...userPrincipal, delegationId: 'delegation-b' },
            { ...userPrincipal, authorizationEpoch: 5n },
            { ...userPrincipal, permissions: [PERMISSIONS.APP_ACCESS] },
            {
                ...userPrincipal,
                appPermissions: [qualifyAppRuntimePermission(appId, 'new-role-permission')],
            },
            servicePrincipal,
        ]
        await Promise.all(
            invalidContexts.map(async (principal) =>
                expect(
                    readAppRuntimeEventCursor(cursor, now, appRuntimeEventCursorContext(principal)),
                ).rejects.toMatchObject({ code: 'cursor_expired' }),
            ),
        )
    })
})

describe('app provider registrations', () => {
    const provider = APP_RUNTIME_SUPPORT_CAPABILITIES.provider
    const registration = { id: 'dns-main', profile: 'dns', version: '1.0.0' }

    test('accepts only v1 profile lists without duplicates', () => {
        expect(appProviderProfilesSchema.safeParse([]).success).toBe(true)
        expect(appProviderProfilesSchema.safeParse([...appProviderProfiles]).success).toBe(true)
        expect(appProviderProfilesSchema.safeParse(['dns', 'dns']).success).toBe(false)
        expect(appProviderProfilesSchema.safeParse(['unknown']).success).toBe(false)
        expect(appProviderProfilesSchema.safeParse([...appProviderProfiles, 'dns']).success).toBe(
            false,
        )
    })

    test('validates strict registrations with bounded unique ids', () => {
        expect(appProviderRegistrationsSchema.safeParse([registration]).success).toBe(true)
        const sameProfile = { ...registration, id: 'dns-two' }
        expect(appProviderRegistrationsSchema.safeParse([registration, sameProfile]).success).toBe(
            true,
        )
        const invalid: unknown[] = [
            [],
            [registration, registration],
            [{ ...registration, version: '1.0.1' }],
            [{ ...registration, profile: 'unknown' }],
            [{ ...registration, id: 'Not Valid' }],
            [{ ...registration, extra: true }],
            Array.from({ length: 33 }, (_, index) => ({ ...registration, id: 'p' + index })),
        ]
        for (const value of invalid)
            expect(appProviderRegistrationsSchema.safeParse(value).success).toBe(false)
        expect(
            appProviderRegistrationsSchema.safeParse(
                Array.from({ length: 32 }, (_, index) => ({ ...registration, id: 'p' + index })),
            ).success,
        ).toBe(true)
    })

    test('grants target only declared v1 profiles and require an explicit service or APP_ACCESS grant', () => {
        for (const profile of appProviderProfiles)
            expect(isAppRuntimeGrantTarget(provider, profile, installationId)).toBe(true)
        expect(isAppRuntimeGrantTarget(provider, 'unknown', installationId)).toBe(false)
        expect(isAppRuntimeGrantTarget(provider, installationId, installationId)).toBe(false)
        expect(isAppRuntimeSupportCapability(provider)).toBe(true)

        const allowed: AppRuntimeGrant = {
            capability: provider,
            resourceId: 'dns',
            allowService: true,
        }
        const delegated = { ...allowed, allowService: false }
        expect(
            isAppRuntimeAuthorized({ ...servicePrincipal, grants: [allowed] }, provider, 'dns'),
        ).toBe(true)
        expect(
            isAppRuntimeAuthorized({ ...servicePrincipal, grants: [allowed] }, provider, 'oidc'),
        ).toBe(false)
        expect(
            isAppRuntimeAuthorized({ ...servicePrincipal, grants: [delegated] }, provider, 'dns'),
        ).toBe(false)
        expect(
            isAppRuntimeAuthorized({ ...userPrincipal, grants: [delegated] }, provider, 'dns'),
        ).toBe(true)
        expect(
            isAppRuntimeAuthorized(
                {
                    ...userPrincipal,
                    grants: [delegated],
                    permissions: [PERMISSIONS.PROXY_HOSTS_VIEW],
                },
                provider,
                'dns',
            ),
        ).toBe(false)
        expect(
            isAppRuntimeAuthorized(
                { ...servicePrincipal, grants: [{ ...allowed, resourceId: 'unknown' }] },
                provider,
                'unknown',
            ),
        ).toBe(false)
    })
})
