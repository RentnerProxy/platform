import { afterEach, beforeEach, describe, expect, test } from 'bun:test'

import { PERMISSIONS } from '@/config/permissions.config.ts'
import {
    APP_RUNTIME_SUPPORT_CAPABILITIES,
    isAppRuntimeAuthorized,
    qualifyAppRuntimePermission,
    requireAppRuntimePermission,
} from '@/server/AppRuntime/authority-policy.server.ts'
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
