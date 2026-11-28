import { describe, expect, mock, test } from 'bun:test'
import { PERMISSIONS } from '@/config/permissions.config.ts'
import type { PermissionKey } from '@/config/Types/permissions-config.types.ts'
import type { AuthenticatedUser } from '@/lib/Auth/Types/auth.types.ts'
import type { AuthTransaction } from '@/server/Auth/Core/Types/database.types.ts'
import { createPersonalAppCategoryService } from '@/server/UserSettings/Notifications/app-categories.service.ts'
import type { PersonalAppCategoryDependencies } from '@/server/UserSettings/Notifications/Types/app-categories.types.ts'

const transaction = {} as AuthTransaction
const rows = [
    {
        appId: 'zeta.reports',
        categories: [
            { id: 'sync', name: 'Sync', resource: 'none' as const },
            { id: 'backup', name: 'Backup', resource: 'none' as const },
        ],
    },
    {
        appId: 'acme.monitor',
        categories: [
            { id: 'upstream', name: 'Upstream down', resource: 'proxyHost' as const },
            { id: 'disk', name: 'Disk space', resource: 'none' as const },
        ],
    },
    // Another installation of the same app contributes its categories once.
    {
        appId: 'acme.monitor',
        categories: [{ id: 'disk', name: 'Disk space', resource: 'none' as const }],
    },
    { appId: 'empty.app', categories: [] },
]

function setup(options: { permissions?: PermissionKey[]; names?: [string, string][] } = {}) {
    const user = (): AuthenticatedUser => ({
        id: '00000000-0000-4000-8000-000000000001',
        permissions: options.permissions ?? [PERMISSIONS.APP_ACCESS],
        displayName: 'User',
        email: 'user@example.test',
        profileImageVersion: null,
        roles: [],
        language: 'en',
        themeMode: 'dark',
    })
    const dependencies = {
        authorize: mock(async () => user()),
        authorizeInTransaction: mock(async () => user()),
        transaction: async (run) => run(transaction),
        readCategories: mock(async () => rows),
        readNames: mock(async () => new Map(options.names ?? [['acme.monitor', 'Acme Monitor']])),
    } satisfies PersonalAppCategoryDependencies
    return { dependencies, service: createPersonalAppCategoryService(dependencies) }
}

describe('personal app incident categories', () => {
    test('groups the categories by app display name with qualified keys', async () => {
        const { service, dependencies } = setup()
        expect(await service.getPersonalAppIncidentCategoriesService()).toEqual([
            {
                appId: 'acme.monitor',
                appName: 'Acme Monitor',
                categories: [
                    { key: 'acme.monitor/disk', name: 'Disk space' },
                    { key: 'acme.monitor/upstream', name: 'Upstream down' },
                ],
            },
            {
                // An app the catalog cannot name is shown by its ID.
                appId: 'zeta.reports',
                appName: 'zeta.reports',
                categories: [
                    { key: 'zeta.reports/backup', name: 'Backup' },
                    { key: 'zeta.reports/sync', name: 'Sync' },
                ],
            },
        ])
        expect(dependencies.authorize).toHaveBeenCalledWith(PERMISSIONS.APP_ACCESS)
    })

    test('uses the same permission as the app incident event and re-checks it in the read', async () => {
        const { service, dependencies } = setup({ permissions: [PERMISSIONS.NOTIFICATIONS_MANAGE] })
        expect(await service.getPersonalAppIncidentCategoriesService()).toEqual([])
        expect(dependencies.readCategories).not.toHaveBeenCalled()
        expect(dependencies.readNames).not.toHaveBeenCalled()
        // The permission can be revoked between the session check and the read.
        const revoked = setup()
        revoked.dependencies.authorizeInTransaction.mockImplementation(async () => ({
            id: '00000000-0000-4000-8000-000000000001',
            permissions: [],
            displayName: 'User',
            email: 'user@example.test',
            profileImageVersion: null,
            roles: [],
            language: 'en',
            themeMode: 'dark',
        }))
        expect(await revoked.service.getPersonalAppIncidentCategoriesService()).toEqual([])
        expect(revoked.dependencies.readCategories).not.toHaveBeenCalled()
    })

    test('refuses an actor without access before reading anything', async () => {
        const { service, dependencies } = setup()
        dependencies.authorize.mockImplementation(async () => {
            throw new Error('permission_denied')
        })
        await expect(service.getPersonalAppIncidentCategoriesService()).rejects.toThrow(
            'permission_denied',
        )
        expect(dependencies.readCategories).not.toHaveBeenCalled()
    })

    test('offers nothing without installed apps and skips the name lookup', async () => {
        const { service, dependencies } = setup()
        dependencies.readCategories.mockImplementation(async () => [])
        expect(await service.getPersonalAppIncidentCategoriesService()).toEqual([])
        expect(dependencies.readNames).not.toHaveBeenCalled()
    })
})
