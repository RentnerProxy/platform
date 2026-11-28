import '@tanstack/react-start/server-only'

import { PERMISSIONS } from '@/config/permissions.config.ts'
import type { AuthenticatedUser } from '@/lib/Auth/Types/auth.types.ts'
import { getAllowedNotificationCategories } from '@/lib/Notifications/notification-access.ts'
import type { AppIncidentCategoryGroup } from '@/lib/Notifications/Types/notifications.types.ts'
import { nativeAppCatalog } from '@/server/AppRuntime/catalog/transport.server.ts'
import { requirePermissionService } from '@/server/Auth/Access/authorization.service.ts'
import { requirePermissionInTransaction } from '@/server/Auth/Access/rbac.service.ts'
import { getAuthDatabase } from '@/server/Auth/Core/database.server.ts'
import { readSubscribableAppIncidentCategoriesInTransaction } from '@/server/Notifications/app-incident-categories.repository.ts'
import type { PersonalAppCategoryDependencies } from './Types/app-categories.types.ts'

/** How long the catalog may take to name apps before they are shown by their ID. */
const NAME_LOOKUP_MS = 3_000

function groupCategories(
    rows: Awaited<ReturnType<PersonalAppCategoryDependencies['readCategories']>>,
    names: ReadonlyMap<string, string>,
): AppIncidentCategoryGroup[] {
    const groups = new Map<string, Map<string, string>>()
    for (const { appId, categories } of rows) {
        const known = groups.get(appId) ?? new Map<string, string>()
        for (const { id, name } of categories) known.set(`${appId}/${id}`, name)
        if (known.size > 0) groups.set(appId, known)
    }
    return [...groups]
        .map(([appId, categories]) => ({
            appId,
            appName: names.get(appId) ?? appId,
            categories: [...categories]
                .map(([key, name]) => ({ key, name }))
                .toSorted(
                    (left, right) =>
                        left.name.localeCompare(right.name) || (left.key < right.key ? -1 : 1),
                ),
        }))
        .toSorted(
            (left, right) =>
                left.appName.localeCompare(right.appName) || (left.appId < right.appId ? -1 : 1),
        )
}

export function createPersonalAppCategoryService(dependencies: PersonalAppCategoryDependencies) {
    return {
        /**
         * The categories a channel owner may subscribe to. They are offered under the same
         * permission as the app incident event itself, and as no app can raise one for a user who
         * lacks it, an unauthorized read returns nothing.
         */
        async getPersonalAppIncidentCategoriesService(): Promise<AppIncidentCategoryGroup[]> {
            const actor = await dependencies.authorize(PERMISSIONS.APP_ACCESS)
            const rows = await dependencies.transaction(async (transaction) => {
                const fresh = await dependencies.authorizeInTransaction(
                    transaction,
                    actor.id,
                    PERMISSIONS.APP_ACCESS,
                )
                return getAllowedNotificationCategories(fresh.permissions).includes('app_incident')
                    ? dependencies.readCategories(transaction)
                    : []
            })
            if (rows.length === 0) return []
            return groupCategories(rows, await dependencies.readNames())
        },
    }
}

async function readCatalogNames(): Promise<ReadonlyMap<string, string>> {
    try {
        const catalog = await nativeAppCatalog(AbortSignal.timeout(NAME_LOOKUP_MS))
        return new Map(
            catalog.installations.flatMap(({ appId, name }) =>
                name === null ? [] : [[appId, name]],
            ),
        )
    } catch {
        // The catalog only names apps; a category stays selectable under the app's ID without it.
        return new Map()
    }
}

export const { getPersonalAppIncidentCategoriesService } = createPersonalAppCategoryService({
    authorize: (permission): Promise<AuthenticatedUser> => requirePermissionService(permission),
    authorizeInTransaction: requirePermissionInTransaction,
    transaction: (run) =>
        getAuthDatabase().transaction(run, {
            isolationLevel: 'repeatable read',
            accessMode: 'read only',
        }),
    readCategories: readSubscribableAppIncidentCategoriesInTransaction,
    readNames: readCatalogNames,
})
