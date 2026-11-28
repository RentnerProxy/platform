import type { PermissionKey } from '@/config/Types/permissions-config.types.ts'
import type { AuthenticatedUser } from '@/lib/Auth/Types/auth.types.ts'
import type { requirePermissionInTransaction } from '@/server/Auth/Access/rbac.service.ts'
import type { AuthTransaction } from '@/server/Auth/Core/Types/database.types.ts'
import type { readSubscribableAppIncidentCategoriesInTransaction } from '@/server/Notifications/app-incident-categories.repository.ts'

export interface PersonalAppCategoryDependencies {
    readonly authorize: (permission: PermissionKey) => Promise<AuthenticatedUser>
    readonly authorizeInTransaction: typeof requirePermissionInTransaction
    readonly transaction: <T>(run: (transaction: AuthTransaction) => Promise<T>) => Promise<T>
    readonly readCategories: typeof readSubscribableAppIncidentCategoriesInTransaction
    /** Display names of installed apps by app ID; apps the catalog cannot name are absent. */
    readonly readNames: () => Promise<ReadonlyMap<string, string>>
}
