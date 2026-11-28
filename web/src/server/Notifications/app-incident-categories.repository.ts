// oxlint-disable-next-line import/no-unassigned-import -- Installed app categories are read only on the server.
import '@tanstack/react-start/server-only'

import { and, eq } from 'drizzle-orm'
import { APP_INCIDENT_CAPABILITY } from '@/config/notifications.config.ts'
import { appRuntimeGenerations, appRuntimeGrants, appRuntimeInstallations } from '@/db/schema.ts'
import type { AuthTransaction } from '@/server/Auth/Core/Types/database.types.ts'

/** The most installations whose categories one read returns. */
const MAX_INSTALLATIONS = 256

/**
 * The incident categories of installations that run an active generation and still hold the
 * incident grant. A category of an app that cannot raise incidents is not offered.
 */
export async function readSubscribableAppIncidentCategoriesInTransaction(
    transaction: AuthTransaction,
) {
    return transaction
        .select({
            appId: appRuntimeInstallations.appId,
            categories: appRuntimeGenerations.incidentCategories,
        })
        .from(appRuntimeGenerations)
        .innerJoin(
            appRuntimeInstallations,
            eq(appRuntimeInstallations.id, appRuntimeGenerations.installationId),
        )
        .innerJoin(
            appRuntimeGrants,
            and(
                eq(appRuntimeGrants.installationId, appRuntimeGenerations.installationId),
                eq(appRuntimeGrants.capabilityId, APP_INCIDENT_CAPABILITY),
                eq(appRuntimeGrants.scope, 'installation'),
                eq(appRuntimeGrants.resourceId, appRuntimeGenerations.installationId),
            ),
        )
        .where(eq(appRuntimeGenerations.state, 'active'))
        .orderBy(appRuntimeInstallations.appId)
        .limit(MAX_INSTALLATIONS)
}
