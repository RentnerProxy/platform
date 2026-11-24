import '@tanstack/react-start/server-only'

import { getAuthDatabase } from '@/server/Auth/Core/database.server.ts'
import { readLegacyFeatureOwnerInTransaction } from './ownership.server.ts'
import type { LegacyFeatureDomain } from './Types/legacy-handoff.types.ts'

/**
 * Admit a built-in worker only while platform owns its domain. Once an app holds the domain, a
 * restart or a downgrade to any image with this check never starts a second productive copy.
 */
export async function isLegacyFeaturePlatformOwned(domain: LegacyFeatureDomain): Promise<boolean> {
    const ownership = await getAuthDatabase().transaction((transaction) =>
        readLegacyFeatureOwnerInTransaction(transaction, domain),
    )
    return ownership.owner === 'platform'
}
