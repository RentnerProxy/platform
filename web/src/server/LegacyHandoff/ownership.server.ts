import '@tanstack/react-start/server-only'

import { eq, sql } from 'drizzle-orm'

import { LEGACY_HANDOFF_LIMITS } from '@/config/legacy-handoff.config.ts'
import { legacyFeatureHandoffs } from '@/db/schema.ts'
import { appProviderProfiles } from '@/server/AppRuntime/contract.ts'
import type { AuthTransaction } from '@/server/Auth/Core/Types/database.types.ts'
import type {
    LegacyFeatureDomain,
    LegacyFeatureOwner,
    PlatformOwnedResult,
} from './Types/legacy-handoff.types.ts'

function domainLock(domain: LegacyFeatureDomain) {
    const key = appProviderProfiles.indexOf(domain)
    if (key < 0) throw new TypeError('Unknown legacy feature domain')
    return sql`${LEGACY_HANDOFF_LIMITS.advisoryLockClass}::int, ${key}::int`
}

/** Wait until no platform writer of the domain is inside a transaction, and keep new ones out. */
export async function lockLegacyFeatureDomain(
    transaction: AuthTransaction,
    domain: LegacyFeatureDomain,
): Promise<void> {
    await transaction.execute(sql`select pg_advisory_xact_lock(${domainLock(domain)})`)
}

export function toLegacyFeatureOwner(
    row: Pick<
        typeof legacyFeatureHandoffs.$inferSelect,
        'installationId' | 'state' | 'digest' | 'partCount'
    >,
): LegacyFeatureOwner {
    const { installationId, digest } = row
    return row.state === 'committed'
        ? { owner: 'app', installationId, digest }
        : { owner: 'handoff', installationId, digest, partCount: row.partCount }
}

export async function readLegacyFeatureOwnerInTransaction(
    transaction: AuthTransaction,
    domain: LegacyFeatureDomain,
): Promise<LegacyFeatureOwner> {
    const [row] = await transaction
        .select()
        .from(legacyFeatureHandoffs)
        .where(eq(legacyFeatureHandoffs.domain, domain))
    return row ? toLegacyFeatureOwner(row) : { owner: 'platform' }
}

/**
 * Run one platform write of a built-in domain only while platform owns it. A handoff in progress
 * holds the exclusive domain lock, so the writer skips instead of waiting for it or racing its export.
 */
export async function withPlatformOwnedLegacyFeature<T>(
    transaction: AuthTransaction,
    domain: LegacyFeatureDomain,
    run: () => Promise<T>,
): Promise<PlatformOwnedResult<T>> {
    const [lock] = await transaction.execute<{ locked: boolean }>(
        sql`select pg_try_advisory_xact_lock_shared(${domainLock(domain)}) as locked`,
    )
    if (!lock?.locked) return { owned: false }
    const ownership = await readLegacyFeatureOwnerInTransaction(transaction, domain)
    if (ownership.owner !== 'platform') return { owned: false }
    return { owned: true, value: await run() }
}
