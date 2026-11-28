import '@tanstack/react-start/server-only'

import { eq, sql } from 'drizzle-orm'

import { LEGACY_HANDOFF_LIMITS } from '@/config/legacy-handoff.config.ts'
import { legacyFeatureHandoffs } from '@/db/schema.ts'
import { appProviderProfiles } from '@/server/AppRuntime/contract.ts'
import type { AuthTransaction } from '@/server/Auth/Core/Types/database.types.ts'
import { signalLegacyFeatureOwnership } from './ownership-signal.server.ts'
import type {
    LegacyFeatureDomain,
    LegacyFeatureOwner,
    PlatformOwnedResult,
} from './Types/legacy-handoff.types.ts'

function domainKey(domain: LegacyFeatureDomain): number {
    const key = appProviderProfiles.indexOf(domain)
    if (key < 0) throw new TypeError('Unknown legacy feature domain')
    return key
}

function domainLock(domain: LegacyFeatureDomain) {
    return sql`${LEGACY_HANDOFF_LIMITS.advisoryLockClass}::int, ${domainKey(domain)}::int`
}

/**
 * Wait until no platform writer of the domain is inside a transaction, and keep new ones out.
 * Statements after the lock must see every writer that committed while it waited, so only read
 * committed transactions qualify. A transaction that already holds a writer's shared lock would be
 * granted its own exclusive request at once and is refused.
 */
export async function lockLegacyFeatureDomain(
    transaction: AuthTransaction,
    domain: LegacyFeatureDomain,
): Promise<void> {
    const key = domainKey(domain)
    const [state] = await transaction.execute<{ isolation: string; writer: boolean }>(sql`
        select current_setting('transaction_isolation') as isolation,
            exists (
                select from pg_locks
                where locktype = 'advisory' and pid = pg_backend_pid() and mode = 'ShareLock'
                    and classid = (${LEGACY_HANDOFF_LIMITS.advisoryLockClass})::oid
                    and objid = (${key})::oid and objsubid = 2
            ) as writer`)
    if (state?.isolation !== 'read committed')
        throw new TypeError('Legacy feature handoffs require a read committed transaction')
    if (state.writer)
        throw new TypeError('A legacy feature handoff cannot run inside a platform writer')
    await transaction.execute(sql`select pg_advisory_xact_lock(${domainLock(domain)})`)
}

/** Keep handoffs from changing any domain's owner until this read-only transaction ends. */
export async function shareLegacyFeatureDomains(transaction: AuthTransaction): Promise<void> {
    await transaction.execute(sql`
        select pg_advisory_xact_lock_shared(${LEGACY_HANDOFF_LIMITS.advisoryLockClass}::int, key)
        from generate_series(0, ${appProviderProfiles.length - 1}::int) as key
        order by key`)
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
 * A skipped writer signals the domain, so a worker gate in this process re-reads ownership and
 * stops its worker instead of polling the fence.
 */
export async function withPlatformOwnedLegacyFeature<T>(
    transaction: AuthTransaction,
    domain: LegacyFeatureDomain,
    run: () => Promise<T>,
): Promise<PlatformOwnedResult<T>> {
    const [lock] = await transaction.execute<{ locked: boolean }>(
        sql`select pg_try_advisory_xact_lock_shared(${domainLock(domain)}) as locked`,
    )
    if (!lock?.locked) return fenced(domain)
    const ownership = await readLegacyFeatureOwnerInTransaction(transaction, domain)
    if (ownership.owner !== 'platform') return fenced(domain)
    return { owned: true, value: await run() }
}

function fenced(domain: LegacyFeatureDomain): PlatformOwnedResult<never> {
    signalLegacyFeatureOwnership([domain])
    return { owned: false }
}
