import '@tanstack/react-start/server-only'

import { createHash } from 'node:crypto'
import { and, eq, sql } from 'drizzle-orm'

import {
    LEGACY_HANDOFF_DIGEST_LABEL,
    LEGACY_HANDOFF_LIMITS,
} from '@/config/legacy-handoff.config.ts'
import {
    appRuntimeInstallations,
    legacyFeatureHandoffParts,
    legacyFeatureHandoffs,
} from '@/db/schema.ts'
import { appProviderProfiles, isAppWireJson } from '@/server/AppRuntime/contract.ts'
import type { AppRuntimeJsonValue } from '@/server/AppRuntime/Types/authority.types.ts'
import { decryptSecret, encryptSecret } from '@/server/Auth/Core/encryption.server.ts'
import type { AuthTransaction } from '@/server/Auth/Core/Types/database.types.ts'
import {
    lockLegacyFeatureDomain,
    shareLegacyFeatureDomains,
    toLegacyFeatureOwner,
} from './ownership.server.ts'
import {
    LegacyFeatureHandoffError,
    type LegacyFeatureDomain,
    type LegacyFeatureHandoffSource,
    type LegacyFeatureOwner,
    type LegacyFeatureStatus,
} from './Types/legacy-handoff.types.ts'

function sha256(value: string): string {
    return createHash('sha256').update(value).digest('hex')
}

/** Bind every encrypted part to its domain, installation, position and content hash. */
function partContext(
    domain: LegacyFeatureDomain,
    installationId: string,
    sequence: number,
    hash: string,
): string {
    return `legacy-feature-handoff:v1:${domain}:${installationId}:${sequence}:${hash}`
}

function exportDigest(domain: LegacyFeatureDomain, hashes: readonly string[]): string {
    return sha256(
        [LEGACY_HANDOFF_DIGEST_LABEL, domain, String(hashes.length), ...hashes].join('\n'),
    )
}

/**
 * Serialize one part and validate the stored text itself: `toJSON` can change what is written, and
 * a throwing getter or hook makes the part invalid instead of escaping past the failure record.
 */
function serializePart(part: unknown): string | undefined {
    try {
        if (!isAppWireJson(part)) return undefined
        const plaintext: unknown = JSON.stringify(part)
        if (
            typeof plaintext !== 'string' ||
            Buffer.byteLength(plaintext) > LEGACY_HANDOFF_LIMITS.partBytes ||
            !isAppWireJson(JSON.parse(plaintext))
        )
            return undefined
        return plaintext
    } catch {
        return undefined
    }
}

async function lockJournalRow(transaction: AuthTransaction, domain: LegacyFeatureDomain) {
    await lockLegacyFeatureDomain(transaction, domain)
    const [row] = await transaction
        .select()
        .from(legacyFeatureHandoffs)
        .where(eq(legacyFeatureHandoffs.domain, domain))
        .for('update')
    return row
}

async function deleteParts(transaction: AuthTransaction, domain: LegacyFeatureDomain) {
    await transaction
        .delete(legacyFeatureHandoffParts)
        .where(eq(legacyFeatureHandoffParts.domain, domain))
}

/**
 * Fence platform writers of the domain and store an encrypted snapshot for one installation.
 * Repeating the call returns the recorded export, so an interrupted import resumes with the same
 * digest; another installation cannot take over a domain that is already handed off.
 */
export async function beginLegacyFeatureHandoffInTransaction(
    transaction: AuthTransaction,
    source: LegacyFeatureHandoffSource,
    installationId: string,
): Promise<LegacyFeatureOwner> {
    const { domain } = source
    const current = await lockJournalRow(transaction, domain)
    if (current) {
        if (current.installationId !== installationId)
            throw new LegacyFeatureHandoffError('conflict')
        return toLegacyFeatureOwner(current)
    }
    const [installation] = await transaction
        .select({ id: appRuntimeInstallations.id })
        .from(appRuntimeInstallations)
        .where(eq(appRuntimeInstallations.id, installationId))
    if (!installation) throw new LegacyFeatureHandoffError('not_found')

    // Parts never outlive their journal row; refuse to mix stray rows into a new snapshot.
    await deleteParts(transaction, domain)
    const hashes: string[] = []
    const pending: Promise<void>[] = []
    let closed = false
    // A source that swallows a rejected part must not turn a partial snapshot into an export.
    let failure: unknown
    const store = async (sequence: number, plaintext: string, hash: string) => {
        const encrypted = await encryptSecret(
            plaintext,
            partContext(domain, installationId, sequence, hash),
        )
        await transaction.insert(legacyFeatureHandoffParts).values({
            domain,
            sequence,
            sha256: hash,
            ciphertext: encrypted.ciphertext,
            iv: encrypted.iv,
        })
    }
    const reject = () => {
        failure ??= new LegacyFeatureHandoffError('invalid_export')
        const rejected = Promise.reject(failure)
        // A source that does not await still gets a rejected emit, but begin reports the failure.
        rejected.catch(() => undefined)
        return rejected
    }
    const emit = (part: AppRuntimeJsonValue) => {
        const plaintext = closed ? undefined : serializePart(part)
        if (plaintext === undefined || hashes.length >= LEGACY_HANDOFF_LIMITS.maximumParts)
            return reject()
        const hash = sha256(plaintext)
        // Reserve the position synchronously so parts keep their emission order.
        const stored = store(hashes.push(hash) - 1, plaintext, hash)
        pending.push(
            stored.catch((error: unknown) => {
                failure ??= error
            }),
        )
        return stored
    }
    try {
        await source.export(transaction, emit)
    } finally {
        closed = true
        // Settle every accepted part before begin returns or rethrows, so no write outlives it.
        await Promise.all(pending)
    }
    if (failure !== undefined) throw failure

    const digest = exportDigest(domain, hashes)
    const [row] = await transaction
        .insert(legacyFeatureHandoffs)
        .values({ domain, installationId, state: 'exported', digest, partCount: hashes.length })
        .returning()
    return toLegacyFeatureOwner(row!)
}

/** Return one decrypted part of the export the installation is importing. */
export async function readLegacyFeatureHandoffPartInTransaction(
    transaction: AuthTransaction,
    domain: LegacyFeatureDomain,
    installationId: string,
    sequence: number,
): Promise<AppRuntimeJsonValue> {
    // A shared row lock keeps commit and abort from deleting the parts during the read.
    const [row] = await transaction
        .select()
        .from(legacyFeatureHandoffs)
        .where(eq(legacyFeatureHandoffs.domain, domain))
        .for('share')
    if (
        row?.state !== 'exported' ||
        row.installationId !== installationId ||
        !Number.isSafeInteger(sequence) ||
        sequence < 0 ||
        sequence >= row.partCount
    )
        throw new LegacyFeatureHandoffError('not_found')
    const [part] = await transaction
        .select()
        .from(legacyFeatureHandoffParts)
        .where(
            and(
                eq(legacyFeatureHandoffParts.domain, domain),
                eq(legacyFeatureHandoffParts.sequence, sequence),
            ),
        )
    if (!part) throw new LegacyFeatureHandoffError('corrupt')
    try {
        const plaintext = await decryptSecret(
            { ciphertext: part.ciphertext, iv: part.iv },
            partContext(domain, installationId, sequence, part.sha256),
        )
        return JSON.parse(plaintext) as AppRuntimeJsonValue
    } catch {
        // An unreadable part needs an abort and a fresh export; platform state is still intact.
        throw new LegacyFeatureHandoffError('corrupt')
    }
}

/**
 * Transfer the domain to the installation once it imported the exact export. Platform state is
 * retired in the same transaction, so a retry neither repeats nor skips the destructive step.
 */
export async function commitLegacyFeatureHandoffInTransaction(
    transaction: AuthTransaction,
    source: LegacyFeatureHandoffSource,
    installationId: string,
    digest: string,
): Promise<LegacyFeatureOwner> {
    const { domain } = source
    const row = await lockJournalRow(transaction, domain)
    if (!row) throw new LegacyFeatureHandoffError('not_found')
    if (row.installationId !== installationId || row.digest !== digest)
        throw new LegacyFeatureHandoffError('conflict')
    if (row.state === 'committed') return toLegacyFeatureOwner(row)
    await source.retire(transaction)
    await deleteParts(transaction, domain)
    const [committed] = await transaction
        .update(legacyFeatureHandoffs)
        .set({ state: 'committed', committedAt: sql`now()` })
        .where(eq(legacyFeatureHandoffs.domain, domain))
        .returning()
    return toLegacyFeatureOwner(committed!)
}

/** Return an uncommitted domain to platform; its untouched state lets platform workers resume. */
export async function abortLegacyFeatureHandoffInTransaction(
    transaction: AuthTransaction,
    domain: LegacyFeatureDomain,
    installationId: string,
): Promise<void> {
    const row = await lockJournalRow(transaction, domain)
    if (!row) return
    if (row.installationId !== installationId || row.state === 'committed')
        throw new LegacyFeatureHandoffError('conflict')
    await deleteParts(transaction, domain)
    await transaction.delete(legacyFeatureHandoffs).where(eq(legacyFeatureHandoffs.domain, domain))
}

/**
 * Report each domain's owner and, while platform owns it, what an app would take over. Shared
 * domain locks keep a handoff from committing between the owner read and the inspection.
 */
export async function inspectLegacyFeaturesInTransaction(
    transaction: AuthTransaction,
    sources: Readonly<Partial<Record<LegacyFeatureDomain, LegacyFeatureHandoffSource>>>,
): Promise<LegacyFeatureStatus[]> {
    await shareLegacyFeatureDomains(transaction)
    const rows = await transaction.select().from(legacyFeatureHandoffs)
    const owners = new Map(rows.map((row) => [row.domain, toLegacyFeatureOwner(row)]))
    return Promise.all(
        appProviderProfiles.map(async (domain): Promise<LegacyFeatureStatus> => {
            const ownership: LegacyFeatureOwner = owners.get(domain) ?? { owner: 'platform' }
            const source = sources[domain]
            return ownership.owner === 'platform' && source
                ? { domain, ownership, inspection: await source.inspect(transaction) }
                : { domain, ownership }
        }),
    )
}
