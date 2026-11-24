import '@tanstack/react-start/server-only'

import { createHash } from 'node:crypto'
import { and, desc, eq, lt, lte } from 'drizzle-orm'
import type { z } from 'zod'

import { LEGACY_HANDOFF_LIMITS } from '@/config/legacy-handoff.config.ts'
import {
    appRuntimeGenerations,
    legacyFeatureHandoffRequests,
    legacyFeatureHandoffs,
} from '@/db/schema.ts'
import {
    APP_RUNTIME_SUPPORT_CAPABILITIES,
    isAppRuntimeAuthorized,
    resolveAppRuntimePrincipalInTransaction,
} from '@/server/AppRuntime/authority.server.ts'
import {
    appLegacyHandoffCommit,
    appLegacyHandoffPartRequest,
    appProviderProfileSchema,
    appProviderProfiles,
} from '@/server/AppRuntime/contract.ts'
import { AppRuntimeProblem } from '@/server/AppRuntime/problem.ts'
import {
    AppRuntimeAuthorityError,
    type AppRuntimeCredentials,
} from '@/server/AppRuntime/Types/authority.types.ts'
import type { LegacyHandoffOperation } from '@/server/AppRuntime/Types/gateway.types.ts'
import type { AuthTransaction } from '@/server/Auth/Core/Types/database.types.ts'
import {
    abortLegacyFeatureHandoffInTransaction,
    beginLegacyFeatureHandoffInTransaction,
    commitLegacyFeatureHandoffInTransaction,
    readLegacyFeatureHandoffPartInTransaction,
} from './journal.server.ts'
import { readLegacyFeatureOwnerInTransaction } from './ownership.server.ts'
import type {
    LegacyFeatureHandoffSources,
    LegacyHandoffPart,
    LegacyHandoffRequest,
    LegacyHandoffStatus,
} from './Types/legacy-handoff-api.types.ts'
import {
    LegacyFeatureHandoffError,
    type LegacyFeatureDomain,
    type LegacyFeatureOwner,
} from './Types/legacy-handoff.types.ts'

const unavailable = new AppRuntimeProblem(503, 'unavailable', 'App API is unavailable.')
const idempotencyConflict = new AppRuntimeProblem(
    409,
    'idempotencyConflict',
    'Idempotency key was reused.',
)

function parse<T>(schema: z.ZodType<T>, value: unknown): T {
    const parsed = schema.safeParse(value)
    if (!parsed.success) throw new AppRuntimeAuthorityError('invalid_input')
    return parsed.data
}

function requiredKey(key: string | undefined): string {
    if (key === undefined) throw new AppRuntimeAuthorityError('invalid_input')
    return key
}

/** Validate the domain path parameter and the operation's body before any transaction starts. */
export function parseLegacyHandoffRequest(
    operation: LegacyHandoffOperation,
    domainParameter: string | undefined,
    body: unknown,
    idempotencyKey: string | undefined,
): LegacyHandoffRequest {
    const domain = parse(appProviderProfileSchema, domainParameter)
    switch (operation) {
        case 'getLegacyHandoff':
            return { operation, domain }
        case 'beginLegacyHandoff':
            return { operation, domain, key: requiredKey(idempotencyKey) }
        case 'readLegacyHandoffPart':
            return { operation, domain, ...parse(appLegacyHandoffPartRequest, body) }
        case 'commitLegacyHandoff':
            return {
                operation,
                domain,
                digest: parse(appLegacyHandoffCommit, body).digest,
                key: requiredKey(idempotencyKey),
            }
    }
}

interface DomainAuthority {
    readonly installationId: string
    /** Idempotency keys are scoped like app messages: per service or delegated user. */
    readonly actor: string
    /** The earliest of the lease, delegation and session deadlines. */
    readonly expiresAt: Date
}

/**
 * Admit only the caller's active generation with a live lease, a manifest that declares the domain
 * as a provider profile, and an authorized grant to register a provider for it.
 */
async function authorizeDomain(
    transaction: AuthTransaction,
    credentials: AppRuntimeCredentials,
    domain: LegacyFeatureDomain,
): Promise<DomainAuthority> {
    const principal = await resolveAppRuntimePrincipalInTransaction(transaction, credentials)
    const { installationId, generation } = principal.identity
    const [current] = await transaction
        .select({ providerProfiles: appRuntimeGenerations.providerProfiles })
        .from(appRuntimeGenerations)
        .where(
            and(
                eq(appRuntimeGenerations.installationId, installationId),
                eq(appRuntimeGenerations.generation, generation),
            ),
        )
    // A lease that expired during the checks is an authority failure, not a missing grant.
    if (principal.expiresAt.getTime() <= Date.now())
        throw new AppRuntimeAuthorityError('unauthorized')
    if (
        !current?.providerProfiles.includes(domain) ||
        !isAppRuntimeAuthorized(principal, APP_RUNTIME_SUPPORT_CAPABILITIES.provider, domain)
    )
        throw new AppRuntimeAuthorityError('forbidden')
    return {
        installationId,
        actor: principal.user?.id ?? 'service',
        expiresAt: principal.expiresAt,
    }
}

/**
 * Bind an accepted begin or commit key to its input before the journal changes. Reuse with other
 * input is a conflict; a retry with the same input continues to the journal, which returns the
 * recorded export or ownership. A failed request rolls the binding back with the transaction.
 */
async function bindRequestKey(
    transaction: AuthTransaction,
    { installationId, actor }: DomainAuthority,
    operation: 'begin' | 'commit',
    key: string,
    input: readonly string[],
): Promise<void> {
    const fingerprint = createHash('sha256').update(JSON.stringify(input)).digest('hex')
    const [inserted] = await transaction
        .insert(legacyFeatureHandoffRequests)
        .values({ installationId, actor, operation, key, fingerprint })
        .onConflictDoNothing()
        .returning({ key: legacyFeatureHandoffRequests.key })
    const scope = eq(legacyFeatureHandoffRequests.installationId, installationId)
    if (!inserted) {
        const [existing] = await transaction
            .select({ fingerprint: legacyFeatureHandoffRequests.fingerprint })
            .from(legacyFeatureHandoffRequests)
            .where(
                and(
                    scope,
                    eq(legacyFeatureHandoffRequests.actor, actor),
                    eq(legacyFeatureHandoffRequests.operation, operation),
                    eq(legacyFeatureHandoffRequests.key, key),
                ),
            )
        if (existing && existing.fingerprint !== fingerprint) throw idempotencyConflict
        return
    }
    // Forget expired keys and keep only the newest ones; the journal still dedupes their retries.
    const { requestKeyRetentionMs, requestKeysPerInstallation } = LEGACY_HANDOFF_LIMITS
    await transaction
        .delete(legacyFeatureHandoffRequests)
        .where(
            and(
                scope,
                lte(
                    legacyFeatureHandoffRequests.createdAt,
                    new Date(Date.now() - requestKeyRetentionMs),
                ),
            ),
        )
    const [oldestKept] = await transaction
        .select({ createdAt: legacyFeatureHandoffRequests.createdAt })
        .from(legacyFeatureHandoffRequests)
        .where(scope)
        .orderBy(desc(legacyFeatureHandoffRequests.createdAt))
        .offset(requestKeysPerInstallation - 1)
        .limit(1)
    if (oldestKept)
        await transaction
            .delete(legacyFeatureHandoffRequests)
            .where(and(scope, lt(legacyFeatureHandoffRequests.createdAt, oldestKept.createdAt)))
}

function toStatus(
    domain: LegacyFeatureDomain,
    owner: LegacyFeatureOwner,
    installationId: string,
): LegacyHandoffStatus {
    if (owner.owner === 'platform') return { domain, state: 'platform' }
    if (owner.installationId !== installationId) throw new AppRuntimeAuthorityError('conflict')
    return owner.owner === 'handoff'
        ? { domain, state: 'exported', digest: owner.digest, partCount: owner.partCount }
        : { domain, state: 'committed', digest: owner.digest }
}

async function journal<T>(run: () => Promise<T>): Promise<T> {
    try {
        return await run()
    } catch (error) {
        if (!(error instanceof LegacyFeatureHandoffError)) throw error
        if (error.code === 'not_found' || error.code === 'conflict')
            throw new AppRuntimeAuthorityError(error.code)
        // A corrupt part or an invalid export needs an abort and a fresh export by platform.
        console.warn('[legacy-handoff] journal refused the request', error.code)
        throw unavailable
    }
}

async function readOwnStatus(
    transaction: AuthTransaction,
    domain: LegacyFeatureDomain,
    installationId: string,
): Promise<LegacyHandoffStatus> {
    return toStatus(
        domain,
        await readLegacyFeatureOwnerInTransaction(transaction, domain),
        installationId,
    )
}

/**
 * Run one App API handoff request for the calling installation. The caller provides a read
 * committed transaction, so the journal's domain lock sees every platform writer that finished.
 */
export async function executeLegacyHandoffInTransaction(
    transaction: AuthTransaction,
    credentials: AppRuntimeCredentials,
    request: LegacyHandoffRequest,
    sources: LegacyFeatureHandoffSources,
): Promise<LegacyHandoffStatus | LegacyHandoffPart> {
    const authority = await authorizeDomain(transaction, credentials, request.domain)
    if (request.operation === 'beginLegacyHandoff')
        await bindRequestKey(transaction, authority, 'begin', request.key, [request.domain])
    if (request.operation === 'commitLegacyHandoff')
        await bindRequestKey(transaction, authority, 'commit', request.key, [
            request.domain,
            request.digest,
        ])
    const result = await runRequest(transaction, authority.installationId, request, sources)
    // The journal work can wait on locks. Never answer, or keep its writes, once the caller's
    // authority has expired; the throw rolls the transaction back.
    if (authority.expiresAt.getTime() <= Date.now())
        throw new AppRuntimeAuthorityError('unauthorized')
    return result
}

async function runRequest(
    transaction: AuthTransaction,
    installationId: string,
    request: LegacyHandoffRequest,
    sources: LegacyFeatureHandoffSources,
): Promise<LegacyHandoffStatus | LegacyHandoffPart> {
    const { domain } = request
    const source = sources[domain]
    // A source registered under another key would hand off a domain the caller was not checked for.
    if (source && source.domain !== domain)
        throw new TypeError('A legacy feature source is registered under another domain')
    switch (request.operation) {
        case 'getLegacyHandoff':
            return readOwnStatus(transaction, domain, installationId)
        case 'beginLegacyHandoff': {
            if (source)
                return toStatus(
                    domain,
                    await journal(() =>
                        beginLegacyFeatureHandoffInTransaction(transaction, source, installationId),
                    ),
                    installationId,
                )
            // Without a source nothing can export the built-in state yet, so never fence it with
            // an empty export. A handoff recorded earlier still answers repeated calls.
            const status = await readOwnStatus(transaction, domain, installationId)
            if (status.state === 'platform') throw new AppRuntimeAuthorityError('not_found')
            return status
        }
        case 'readLegacyHandoffPart': {
            const { digest, sequence } = request
            // The shared row lock keeps abort and commit from replacing the export until this
            // transaction ends, so the digest check and the read see the same export.
            const [row] = await transaction
                .select({
                    installationId: legacyFeatureHandoffs.installationId,
                    state: legacyFeatureHandoffs.state,
                    digest: legacyFeatureHandoffs.digest,
                })
                .from(legacyFeatureHandoffs)
                .where(eq(legacyFeatureHandoffs.domain, domain))
                .for('share')
            if (row && row.installationId !== installationId)
                throw new AppRuntimeAuthorityError('conflict')
            if (row?.state !== 'exported') throw new AppRuntimeAuthorityError('not_found')
            if (row.digest !== digest) throw new AppRuntimeAuthorityError('conflict')
            const part = await journal(() =>
                readLegacyFeatureHandoffPartInTransaction(
                    transaction,
                    domain,
                    installationId,
                    sequence,
                ),
            )
            return { sequence, part }
        }
        case 'commitLegacyHandoff': {
            const { digest } = request
            if (source)
                return toStatus(
                    domain,
                    await journal(() =>
                        commitLegacyFeatureHandoffInTransaction(
                            transaction,
                            source,
                            installationId,
                            digest,
                        ),
                    ),
                    installationId,
                )
            const status = await readOwnStatus(transaction, domain, installationId)
            if (status.state === 'platform') throw new AppRuntimeAuthorityError('not_found')
            if (status.digest !== digest) throw new AppRuntimeAuthorityError('conflict')
            // Without its source an export cannot retire platform state; only an abort releases it.
            if (status.state === 'exported') throw unavailable
            return status
        }
    }
}

/**
 * Return every uncommitted domain of a departing installation to platform. Its untouched state lets
 * platform workers resume, while committed ownership stays recorded with the installation.
 */
export async function abortInstallationLegacyHandoffsInTransaction(
    transaction: AuthTransaction,
    installationId: string,
): Promise<void> {
    const rows = await transaction
        .select({ domain: legacyFeatureHandoffs.domain })
        .from(legacyFeatureHandoffs)
        .where(
            and(
                eq(legacyFeatureHandoffs.installationId, installationId),
                eq(legacyFeatureHandoffs.state, 'exported'),
            ),
        )
    // Take the domain locks in profile order, the order every multi-domain reader uses.
    const domains = appProviderProfiles.filter((domain) =>
        rows.some((row) => row.domain === domain),
    )
    for (const domain of domains) {
        // oxlint-disable-next-line no-await-in-loop -- Domain locks are taken one at a time in order.
        await journal(() =>
            abortLegacyFeatureHandoffInTransaction(transaction, domain, installationId),
        )
    }
}
