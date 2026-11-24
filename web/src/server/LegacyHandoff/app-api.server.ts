import '@tanstack/react-start/server-only'

import { and, eq } from 'drizzle-orm'
import type { z } from 'zod'

import { appRuntimeGenerations, legacyFeatureHandoffs } from '@/db/schema.ts'
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

function parse<T>(schema: z.ZodType<T>, value: unknown): T {
    const parsed = schema.safeParse(value)
    if (!parsed.success) throw new AppRuntimeAuthorityError('invalid_input')
    return parsed.data
}

/** Validate the domain path parameter and the operation's body before any transaction starts. */
export function parseLegacyHandoffRequest(
    operation: LegacyHandoffOperation,
    domainParameter: string | undefined,
    body: unknown,
): LegacyHandoffRequest {
    const domain = parse(appProviderProfileSchema, domainParameter)
    switch (operation) {
        case 'getLegacyHandoff':
        case 'beginLegacyHandoff':
            return { operation, domain }
        case 'readLegacyHandoffPart':
            return { operation, domain, sequence: parse(appLegacyHandoffPartRequest, body).sequence }
        case 'commitLegacyHandoff':
            return { operation, domain, digest: parse(appLegacyHandoffCommit, body).digest }
    }
}

/**
 * Admit only the caller's active generation with a live lease, a manifest that declares the domain
 * as a provider profile, and an authorized grant to register a provider for it.
 */
async function authorizeDomain(
    transaction: AuthTransaction,
    credentials: AppRuntimeCredentials,
    domain: LegacyFeatureDomain,
): Promise<string> {
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
    return installationId
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
    const { domain } = request
    const installationId = await authorizeDomain(transaction, credentials, domain)
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
            const { sequence } = request
            try {
                const part = await journal(() =>
                    readLegacyFeatureHandoffPartInTransaction(
                        transaction,
                        domain,
                        installationId,
                        sequence,
                    ),
                )
                return { sequence, part }
            } catch (error) {
                // Report another holder as a conflict instead of a missing export.
                if (error instanceof AppRuntimeAuthorityError && error.code === 'not_found')
                    await readOwnStatus(transaction, domain, installationId)
                throw error
            }
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
