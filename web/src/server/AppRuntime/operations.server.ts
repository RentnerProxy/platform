import '@tanstack/react-start/server-only'

import { createHash, randomUUID } from 'node:crypto'
import { and, asc, eq, inArray, sql } from 'drizzle-orm'
import { z } from 'zod'
import { withBackgroundDatabaseContext } from '@/db/background-admission.ts'
import {
    appRuntimeInstallations,
    appRuntimeOperationRequests,
    appRuntimeOperations,
} from '@/db/schema.ts'
import type { ProxyRuntimeMutationStatus } from '@/lib/ProxyRuntime/Types/proxy-runtime.types.ts'
import { CertificateDomainError } from '@/server/Admin/CertificateManagement/certificates.errors.ts'
import {
    mapProxyHostDomainUniqueViolation,
    ProxyHostDomainError,
} from '@/server/Admin/ProxyHostManagement/proxy-hosts.errors.ts'
import { TrustedCaDomainError } from '@/server/Admin/TrustedCaManagement/trusted-cas.errors.ts'
import { getAuthDatabase } from '@/server/Auth/Core/database.server.ts'
import { isAuthDomainError } from '@/server/Auth/Core/errors.server.ts'
import type { AuthTransaction } from '@/server/Auth/Core/Types/database.types.ts'
import { getBackgroundDatabase } from '@/server/Foundation/background-database.server.ts'
import { readProxyRuntimeSnapshot } from '@/server/ProxyRuntime/proxy-runtime-data.ts'
import { reconcileProxyConfigurationService } from '@/server/ProxyRuntime/proxy-runtime.service.ts'
import { ProxyRuntimeSnapshotError } from '@/server/ProxyRuntime/proxy-runtime-snapshot.ts'
import { lockProxyRuntimeSettings } from '@/server/ProxyRuntime/proxy-runtime-settings.ts'
import {
    isAppRuntimeAuthorized,
    refreshAppRuntimePrincipalInTransaction,
    requireAppRuntimeAuthorization,
    resolveAppRuntimePrincipalInTransaction,
} from './authority.server.ts'
import { appProxyHostChange, appRecordId } from './contract.ts'
import {
    applyAppOwnedProxyHostChange,
    checkAppOwnedProxyHostChange,
    manageOwnedHosts,
    ownedHostPermission,
    setAppRuntimeTransactionTimeout,
} from './hosts.server.ts'
import { AppRuntimeProblem } from './problem.ts'
import { AppRuntimeAuthorityError } from './Types/authority.types.ts'
import type {
    AppRuntimeCredentials,
    AppRuntimeIdentity,
    AppRuntimePrincipal,
} from './Types/authority.types.ts'
import type { AppOwnedProxyHostChange } from './Types/hosts.types.ts'
import type {
    AppOperation,
    AppOperationFailure,
    AppOperationWorkerClaim,
} from './Types/operations.types.ts'

type OperationRow = typeof appRuntimeOperations.$inferSelect

const pollIntervalMs = 1_000
const reconcileLeaseMs = 60_000
const reconcileConfirmationMs = 120_000
const maxPendingPerInstallation = 100
const operationIdSchema = z.uuid().refine((value) => value === value.toLowerCase())
const reconcileUnconfirmed = new AppRuntimeProblem(
    503,
    'proxyApplyUnconfirmed',
    'Proxy configuration apply could not be confirmed',
)

function digest(value: string): string {
    return createHash('sha256').update(value).digest('hex')
}

function failureFields({ code, status, title }: AppRuntimeProblem): AppOperationFailure {
    return { code, status, title }
}

function operationDocument(row: OperationRow): AppOperation {
    const { id, status } = row
    if (status === 'failed') {
        if (!row.failure) throw new Error('Failed app operation has no problem')
        const { code, status: failureStatus, title } = row.failure
        return {
            id,
            status,
            problem: new AppRuntimeProblem(failureStatus, code, title).document(row.requestId),
        }
    }
    return status === 'succeeded' && row.result
        ? { id, status, result: row.result }
        : { id, status }
}

/** Durable receipts share a key namespace across app proxy acceptance and cancellation. */
async function lockOperationRequest(
    transaction: AuthTransaction,
    installationId: string,
    key: string,
) {
    if (!appRecordId.safeParse(key).success) throw new AppRuntimeAuthorityError('invalid_input')
    const keyHash = digest(key)
    await transaction.execute(
        sql`select pg_advisory_xact_lock(hashtextextended(${'app-runtime-operation:' + installationId + ':' + keyHash}, 0))`,
    )
    const [receipt] = await transaction
        .select()
        .from(appRuntimeOperationRequests)
        .where(
            and(
                eq(appRuntimeOperationRequests.installationId, installationId),
                eq(appRuntimeOperationRequests.keyHash, keyHash),
            ),
        )
    return { keyHash, receipt }
}

function assertSameOperationRequest(receipt: { payloadHash: string }, payloadHash: string) {
    if (receipt.payloadHash !== payloadHash)
        throw new AppRuntimeProblem(409, 'idempotencyConflict', 'Idempotency key was reused')
}

async function readAuthorizedOperation(
    transaction: AuthTransaction,
    principal: AppRuntimePrincipal,
    operationId: string,
    update = false,
): Promise<OperationRow> {
    if (!operationIdSchema.safeParse(operationId).success)
        throw new AppRuntimeAuthorityError('not_found')
    const query = transaction
        .select()
        .from(appRuntimeOperations)
        .where(
            and(
                eq(appRuntimeOperations.id, operationId),
                eq(appRuntimeOperations.installationId, principal.identity.installationId),
            ),
        )
    const [row] = await (update ? query.for('update') : query)
    if (
        !row ||
        row.actorUserId !== (principal.user?.id ?? null) ||
        !isAppRuntimeAuthorized(principal, manageOwnedHosts, row.input.hostId, [
            ownedHostPermission(row.input),
        ])
    )
        throw new AppRuntimeAuthorityError('not_found')
    return row
}

function hostChangeProblem(error: unknown): AppRuntimeProblem | null {
    if (error instanceof AppRuntimeProblem) return error
    const hostError =
        error instanceof ProxyHostDomainError ? error : mapProxyHostDomainUniqueViolation(error)
    if (hostError?.code === 'domain_conflict')
        return new AppRuntimeProblem(409, 'hostNameConflict', 'Proxy host name is unavailable')
    if (hostError?.code === 'discovery_managed')
        return new AppRuntimeProblem(409, 'hostOwnershipConflict', 'Proxy host ownership changed')
    if (hostError?.code === 'proxy_host_not_found')
        return new AppRuntimeProblem(409, 'hostRevisionConflict', 'Proxy host revision changed')
    if (
        hostError?.code === 'invalid_input' ||
        (isAuthDomainError(error) && error.code === 'invalid_input')
    )
        return new AppRuntimeProblem(
            400,
            'invalidHostConfiguration',
            'Proxy host configuration is invalid',
        )
    if (error instanceof ProxyRuntimeSnapshotError || error instanceof z.ZodError)
        return new AppRuntimeProblem(
            409,
            'proxyConfigurationConflict',
            'Proxy configuration could not be validated',
        )
    if (error instanceof CertificateDomainError || error instanceof TrustedCaDomainError) {
        if (error.code === 'controller_unavailable')
            return new AppRuntimeProblem(
                503,
                'proxyValidationUnavailable',
                'Proxy configuration validation unavailable',
            )
        return new AppRuntimeProblem(
            409,
            'hostConfigurationConflict',
            'Proxy host configuration conflicts with its certificate settings',
        )
    }
    return null
}

export async function updateAppOwnedProxyHost(
    credentials: AppRuntimeCredentials,
    raw: AppOwnedProxyHostChange,
    idempotencyKey: string,
    requestId: string,
    signal?: AbortSignal,
): Promise<AppOperation> {
    const parsed = appProxyHostChange.safeParse(raw)
    if (!parsed.success || !appRecordId.safeParse(requestId).success)
        throw new AppRuntimeAuthorityError('invalid_input')
    const input = parsed.data
    signal?.throwIfAborted()
    try {
        return await getAuthDatabase().transaction(async (transaction) => {
            await setAppRuntimeTransactionTimeout(transaction)
            await lockProxyRuntimeSettings(transaction)
            const principal = await resolveAppRuntimePrincipalInTransaction(
                transaction,
                credentials,
            )
            requireAppRuntimeAuthorization(principal, manageOwnedHosts, input.hostId, [
                ownedHostPermission(input),
            ])
            const { installationId, generation } = principal.identity
            const actorUserId = principal.user?.id ?? null
            const payloadHash = digest(JSON.stringify(['change', actorUserId, input]))
            const { keyHash, receipt } = await lockOperationRequest(
                transaction,
                installationId,
                idempotencyKey,
            )
            if (receipt) {
                assertSameOperationRequest(receipt, payloadHash)
                return operationDocument(
                    await readAuthorizedOperation(transaction, principal, receipt.operationId),
                )
            }
            await checkAppOwnedProxyHostChange(transaction, principal, input)
            const pending = await transaction
                .select({ id: appRuntimeOperations.id })
                .from(appRuntimeOperations)
                .where(
                    and(
                        eq(appRuntimeOperations.installationId, installationId),
                        inArray(appRuntimeOperations.status, ['accepted', 'running']),
                    ),
                )
                .limit(maxPendingPerInstallation)
            if (pending.length >= maxPendingPerInstallation)
                throw new AppRuntimeProblem(
                    429,
                    'operationQueueFull',
                    'App operation queue is full',
                )
            signal?.throwIfAborted()
            if (principal.expiresAt.getTime() <= Date.now())
                throw new AppRuntimeAuthorityError('unauthorized')
            const id = randomUUID()
            await transaction.insert(appRuntimeOperations).values({
                id,
                installationId,
                generation,
                requestId,
                actorUserId,
                delegationId: principal.delegationId,
                input: sql`${input}`,
                status: 'accepted',
            })
            await transaction
                .insert(appRuntimeOperationRequests)
                .values({ installationId, keyHash, payloadHash, operationId: id })
            return { id, status: 'accepted' }
        })
    } catch (error) {
        throw hostChangeProblem(error) ?? error
    }
}

export async function getAppOperation(
    credentials: AppRuntimeCredentials,
    operationId: string,
): Promise<AppOperation> {
    return getAuthDatabase().transaction(async (transaction) => {
        await setAppRuntimeTransactionTimeout(transaction)
        const principal = await resolveAppRuntimePrincipalInTransaction(transaction, credentials)
        return operationDocument(await readAuthorizedOperation(transaction, principal, operationId))
    })
}

export async function cancelAppOperation(
    credentials: AppRuntimeCredentials,
    operationId: string,
    idempotencyKey: string,
    requestId: string,
    signal?: AbortSignal,
): Promise<AppOperation> {
    if (!appRecordId.safeParse(requestId).success)
        throw new AppRuntimeAuthorityError('invalid_input')
    signal?.throwIfAborted()
    return getAuthDatabase().transaction(async (transaction) => {
        await setAppRuntimeTransactionTimeout(transaction)
        const principal = await resolveAppRuntimePrincipalInTransaction(transaction, credentials)
        const { installationId } = principal.identity
        const payloadHash = digest(
            JSON.stringify(['cancel', principal.user?.id ?? null, operationId]),
        )
        const { keyHash, receipt } = await lockOperationRequest(
            transaction,
            installationId,
            idempotencyKey,
        )
        const row = await readAuthorizedOperation(transaction, principal, operationId, true)
        if (receipt) {
            assertSameOperationRequest(receipt, payloadHash)
            return operationDocument(row)
        }
        signal?.throwIfAborted()
        if (principal.expiresAt.getTime() <= Date.now())
            throw new AppRuntimeAuthorityError('unauthorized')
        if (row.status === 'accepted')
            await transaction
                .update(appRuntimeOperations)
                .set({ status: 'cancelled' })
                .where(eq(appRuntimeOperations.id, operationId))
        await transaction
            .insert(appRuntimeOperationRequests)
            .values({ installationId, keyHash, payloadHash, operationId })
        return operationDocument(row.status === 'accepted' ? { ...row, status: 'cancelled' } : row)
    })
}

function workerChangeProblem(error: unknown): AppRuntimeProblem | null {
    if (error instanceof AppRuntimeAuthorityError)
        return new AppRuntimeProblem(
            403,
            'operationAuthorizationLost',
            'App operation authorization expired or changed',
        )
    return hostChangeProblem(error)
}

/** Cancellation and the first desired-configuration write race on the same durable row lock. */
async function claimAppProxyOperation(
    signal: AbortSignal,
): Promise<AppOperationWorkerClaim | null> {
    return getAuthDatabase().transaction(async (transaction) => {
        await setAppRuntimeTransactionTimeout(transaction)
        await lockProxyRuntimeSettings(transaction)
        signal.throwIfAborted()
        const [candidate] = await transaction
            .select({
                operation: appRuntimeOperations,
                appId: appRuntimeInstallations.appId,
                uid: appRuntimeInstallations.uid,
                leased: sql<boolean>`coalesce(${appRuntimeOperations.leaseExpiresAt} > clock_timestamp(), false)`,
            })
            .from(appRuntimeOperations)
            .innerJoin(
                appRuntimeInstallations,
                eq(appRuntimeInstallations.id, appRuntimeOperations.installationId),
            )
            .where(inArray(appRuntimeOperations.status, ['running', 'accepted']))
            .orderBy(
                sql`(${appRuntimeOperations.status} = 'running') desc`,
                asc(appRuntimeOperations.createdAt),
                asc(appRuntimeOperations.id),
            )
            .limit(1)
        if (!candidate || candidate.leased) return null
        const { operation, appId, uid } = candidate
        const { id, installationId, generation, delegationId } = operation
        const leaseToken = randomUUID()
        const leaseExpiresAt = sql`clock_timestamp() + ${reconcileLeaseMs} * interval '1 millisecond'`
        const claimed = { id, leaseToken, acceptedAt: operation.createdAt }
        if (operation.status === 'running') {
            const [row] = await transaction
                .update(appRuntimeOperations)
                .set({ leaseToken, leaseExpiresAt })
                .where(
                    and(
                        eq(appRuntimeOperations.id, id),
                        eq(appRuntimeOperations.status, 'running'),
                    ),
                )
                .returning({ id: appRuntimeOperations.id })
            return row ? claimed : null
        }

        try {
            return await transaction.transaction(async (nested) => {
                const identity: AppRuntimeIdentity = { appId, uid, installationId, generation }
                const principal = await refreshAppRuntimePrincipalInTransaction(
                    nested,
                    identity,
                    delegationId,
                )
                if ((principal.user?.id ?? null) !== operation.actorUserId)
                    throw new AppRuntimeAuthorityError('forbidden')
                const [pending] = await nested
                    .select({ id: appRuntimeOperations.id })
                    .from(appRuntimeOperations)
                    .where(
                        and(
                            eq(appRuntimeOperations.id, id),
                            eq(appRuntimeOperations.status, 'accepted'),
                        ),
                    )
                    .for('update')
                if (!pending) return null
                signal.throwIfAborted()
                const result = await applyAppOwnedProxyHostChange(
                    nested,
                    principal,
                    operation.input,
                    id,
                )
                // Roll back invalid desired snapshots before reconciliation can touch the active proxy.
                await readProxyRuntimeSnapshot(nested)
                if (principal.expiresAt.getTime() <= Date.now())
                    throw new AppRuntimeAuthorityError('unauthorized')
                signal.throwIfAborted()
                await nested
                    .update(appRuntimeOperations)
                    .set({
                        status: 'running',
                        leaseToken,
                        leaseExpiresAt,
                        result: sql`${result}`,
                    })
                    .where(eq(appRuntimeOperations.id, id))
                return claimed
            })
        } catch (error) {
            const problem = workerChangeProblem(error)
            if (!problem) throw error
            const failure = failureFields(problem)
            await transaction
                .update(appRuntimeOperations)
                .set({ status: 'failed', failure: sql`${failure}` })
                .where(
                    and(
                        eq(appRuntimeOperations.id, id),
                        eq(appRuntimeOperations.status, 'accepted'),
                    ),
                )
            return null
        }
    })
}

function reconcileWhileRunning(
    reconcile: () => Promise<ProxyRuntimeMutationStatus>,
    signal: AbortSignal,
): Promise<ProxyRuntimeMutationStatus> {
    if (signal.aborted) return Promise.resolve('pending')
    return new Promise((resolve, reject) => {
        const abort = () => resolve('pending')
        signal.addEventListener('abort', abort, { once: true })
        void reconcile()
            .then(resolve, reject)
            .finally(() => signal.removeEventListener('abort', abort))
    })
}

async function reconcileClaim(
    claim: AppOperationWorkerClaim,
    reconcile: () => Promise<ProxyRuntimeMutationStatus>,
    signal: AbortSignal,
): Promise<void> {
    let state: ProxyRuntimeMutationStatus = 'pending'
    try {
        state = await reconcileWhileRunning(reconcile, signal)
    } finally {
        const failure = failureFields(reconcileUnconfirmed)
        const confirmationExpired =
            state === 'pending' &&
            !signal.aborted &&
            claim.acceptedAt.getTime() + reconcileConfirmationMs <= Date.now()
        await getBackgroundDatabase('critical').transaction(async (transaction) => {
            await setAppRuntimeTransactionTimeout(transaction)
            await transaction
                .update(appRuntimeOperations)
                .set({
                    leaseToken: null,
                    leaseExpiresAt: null,
                    ...(state === 'applied' && { status: 'succeeded' as const }),
                    ...(confirmationExpired && {
                        status: 'failed' as const,
                        failure: sql`${failure}`,
                    }),
                })
                .where(
                    and(
                        eq(appRuntimeOperations.id, claim.id),
                        eq(appRuntimeOperations.leaseToken, claim.leaseToken),
                    ),
                )
        })
    }
}

/** Poll from persistent state so process restarts resume both accepted and committed work. */
export function createAppProxyOperationWorker(
    reconcile: () => Promise<ProxyRuntimeMutationStatus> = reconcileProxyConfigurationService,
) {
    const controller = new AbortController()
    let timer: ReturnType<typeof setTimeout> | undefined
    let flight: Promise<void> | undefined
    let started = false

    async function run() {
        const claim = await withBackgroundDatabaseContext(
            () => claimAppProxyOperation(controller.signal),
            controller.signal,
            'critical',
        )
        if (claim) await reconcileClaim(claim, reconcile, controller.signal)
    }

    function tick() {
        if (controller.signal.aborted) return
        flight = run()
            .catch(() => {
                if (!controller.signal.aborted)
                    console.warn('[app-runtime] Proxy operation worker temporarily unavailable')
            })
            .finally(() => {
                flight = undefined
                if (!controller.signal.aborted) {
                    timer = setTimeout(tick, pollIntervalMs)
                    timer.unref?.()
                }
            })
    }

    return {
        start() {
            if (started) return
            started = true
            tick()
        },
        async stop() {
            controller.abort()
            if (timer !== undefined) clearTimeout(timer)
            await flight
        },
    }
}
