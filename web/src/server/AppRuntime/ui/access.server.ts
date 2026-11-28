import '@tanstack/react-start/server-only'

import type { AppUiPayload, AppUiSummary } from '@/lib/AppUi/contract.ts'
import type { AuthTransaction } from '@/server/Auth/Core/Types/database.types.ts'
import {
    isAppRuntimeAuthorized,
    qualifyAppRuntimePermission,
    readAppUiActorInTransaction,
    readAppUiPrincipalInTransaction,
    requireAppRuntimeAuthorization,
    requireAppRuntimePermission,
} from '../authority.server.ts'
import { appRecordId } from '../contract.ts'
import { appRuntimeTransaction, withAppRuntimeErrors } from '../services.server.ts'
import { AppRuntimeAuthorityError, type AppRuntimeIdentity } from '../Types/authority.types.ts'
import { resolveNativePresentation } from './native-presentation.server.ts'
import {
    appUiEnabled,
    nativeAppUi,
    nativeAppUis,
    nativeAppUiCall,
    nativeAppUiPolicy,
    uiProblems,
    type AppUiCallInput,
    type AppUiOperationPolicy,
    type NativeAppUi,
} from './transport.server.ts'

type AppUiBinding = Pick<NativeAppUi, 'installationId' | 'generation'>
type AppUiActor = Awaited<ReturnType<typeof readAppUiActorInTransaction>>

async function summarize(
    transaction: AuthTransaction,
    app: NativeAppUi,
    actor: AppUiActor,
): Promise<AppUiSummary | null> {
    try {
        const principal = await readAppUiPrincipalInTransaction(transaction, app, actor)
        const { appId, installationId, generation, name, slots, routes, dialogs, events } = app
        return {
            appId,
            installationId,
            generation,
            name,
            slots,
            routes,
            dialogs,
            events,
            ...(resolveNativePresentation(app) && { native: true as const }),
            permissionKeys: app.permissionKeys.filter((key) =>
                principal.appPermissions.includes(qualifyAppRuntimePermission(appId, key)),
            ),
        }
    } catch (error) {
        if (error instanceof AppRuntimeAuthorityError) return null
        throw error
    }
}

export async function listAuthorizedAppUis(
    sessionId: string,
    signal: AbortSignal,
): Promise<AppUiSummary[]> {
    if (!appUiEnabled()) return []
    try {
        const apps = await nativeAppUis(signal)
        if (apps.length === 0) return []
        return await appRuntimeTransaction(signal, async (transaction) => {
            const actor = await readAppUiActorInTransaction(transaction, sessionId)
            const visible: AppUiSummary[] = []
            for (const app of apps) {
                // oxlint-disable-next-line no-await-in-loop -- Keep installation locks ordered on one connection.
                const summary = await summarize(transaction, app, actor)
                if (summary) visible.push(summary)
            }
            return visible
        })
    } catch {
        return []
    }
}

export async function activeAppUi(
    binding: AppUiBinding,
    signal: AbortSignal,
): Promise<NativeAppUi> {
    if (!appUiEnabled()) throw uiProblems.missing
    const found = await nativeAppUi(binding, signal).catch((error: unknown) => {
        if (error === uiProblems.missing) throw uiProblems.stale
        throw error
    })
    if (found.installationId !== binding.installationId || found.generation !== binding.generation)
        throw uiProblems.stale
    return found
}

export function authorizeAppUi(
    sessionId: string,
    app: AppRuntimeIdentity,
    signal: AbortSignal,
    policy?: AppUiOperationPolicy,
    payload?: AppUiCallInput['payload'],
): Promise<readonly string[]> {
    return withAppRuntimeErrors(() =>
        appRuntimeTransaction(signal, async (transaction) => {
            const actor = await readAppUiActorInTransaction(transaction, sessionId)
            const principal = await readAppUiPrincipalInTransaction(
                transaction,
                app,
                actor,
                policy?.resource !== undefined,
            )
            if (policy) requireAppUiOperation(principal, policy, payload)
            return principal.appPermissions
        }),
    )
}

type AppUiOperationPrincipal = Parameters<typeof requireAppRuntimePermission>[0] &
    Parameters<typeof requireAppRuntimeAuthorization>[0]

/** The operation permission and, when declared, the requested resource. */
function requireAppUiOperation(
    principal: AppUiOperationPrincipal,
    policy: AppUiOperationPolicy,
    payload?: AppUiCallInput['payload'],
) {
    requireAppRuntimePermission(principal, policy.permissionKey)
    if (!policy.resource) return
    const { resourceIdField, capability } = policy.resource
    const resourceId = appRecordId.safeParse(
        payload && Object.hasOwn(payload, resourceIdField) ? payload[resourceIdField] : undefined,
    )
    if (!resourceId.success) throw uiProblems.invalid
    requireAppRuntimeAuthorization(principal, capability, resourceId.data)
}

export async function executeAppUiCall(
    sessionId: string,
    input: AppUiCallInput,
    expected: Pick<AppRuntimeIdentity, 'appId' | 'uid'>,
    signal: AbortSignal,
) {
    const app = await activeAppUi(input, signal)
    if (app.appId !== expected.appId || app.uid !== expected.uid) throw uiProblems.frameRevoked
    const policy = await nativeAppUiPolicy(input, signal)
    await authorizeAppUi(sessionId, app, signal, policy, input.payload)
    const result = await nativeAppUiCall(input, signal)
    if (!policy.results) {
        await authorizeAppUi(sessionId, app, signal, policy, input.payload)
        return result
    }
    return authorizeAndFilterAppUiResult(sessionId, app, signal, policy, policy.results, {
        payload: input.payload,
        result,
    })
}

type AppUiResultsPolicy = NonNullable<AppUiOperationPolicy['results']>
type AppUiResultsPrincipal = Parameters<typeof isAppRuntimeAuthorized>[0]

/**
 * Keeps only the list items the principal may see. Anything but a plain object that holds the
 * declared list (plus an optional `nextCursor`) fails closed so an app cannot leak aggregates.
 */
export function filterAppUiResult(
    principal: AppUiResultsPrincipal,
    results: AppUiResultsPolicy,
    result: unknown,
): AppUiPayload {
    if (result === null || typeof result !== 'object' || Array.isArray(result))
        throw uiProblems.invalid
    const body = result as Record<string, unknown>
    const { listField, resourceIdField, capability } = results
    const keys = Object.keys(body)
    if (
        !Object.hasOwn(body, listField) ||
        keys.some((key) => key !== listField && key !== 'nextCursor')
    )
        throw uiProblems.invalid
    const items: unknown = body[listField]
    if (!Array.isArray(items)) throw uiProblems.invalid
    const visible = items.filter((item: unknown) => {
        if (item === null || typeof item !== 'object' || Array.isArray(item)) return false
        const id = appRecordId.safeParse(
            Object.hasOwn(item, resourceIdField)
                ? (item as Record<string, unknown>)[resourceIdField]
                : undefined,
        )
        return id.success && isAppRuntimeAuthorized(principal, capability, id.data)
    })
    return {
        [listField]: visible,
        ...(Object.hasOwn(body, 'nextCursor') && { nextCursor: body.nextCursor }),
    } as AppUiPayload
}

/**
 * The final check after the app answered and the filter run in one transaction: a permission,
 * resource or grant revoked after the call withholds or filters the answer, with no gap between.
 */
function authorizeAndFilterAppUiResult(
    sessionId: string,
    app: AppRuntimeIdentity,
    signal: AbortSignal,
    policy: AppUiOperationPolicy,
    results: AppUiResultsPolicy,
    { payload, result }: { payload: AppUiCallInput['payload']; result: unknown },
): Promise<AppUiPayload> {
    return withAppRuntimeErrors(() =>
        appRuntimeTransaction(signal, async (transaction) => {
            const actor = await readAppUiActorInTransaction(transaction, sessionId)
            const principal = await readAppUiPrincipalInTransaction(transaction, app, actor, true)
            requireAppUiOperation(principal, policy, payload)
            return filterAppUiResult(principal, results, result)
        }),
    )
}
