import '@tanstack/react-start/server-only'

import { z } from 'zod'

import {
    deleteAppRuntimeSecretInTransaction,
    putAppRuntimeSecretInTransaction,
    readAppRuntimeLeaseInTransaction,
} from './authority.server.ts'
import {
    appCapabilitySchema,
    appGenerationSchema,
    appIdSchema,
    appProviderProfilesSchema,
    appProviderRegistrationsSchema,
    appRecordId,
    appUidSchema,
} from './contract.ts'
import {
    activateAppRuntimeGenerationInTransaction,
    checkAppRuntimeDependenciesInTransaction,
    recordAppRuntimeProvidersInTransaction,
    registerAppRuntimeGenerationInTransaction,
    renewAppRuntimeGenerationLeaseInTransaction,
    replaceAppRuntimeGrantsInTransaction,
    revokeAppRuntimeGenerationInTransaction,
    setAppRuntimeRolePermissionInTransaction,
} from './lifecycle.server.ts'
import { AppRuntimeProblem } from './problem.ts'
import { appRuntimeTransaction, parseAppInput, withAppRuntimeErrors } from './services.server.ts'

const identitySchema = z.strictObject({
    appId: appIdSchema,
    installationId: appRecordId,
    generation: appGenerationSchema,
    uid: appUidSchema,
})
const leaseDeadlineSchema = z.iso.datetime({ precision: 3 }).transform((value) => new Date(value))
const generationRequest = z.strictObject({ identity: identitySchema })
const lease = z.strictObject({ identity: identitySchema, leaseExpiresAt: leaseDeadlineSchema })
const permissionKeySchema = z.string().regex(/^[a-z][a-z0-9-]{0,31}$/u)
const registration = lease.extend({
    capabilities: z.array(appCapabilitySchema).max(32),
    permissionKeys: z.array(permissionKeySchema).max(64).optional(),
    providerProfiles: appProviderProfilesSchema.default([]),
    hasUi: z.boolean().optional(),
})
const providerUpdate = z.strictObject({
    identity: identitySchema,
    providers: appProviderRegistrationsSchema,
})
const grantUpdate = z.strictObject({
    identity: identitySchema,
    grants: z
        .array(
            z.strictObject({
                capability: z.strictObject({
                    id: z.string().min(1).max(64),
                    scope: z.string().min(1).max(32),
                }),
                resourceId: appRecordId,
                allowService: z.boolean(),
                permissionKey: permissionKeySchema.optional(),
            }),
        )
        .max(256),
})
const roleUpdate = z.strictObject({
    identity: identitySchema,
    roleId: z.uuid(),
    permissionKey: permissionKeySchema,
    allowed: z.boolean(),
})
const secretReference = z.strictObject({ identity: identitySchema, secretId: appRecordId })
const secretUpdate = secretReference.extend({ value: z.string().min(1).max(16_384) })
// The removal check aborts legacy handoffs, whose domain locks require read committed.
const readCommitted = { isolationLevel: 'read committed' } as const

/** These controls are reachable only on the platform-owned bridge, outside the app route allowlist. */
export function manageAppRuntime(action: string, body: unknown, signal: AbortSignal) {
    return withAppRuntimeErrors(async () => {
        const result = await appRuntimeTransaction(signal, async (transaction) => {
            switch (action) {
                case 'lease': {
                    const input = parseAppInput(generationRequest, body)
                    return readAppRuntimeLeaseInTransaction(transaction, input.identity)
                }
                case 'register': {
                    const {
                        identity,
                        leaseExpiresAt,
                        capabilities,
                        permissionKeys,
                        providerProfiles,
                        hasUi,
                    } = parseAppInput(registration, body)
                    return registerAppRuntimeGenerationInTransaction(transaction, {
                        identity,
                        leaseExpiresAt,
                        capabilities,
                        providerProfiles,
                        ...(permissionKeys !== undefined && { permissionKeys }),
                        ...(hasUi !== undefined && { hasUi }),
                    })
                }
                case 'providers': {
                    const input = parseAppInput(providerUpdate, body)
                    return recordAppRuntimeProvidersInTransaction(
                        transaction,
                        input.identity,
                        input.providers,
                    )
                }
                case 'activate':
                case 'renew': {
                    const input = parseAppInput(lease, body)
                    const update =
                        action === 'activate'
                            ? activateAppRuntimeGenerationInTransaction
                            : renewAppRuntimeGenerationLeaseInTransaction
                    return update(transaction, input.identity, input.leaseExpiresAt)
                }
                case 'workers-stopped':
                case 'removable':
                case 'purge-data': {
                    const { identity } = parseAppInput(generationRequest, body)
                    return checkAppRuntimeDependenciesInTransaction(transaction, identity, action)
                }
                case 'revoke':
                case 'retire': {
                    const input = parseAppInput(generationRequest, body)
                    return revokeAppRuntimeGenerationInTransaction(
                        transaction,
                        input.identity,
                        action === 'retire',
                    )
                }
                case 'grants': {
                    const { identity, grants } = parseAppInput(grantUpdate, body)
                    return replaceAppRuntimeGrantsInTransaction(
                        transaction,
                        identity,
                        grants.map(({ permissionKey, ...grant }) =>
                            Object.assign(
                                grant,
                                permissionKey === undefined ? undefined : { permissionKey },
                            ),
                        ),
                    )
                }
                case 'role-permission': {
                    const input = parseAppInput(roleUpdate, body)
                    return setAppRuntimeRolePermissionInTransaction(
                        transaction,
                        input.identity,
                        input.roleId,
                        input.permissionKey,
                        input.allowed,
                    )
                }
                case 'put-secret': {
                    const input = parseAppInput(secretUpdate, body)
                    return putAppRuntimeSecretInTransaction(
                        transaction,
                        input.identity,
                        input.secretId,
                        input.value,
                    )
                }
                case 'delete-secret': {
                    const input = parseAppInput(secretReference, body)
                    return deleteAppRuntimeSecretInTransaction(
                        transaction,
                        input.identity,
                        input.secretId,
                    )
                }
                default:
                    throw new AppRuntimeProblem(
                        404,
                        'notFound',
                        'App management operation was not found.',
                    )
            }
        }, readCommitted)
        const headers = { 'Cache-Control': 'no-store' }
        if (result !== undefined) return Response.json(result, { headers })
        return new Response(null, { status: 204, headers })
    })
}
