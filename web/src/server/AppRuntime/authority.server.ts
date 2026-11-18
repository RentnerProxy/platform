import '@tanstack/react-start/server-only'

import { and, asc, eq, inArray, sql } from 'drizzle-orm'

import { ACTIVE_OWNER_ADVISORY_LOCK_ID } from '@/config/auth.config.ts'
import { PERMISSIONS } from '@/config/permissions.config.ts'
import {
    appRuntimeDelegations,
    appRuntimeGenerations,
    appRuntimeGrants,
    appRuntimeInstallations,
    appRuntimeRolePermissions,
    appRuntimeSecrets,
    roles,
    sessions,
    userRoles,
    users,
} from '@/db/schema.ts'
import {
    hasOwnerRole,
    resolveActiveUserAccessInTransaction,
} from '@/server/Auth/Access/rbac.service.ts'
import type { AuthTransaction } from '@/server/Auth/Core/Types/database.types.ts'
import { decryptSecret, encryptSecret } from '@/server/Auth/Core/encryption.server.ts'
import {
    createOpaqueToken,
    hashOpaqueToken,
    isValidOpaqueToken,
} from '@/server/Auth/Core/tokens.server.ts'
import { isOidcSessionValidInTransaction } from '@/server/Auth/Oidc/oidc-session.server.ts'
import {
    APP_RUNTIME_SUPPORT_CAPABILITIES,
    isAppRuntimeAuthorized,
    isAppRuntimeSupportCapability,
    qualifyAppRuntimePermission,
} from './authority-policy.server.ts'
import {
    appCapabilitySchema,
    appIdSchema,
    appGenerationSchema,
    appRecordId,
    appUidSchema,
} from './contract.ts'
import {
    AppRuntimeAuthorityError,
    type AppRuntimeCredentials,
    type AppRuntimeIdentity,
    type AppRuntimePrincipal,
} from './Types/authority.types.ts'

export {
    APP_RUNTIME_SUPPORT_CAPABILITIES,
    isAppRuntimeAuthorized,
    qualifyAppRuntimePermission,
    requireAppRuntimeAuthorization,
    requireAppRuntimePermission,
} from './authority-policy.server.ts'

const appRuntimeProfile = 'rentnerproxy-linux-v1'
const appRuntimeVersion = '1.0.0'
const delegationLifetimeMs = 15 * 60 * 1000

export function isAppRuntimeIdentity(identity: AppRuntimeIdentity): boolean {
    return (
        appIdSchema.safeParse(identity.appId).success &&
        appRecordId.safeParse(identity.installationId).success &&
        appGenerationSchema.safeParse(identity.generation).success &&
        appUidSchema.safeParse(identity.uid).success
    )
}

export async function lockAppRuntimeInstallation(
    transaction: AuthTransaction,
    identity: AppRuntimeIdentity,
    write = false,
) {
    if (!isAppRuntimeIdentity(identity)) throw new AppRuntimeAuthorityError('unauthorized')

    const [installation] = await transaction
        .select()
        .from(appRuntimeInstallations)
        .where(eq(appRuntimeInstallations.id, identity.installationId))
        .for(write ? 'update' : 'share')
    if (installation?.appId !== identity.appId || installation.uid !== identity.uid)
        throw new AppRuntimeAuthorityError('unauthorized')
    return installation
}

async function readAppRuntimeGeneration(
    transaction: AuthTransaction,
    identity: AppRuntimeIdentity,
    { allowPreparing = false, write = false } = {},
) {
    const installation = await lockAppRuntimeInstallation(transaction, identity, write)
    const [generation] = await transaction
        .select()
        .from(appRuntimeGenerations)
        .where(
            and(
                eq(appRuntimeGenerations.installationId, identity.installationId),
                eq(appRuntimeGenerations.generation, identity.generation),
            ),
        )
    if (
        !generation ||
        generation.leaseExpiresAt.getTime() <= Date.now() ||
        (generation.state !== 'active' && !(allowPreparing && generation.state === 'preparing'))
    )
        throw new AppRuntimeAuthorityError('unauthorized')
    return { ...generation, authorizationEpoch: installation.authorizationEpoch }
}

async function readGrants(
    transaction: AuthTransaction,
    generation: typeof appRuntimeGenerations.$inferSelect,
) {
    const rows = await transaction
        .select()
        .from(appRuntimeGrants)
        .where(eq(appRuntimeGrants.installationId, generation.installationId))
        .orderBy(
            asc(appRuntimeGrants.capabilityId),
            asc(appRuntimeGrants.scope),
            asc(appRuntimeGrants.resourceId),
        )
    return rows.flatMap(({ capabilityId, scope, resourceId, allowService, permissionKey }) => {
        const capability = { id: capabilityId, scope }
        if (
            (!generation.capabilities.includes(capabilityId) ||
                !appCapabilitySchema.safeParse(capability).success) &&
            !isAppRuntimeSupportCapability(capability)
        )
            return []
        if (permissionKey !== null && !generation.permissionKeys.includes(permissionKey)) return []
        return [
            {
                capability,
                resourceId,
                allowService,
                ...(permissionKey === null ? {} : { permissionKey }),
            },
        ]
    })
}

export async function readAppRuntimeLeaseInTransaction(
    transaction: AuthTransaction,
    identity: AppRuntimeIdentity,
): Promise<{ expiresAt: number }> {
    const generation = await readAppRuntimeGeneration(transaction, identity, {
        allowPreparing: true,
    })
    return { expiresAt: generation.leaseExpiresAt.getTime() }
}

export async function readAppRuntimeContextInTransaction(
    transaction: AuthTransaction,
    identity: AppRuntimeIdentity,
) {
    const generation = await readAppRuntimeGeneration(transaction, identity, {
        allowPreparing: true,
    })
    const grants = await readGrants(transaction, generation)
    const capabilities = new Map(
        grants
            .filter(({ capability }) => !isAppRuntimeSupportCapability(capability))
            .map(({ capability }) => [capability.id, capability]),
    )

    if (generation.leaseExpiresAt.getTime() <= Date.now())
        throw new AppRuntimeAuthorityError('unauthorized')
    return {
        appId: identity.appId,
        installationId: identity.installationId,
        generation: identity.generation,
        runtimeProfile: appRuntimeProfile,
        versions: {
            appProtocol: appRuntimeVersion,
            platformApi: appRuntimeVersion,
            ...(generation.hasUi ? { uiBridge: appRuntimeVersion } : {}),
        },
        capabilities: [...capabilities.values()],
    }
}

export async function lockAppRuntimeUserPolicy(transaction: AuthTransaction): Promise<void> {
    // User/role assignment and OIDC trust changes use the exclusive form of this lock.
    await transaction.execute(
        sql`select pg_advisory_xact_lock_shared(${ACTIVE_OWNER_ADVISORY_LOCK_ID})`,
    )
}

async function resolveAppRuntimeSession(transaction: AuthTransaction, sessionId: string) {
    const [sessionOwner] = await transaction
        .select({ userId: sessions.userId })
        .from(sessions)
        .where(eq(sessions.id, sessionId))
    if (!sessionOwner) throw new AppRuntimeAuthorityError('unauthorized')

    // Lock in the same order as authentication updates and session revocation.
    const [user] = await transaction
        .select({ status: users.status, oidcProviderId: users.oidcProviderId })
        .from(users)
        .where(eq(users.id, sessionOwner.userId))
        .for('share')
    if (user?.status !== 'active') throw new AppRuntimeAuthorityError('unauthorized')
    const roleRows = await transaction
        .select({ roleId: userRoles.roleId })
        .from(userRoles)
        .where(eq(userRoles.userId, sessionOwner.userId))
        .orderBy(asc(userRoles.roleId))
    const roleIds = roleRows.map(({ roleId }) => roleId)
    // Role editing takes an exclusive row lock before rewriting its permissions.
    if (roleIds.length > 0)
        await transaction
            .select({ id: roles.id })
            .from(roles)
            .where(inArray(roles.id, roleIds))
            .orderBy(asc(roles.id))
            .for('share')
    const [session] = await transaction
        .select()
        .from(sessions)
        .where(and(eq(sessions.id, sessionId), eq(sessions.userId, sessionOwner.userId)))
        .for('share')
    if (!session || session.expiresAt.getTime() <= Date.now())
        throw new AppRuntimeAuthorityError('unauthorized')

    const actor = await resolveActiveUserAccessInTransaction(transaction, session.userId)
    if (
        !actor?.permissions.includes(PERMISSIONS.APP_ACCESS) ||
        (user.oidcProviderId !== null && !session.oidcProof) ||
        (session.oidcProof !== null &&
            !(await isOidcSessionValidInTransaction(
                transaction,
                session.oidcProof,
                session.userId,
                user.oidcProviderId,
                actor.roles,
            )))
    )
        throw new AppRuntimeAuthorityError('unauthorized')

    return { actor, roleIds, session }
}

async function readAppPermissions(
    transaction: AuthTransaction,
    identity: AppRuntimeIdentity,
    declaredKeys: readonly string[],
    actor: Awaited<ReturnType<typeof resolveAppRuntimeSession>>['actor'],
    roleIds: string[],
): Promise<string[]> {
    const rows =
        !hasOwnerRole(actor.roles) && roleIds.length > 0 && declaredKeys.length > 0
            ? await transaction
                  .select({ key: appRuntimeRolePermissions.key })
                  .from(appRuntimeRolePermissions)
                  .where(
                      and(
                          eq(appRuntimeRolePermissions.installationId, identity.installationId),
                          inArray(appRuntimeRolePermissions.roleId, roleIds),
                      ),
                  )
            : []
    const assigned = new Set(rows.map(({ key }) => key))
    const keys = hasOwnerRole(actor.roles)
        ? declaredKeys
        : declaredKeys.filter((key) => assigned.has(key))
    return keys.map((key) => qualifyAppRuntimePermission(identity.appId, key)).toSorted()
}

async function readPrincipal(
    transaction: AuthTransaction,
    identity: AppRuntimeIdentity,
    delegation: { id: string } | { tokenHash: string } | null,
): Promise<AppRuntimePrincipal> {
    if (delegation !== null) await lockAppRuntimeUserPolicy(transaction)
    const generation = await readAppRuntimeGeneration(transaction, identity)
    const grants = await readGrants(transaction, generation)
    if (delegation === null) {
        if (generation.leaseExpiresAt.getTime() <= Date.now())
            throw new AppRuntimeAuthorityError('unauthorized')
        return {
            kind: 'service',
            identity,
            expiresAt: generation.leaseExpiresAt,
            grants,
            authorizationEpoch: generation.authorizationEpoch,
            user: null,
            delegationId: null,
            sessionId: null,
            permissions: [],
            appPermissions: [],
        }
    }

    const selector =
        'id' in delegation
            ? eq(appRuntimeDelegations.id, delegation.id)
            : eq(appRuntimeDelegations.tokenHash, delegation.tokenHash)
    const target = and(
        selector,
        eq(appRuntimeDelegations.installationId, identity.installationId),
        eq(appRuntimeDelegations.generation, identity.generation),
    )
    const [sessionBinding] = await transaction
        .select({ sessionId: appRuntimeDelegations.sessionId })
        .from(appRuntimeDelegations)
        .where(target)
    if (!sessionBinding) throw new AppRuntimeAuthorityError('unauthorized')

    const { actor, roleIds, session } = await resolveAppRuntimeSession(
        transaction,
        sessionBinding.sessionId,
    )
    const [binding] = await transaction
        .select()
        .from(appRuntimeDelegations)
        .where(target)
        .for('share')
    if (!binding || binding.sessionId !== session.id)
        throw new AppRuntimeAuthorityError('unauthorized')
    const appPermissions = await readAppPermissions(
        transaction,
        identity,
        generation.permissionKeys,
        actor,
        roleIds,
    )
    const expiresAt = new Date(
        Math.min(
            binding.expiresAt.getTime(),
            generation.leaseExpiresAt.getTime(),
            session.expiresAt.getTime(),
        ),
    )
    if (expiresAt.getTime() <= Date.now()) throw new AppRuntimeAuthorityError('unauthorized')
    return {
        kind: 'user',
        identity,
        expiresAt,
        grants,
        authorizationEpoch: generation.authorizationEpoch,
        user: actor,
        delegationId: binding.id,
        sessionId: session.id,
        permissions: actor.permissions,
        appPermissions,
    }
}

export async function resolveAppRuntimePrincipalInTransaction(
    transaction: AuthTransaction,
    credentials: AppRuntimeCredentials,
): Promise<AppRuntimePrincipal> {
    const { identity, delegation } = credentials
    if (delegation === undefined) return readPrincipal(transaction, identity, null)
    if (!isValidOpaqueToken(delegation)) throw new AppRuntimeAuthorityError('unauthorized')
    return readPrincipal(transaction, identity, { tokenHash: await hashOpaqueToken(delegation) })
}

export function refreshAppRuntimePrincipalInTransaction(
    transaction: AuthTransaction,
    identity: AppRuntimeIdentity,
    delegationId: string | null,
): Promise<AppRuntimePrincipal> {
    if (delegationId !== null && !uuidPattern.test(delegationId))
        throw new AppRuntimeAuthorityError('unauthorized')
    return readPrincipal(transaction, identity, delegationId === null ? null : { id: delegationId })
}

const uuidPattern = /^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$/i

export async function issueAppRuntimeDelegationInTransaction(
    transaction: AuthTransaction,
    identity: AppRuntimeIdentity,
    sessionId: string,
    requestedExpiresAt?: Date,
): Promise<string> {
    if (!uuidPattern.test(sessionId)) throw new AppRuntimeAuthorityError('invalid_input')
    await lockAppRuntimeUserPolicy(transaction)
    const generation = await readAppRuntimeGeneration(transaction, identity)
    const { session } = await resolveAppRuntimeSession(transaction, sessionId)
    const now = Date.now()
    if (generation.leaseExpiresAt.getTime() <= now)
        throw new AppRuntimeAuthorityError('unauthorized')
    const expiresAt = new Date(
        Math.min(
            now + delegationLifetimeMs,
            session.expiresAt.getTime(),
            requestedExpiresAt?.getTime() ?? Infinity,
        ),
    )
    if (!Number.isFinite(expiresAt.getTime()) || expiresAt.getTime() <= now)
        throw new AppRuntimeAuthorityError('invalid_input')

    const token = createOpaqueToken()
    await transaction.insert(appRuntimeDelegations).values({
        expiresAt,
        sessionId,
        installationId: identity.installationId,
        generation: identity.generation,
        tokenHash: await hashOpaqueToken(token),
    })
    return token
}

function secretContext(installationId: string, secretId: string): string {
    return `app-runtime-secret:v1:${installationId}:${secretId}`
}

export async function putAppRuntimeSecretInTransaction(
    transaction: AuthTransaction,
    identity: AppRuntimeIdentity,
    secretId: string,
    value: string,
): Promise<void> {
    if (!appRecordId.safeParse(secretId).success || value.length === 0 || value.length > 16_384)
        throw new AppRuntimeAuthorityError('invalid_input')
    await readAppRuntimeGeneration(transaction, identity, { allowPreparing: true, write: true })
    const { installationId } = identity
    const { ciphertext, iv } = await encryptSecret(value, secretContext(installationId, secretId))
    await transaction
        .insert(appRuntimeSecrets)
        .values({ installationId, id: secretId, ciphertext, iv })
        .onConflictDoUpdate({
            target: [appRuntimeSecrets.installationId, appRuntimeSecrets.id],
            set: { ciphertext, iv },
        })
}

export async function deleteAppRuntimeSecretInTransaction(
    transaction: AuthTransaction,
    identity: AppRuntimeIdentity,
    secretId: string,
): Promise<void> {
    if (!appRecordId.safeParse(secretId).success)
        throw new AppRuntimeAuthorityError('invalid_input')
    await readAppRuntimeGeneration(transaction, identity, { allowPreparing: true, write: true })
    await transaction
        .delete(appRuntimeSecrets)
        .where(
            and(
                eq(appRuntimeSecrets.installationId, identity.installationId),
                eq(appRuntimeSecrets.id, secretId),
            ),
        )
}

export async function readAppRuntimeSecretInTransaction(
    transaction: AuthTransaction,
    principal: AppRuntimePrincipal,
    secretId: string,
): Promise<{ value: string }> {
    if (!isAppRuntimeAuthorized(principal, APP_RUNTIME_SUPPORT_CAPABILITIES.secret, secretId))
        throw new AppRuntimeAuthorityError('not_found')
    const { installationId } = principal.identity
    const [secret] = await transaction
        .select()
        .from(appRuntimeSecrets)
        .where(
            and(
                eq(appRuntimeSecrets.installationId, installationId),
                eq(appRuntimeSecrets.id, secretId),
            ),
        )
    if (!secret) throw new AppRuntimeAuthorityError('not_found')
    const value = await decryptSecret(secret, secretContext(installationId, secretId))
    if (principal.expiresAt.getTime() <= Date.now())
        throw new AppRuntimeAuthorityError('unauthorized')
    return { value }
}
