import '@tanstack/react-start/server-only'

import { and, desc, eq, ne, sql } from 'drizzle-orm'

import { ACTIVE_OWNER_ADVISORY_LOCK_ID } from '@/config/auth.config.ts'
import {
    appRuntimeDelegations,
    appRuntimeGenerations,
    appRuntimeGrants,
    appRuntimeInstallations,
    appRuntimeRolePermissions,
    roles,
} from '@/db/schema.ts'
import type { AuthTransaction } from '@/server/Auth/Core/Types/database.types.ts'
import {
    isAppRuntimeGrantTarget,
    isAppRuntimeSupportCapability,
    isLocalAppRuntimePermissionKey,
} from './authority-policy.server.ts'
import { isAppRuntimeIdentity, lockAppRuntimeInstallation } from './authority.server.ts'
import { appCapabilitySchema } from './contract.ts'
import {
    AppRuntimeAuthorityError,
    type AppRuntimeGrant,
    type AppRuntimeIdentity,
    type AppRuntimeRegistration,
} from './Types/authority.types.ts'

const maxGrants = 256
const maxLeaseLifetimeMs = 5 * 60 * 1000

function assertLeaseDeadline(leaseExpiresAt: Date, now: number): void {
    const deadline = leaseExpiresAt.getTime()
    if (!Number.isFinite(deadline) || deadline <= now || deadline > now + maxLeaseLifetimeMs)
        throw new AppRuntimeAuthorityError('invalid_input')
}

async function bumpAuthorizationEpoch(
    transaction: AuthTransaction,
    installationId: string,
): Promise<void> {
    await transaction
        .update(appRuntimeInstallations)
        .set({ authorizationEpoch: sql`${appRuntimeInstallations.authorizationEpoch} + 1` })
        .where(eq(appRuntimeInstallations.id, installationId))
}

async function loadLockedGeneration(transaction: AuthTransaction, identity: AppRuntimeIdentity) {
    await lockAppRuntimeInstallation(transaction, identity, true)
    const [generation] = await transaction
        .select()
        .from(appRuntimeGenerations)
        .where(
            and(
                eq(appRuntimeGenerations.installationId, identity.installationId),
                eq(appRuntimeGenerations.generation, identity.generation),
            ),
        )
    if (!generation) throw new AppRuntimeAuthorityError('not_found')
    return generation
}

export async function registerAppRuntimeGenerationInTransaction(
    transaction: AuthTransaction,
    registration: AppRuntimeRegistration,
): Promise<void> {
    const {
        identity,
        leaseExpiresAt,
        capabilities,
        permissionKeys = [],
        hasUi = false,
    } = registration
    if (
        !isAppRuntimeIdentity(identity) ||
        capabilities.length > 32 ||
        !capabilities.every((capability) => appCapabilitySchema.safeParse(capability).success) ||
        new Set(capabilities.map(({ id }) => id)).size !== capabilities.length ||
        permissionKeys.length > 64 ||
        !permissionKeys.every(isLocalAppRuntimePermissionKey) ||
        new Set(permissionKeys).size !== permissionKeys.length
    )
        throw new AppRuntimeAuthorityError('invalid_input')

    const { installationId, appId, uid, generation } = identity
    await transaction
        .insert(appRuntimeInstallations)
        .values({ id: installationId, appId, uid })
        .onConflictDoNothing()
    await lockAppRuntimeInstallation(transaction, identity, true)
    const [previous] = await transaction
        .select()
        .from(appRuntimeGenerations)
        .where(eq(appRuntimeGenerations.installationId, installationId))
        .orderBy(desc(appRuntimeGenerations.generation))
        .limit(1)
    const declaredCapabilities = capabilities.map(({ id }) => id).toSorted()
    const declaredPermissions = permissionKeys.toSorted()
    const now = Date.now()
    if (previous && previous.generation >= generation) {
        if (
            previous.generation === generation &&
            previous.state !== 'revoked' &&
            previous.leaseExpiresAt.getTime() > now &&
            previous.hasUi === hasUi &&
            JSON.stringify(previous.capabilities) === JSON.stringify(declaredCapabilities) &&
            JSON.stringify(previous.permissionKeys) === JSON.stringify(declaredPermissions)
        )
            return
        throw new AppRuntimeAuthorityError('conflict')
    }
    assertLeaseDeadline(leaseExpiresAt, now)

    await transaction
        .update(appRuntimeGenerations)
        .set({ state: 'revoked' })
        .where(
            and(
                eq(appRuntimeGenerations.installationId, installationId),
                eq(appRuntimeGenerations.state, 'preparing'),
            ),
        )
    await transaction.insert(appRuntimeGenerations).values({
        installationId,
        generation,
        leaseExpiresAt,
        state: 'preparing',
        capabilities: declaredCapabilities,
        permissionKeys: declaredPermissions,
        hasUi,
    })
}

export async function activateAppRuntimeGenerationInTransaction(
    transaction: AuthTransaction,
    identity: AppRuntimeIdentity,
    leaseExpiresAt: Date,
): Promise<void> {
    const candidate = await loadLockedGeneration(transaction, identity)
    const now = Date.now()
    if (candidate.state === 'active' && candidate.leaseExpiresAt.getTime() > now) return
    if (candidate.state !== 'preparing' || candidate.leaseExpiresAt.getTime() <= now)
        throw new AppRuntimeAuthorityError('conflict')
    assertLeaseDeadline(leaseExpiresAt, now)
    const { installationId, generation } = identity
    await transaction
        .update(appRuntimeGenerations)
        .set({ state: 'revoked' })
        .where(
            and(
                eq(appRuntimeGenerations.installationId, installationId),
                ne(appRuntimeGenerations.generation, generation),
                eq(appRuntimeGenerations.state, 'active'),
            ),
        )
    await transaction
        .update(appRuntimeGenerations)
        .set({ state: 'active', leaseExpiresAt })
        .where(
            and(
                eq(appRuntimeGenerations.installationId, installationId),
                eq(appRuntimeGenerations.generation, generation),
            ),
        )
    await transaction
        .delete(appRuntimeDelegations)
        .where(
            and(
                eq(appRuntimeDelegations.installationId, installationId),
                ne(appRuntimeDelegations.generation, generation),
            ),
        )
}

export async function renewAppRuntimeGenerationLeaseInTransaction(
    transaction: AuthTransaction,
    identity: AppRuntimeIdentity,
    leaseExpiresAt: Date,
): Promise<void> {
    const current = await loadLockedGeneration(transaction, identity)
    const now = Date.now()
    if (current.state === 'revoked' || current.leaseExpiresAt.getTime() <= now)
        throw new AppRuntimeAuthorityError('conflict')
    assertLeaseDeadline(leaseExpiresAt, now)
    if (leaseExpiresAt <= current.leaseExpiresAt) return
    await transaction
        .update(appRuntimeGenerations)
        .set({ leaseExpiresAt })
        .where(
            and(
                eq(appRuntimeGenerations.installationId, identity.installationId),
                eq(appRuntimeGenerations.generation, identity.generation),
            ),
        )
}

export async function revokeAppRuntimeGenerationInTransaction(
    transaction: AuthTransaction,
    identity: AppRuntimeIdentity,
): Promise<void> {
    await loadLockedGeneration(transaction, identity)
    const { installationId, generation } = identity
    await transaction
        .update(appRuntimeGenerations)
        .set({ state: 'revoked' })
        .where(
            and(
                eq(appRuntimeGenerations.installationId, installationId),
                eq(appRuntimeGenerations.generation, generation),
            ),
        )
    await transaction
        .delete(appRuntimeDelegations)
        .where(
            and(
                eq(appRuntimeDelegations.installationId, installationId),
                eq(appRuntimeDelegations.generation, generation),
            ),
        )
}

export async function replaceAppRuntimeGrantsInTransaction(
    transaction: AuthTransaction,
    identity: AppRuntimeIdentity,
    grants: readonly AppRuntimeGrant[],
): Promise<void> {
    const generation = await loadLockedGeneration(transaction, identity)
    if (generation.state === 'revoked' || generation.leaseExpiresAt.getTime() <= Date.now())
        throw new AppRuntimeAuthorityError('conflict')
    if (grants.length > maxGrants) throw new AppRuntimeAuthorityError('invalid_input')
    const seen = new Set<string>()
    const entries = grants.map(({ capability, resourceId, allowService, permissionKey }) => {
        const target = JSON.stringify([capability.id, capability.scope, resourceId])
        if (
            seen.has(target) ||
            !isAppRuntimeGrantTarget(capability, resourceId, identity.installationId) ||
            (!isAppRuntimeSupportCapability(capability) &&
                !generation.capabilities.includes(capability.id)) ||
            (permissionKey !== undefined && !generation.permissionKeys.includes(permissionKey))
        )
            throw new AppRuntimeAuthorityError('invalid_input')
        seen.add(target)
        return {
            installationId: identity.installationId,
            capabilityId: capability.id,
            scope: capability.scope,
            resourceId,
            allowService,
            ...(permissionKey === undefined ? {} : { permissionKey }),
        }
    })
    await transaction
        .delete(appRuntimeGrants)
        .where(eq(appRuntimeGrants.installationId, identity.installationId))
    if (entries.length > 0) await transaction.insert(appRuntimeGrants).values(entries)
    await bumpAuthorizationEpoch(transaction, identity.installationId)
}

export async function setAppRuntimeRolePermissionInTransaction(
    transaction: AuthTransaction,
    identity: AppRuntimeIdentity,
    roleId: string,
    permissionKey: string,
    allowed: boolean,
): Promise<void> {
    // Exclude concurrent membership changes and delegation/recovery authorization.
    await transaction.execute(sql`select pg_advisory_xact_lock(${ACTIVE_OWNER_ADVISORY_LOCK_ID})`)
    const generation = await loadLockedGeneration(transaction, identity)
    if (generation.state === 'revoked' || generation.leaseExpiresAt.getTime() <= Date.now())
        throw new AppRuntimeAuthorityError('conflict')
    if (
        !isLocalAppRuntimePermissionKey(permissionKey) ||
        (allowed && !generation.permissionKeys.includes(permissionKey))
    )
        throw new AppRuntimeAuthorityError('invalid_input')
    const [role] = await transaction
        .select({ id: roles.id })
        .from(roles)
        .where(eq(roles.id, roleId))
        .for('update')
    if (!role) throw new AppRuntimeAuthorityError('not_found')
    const { installationId } = identity
    if (allowed) {
        await transaction
            .insert(appRuntimeRolePermissions)
            .values({ installationId, roleId, key: permissionKey })
            .onConflictDoNothing()
        await bumpAuthorizationEpoch(transaction, installationId)
        return
    }
    await transaction
        .delete(appRuntimeRolePermissions)
        .where(
            and(
                eq(appRuntimeRolePermissions.installationId, installationId),
                eq(appRuntimeRolePermissions.roleId, roleId),
                eq(appRuntimeRolePermissions.key, permissionKey),
            ),
        )
    await bumpAuthorizationEpoch(transaction, installationId)
}
