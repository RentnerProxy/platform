import '@tanstack/react-start/server-only'

import { and, desc, eq, inArray, isNotNull, isNull, ne, sql } from 'drizzle-orm'

import { ACTIVE_OWNER_ADVISORY_LOCK_ID } from '@/config/auth.config.ts'
import {
    appRuntimeDelegations,
    appRuntimeGenerations,
    appRuntimeGrants,
    appRuntimeInstallations,
    appRuntimeOperations,
    appRuntimeOwnedProxyHosts,
    appRuntimePendingSecrets,
    appRuntimeRolePermissions,
    appRuntimeSecrets,
    legacyFeatureHandoffRequests,
    roles,
    type AppRuntimeStoredGrant,
} from '@/db/schema.ts'
import type { AuthTransaction } from '@/server/Auth/Core/Types/database.types.ts'
import { abortInstallationLegacyHandoffsInTransaction } from '@/server/LegacyHandoff/app-api.server.ts'
import {
    APP_RUNTIME_SUPPORT_CAPABILITIES,
    isAppRuntimeGrantTarget,
    isAppRuntimeSupportCapability,
    isLocalAppRuntimePermissionKey,
    sameAppRuntimeCapability,
} from './authority-policy.server.ts'
import { isAppRuntimeIdentity, lockAppRuntimeInstallation } from './authority.server.ts'
import {
    appCapabilitySchema,
    appProviderProfilesSchema,
    appProviderRegistrationsSchema,
} from './contract.ts'
import {
    AppRuntimeAuthorityError,
    type AppRuntimeGrant,
    type AppRuntimeIdentity,
    type AppRuntimeProviderRegistration,
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

async function reserveInstallation(transaction: AuthTransaction, identity: AppRuntimeIdentity) {
    const { installationId, appId, uid } = identity
    await transaction
        .insert(appRuntimeInstallations)
        .values({ id: installationId, appId, uid })
        .onConflictDoNothing()
    await lockAppRuntimeInstallation(transaction, identity, true)
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
        providerProfiles = [],
        hasUi = false,
    } = registration
    if (
        !isAppRuntimeIdentity(identity) ||
        capabilities.length > 32 ||
        !capabilities.every((capability) => appCapabilitySchema.safeParse(capability).success) ||
        new Set(capabilities.map(({ id }) => id)).size !== capabilities.length ||
        permissionKeys.length > 64 ||
        !permissionKeys.every(isLocalAppRuntimePermissionKey) ||
        new Set(permissionKeys).size !== permissionKeys.length ||
        !appProviderProfilesSchema.safeParse(providerProfiles).success
    )
        throw new AppRuntimeAuthorityError('invalid_input')

    const { installationId, generation } = identity
    await reserveInstallation(transaction, identity)
    const [previous] = await transaction
        .select()
        .from(appRuntimeGenerations)
        .where(eq(appRuntimeGenerations.installationId, installationId))
        .orderBy(desc(appRuntimeGenerations.generation))
        .limit(1)
    const declaredCapabilities = capabilities.map(({ id }) => id).toSorted()
    const declaredPermissions = permissionKeys.toSorted()
    const declaredProviders = providerProfiles.toSorted()
    const now = Date.now()
    if (previous && previous.generation >= generation) {
        if (
            previous.generation === generation &&
            previous.state !== 'revoked' &&
            previous.leaseExpiresAt.getTime() > now &&
            previous.hasUi === hasUi &&
            JSON.stringify(previous.capabilities) === JSON.stringify(declaredCapabilities) &&
            JSON.stringify(previous.permissionKeys) === JSON.stringify(declaredPermissions) &&
            JSON.stringify(previous.providerProfiles) === JSON.stringify(declaredProviders)
        )
            return
        throw new AppRuntimeAuthorityError('conflict')
    }
    assertLeaseDeadline(leaseExpiresAt, now)

    await transaction
        .update(appRuntimeGenerations)
        .set({ state: 'revoked', pendingGrants: null })
        .where(
            and(
                eq(appRuntimeGenerations.installationId, installationId),
                eq(appRuntimeGenerations.state, 'preparing'),
            ),
        )
    await transaction
        .delete(appRuntimePendingSecrets)
        .where(eq(appRuntimePendingSecrets.installationId, installationId))
    await transaction.insert(appRuntimeGenerations).values({
        installationId,
        generation,
        leaseExpiresAt,
        state: 'preparing',
        capabilities: sql`${JSON.stringify(declaredCapabilities)}::text::jsonb`,
        permissionKeys: sql`${JSON.stringify(declaredPermissions)}::text::jsonb`,
        providerProfiles: sql`${JSON.stringify(declaredProviders)}::text::jsonb`,
        hasUi,
    })
}

/** Record the broker-validated provider registrations once, while the generation is preparing. */
export async function recordAppRuntimeProvidersInTransaction(
    transaction: AuthTransaction,
    identity: AppRuntimeIdentity,
    providers: readonly AppRuntimeProviderRegistration[],
): Promise<void> {
    if (!appProviderRegistrationsSchema.safeParse(providers).success)
        throw new AppRuntimeAuthorityError('invalid_input')
    const generation = await loadLockedGeneration(transaction, identity)
    if (generation.state !== 'preparing' || generation.leaseExpiresAt.getTime() <= Date.now())
        throw new AppRuntimeAuthorityError('conflict')
    if (!providers.every(({ profile }) => generation.providerProfiles.includes(profile)))
        throw new AppRuntimeAuthorityError('forbidden')
    const recorded = providers.map(({ id, profile, version }) => ({ id, profile, version }))
    if (generation.providers !== null) {
        if (JSON.stringify(generation.providers) === JSON.stringify(recorded)) return
        throw new AppRuntimeAuthorityError('conflict')
    }
    await transaction
        .update(appRuntimeGenerations)
        .set({ providers: sql`${JSON.stringify(recorded)}::text::jsonb` })
        .where(
            and(
                eq(appRuntimeGenerations.installationId, identity.installationId),
                eq(appRuntimeGenerations.generation, identity.generation),
            ),
        )
}

function pendingSecretsFor({ installationId, generation }: AppRuntimeIdentity) {
    return and(
        eq(appRuntimePendingSecrets.installationId, installationId),
        eq(appRuntimePendingSecrets.generation, generation),
    )
}

async function applyPendingSecrets(
    transaction: AuthTransaction,
    identity: AppRuntimeIdentity,
): Promise<void> {
    const scope = pendingSecretsFor(identity)
    const deletions = transaction
        .select({ id: appRuntimePendingSecrets.id })
        .from(appRuntimePendingSecrets)
        .where(and(scope, isNull(appRuntimePendingSecrets.ciphertext)))
    await transaction
        .delete(appRuntimeSecrets)
        .where(
            and(
                eq(appRuntimeSecrets.installationId, identity.installationId),
                inArray(appRuntimeSecrets.id, deletions),
            ),
        )
    await transaction
        .insert(appRuntimeSecrets)
        .select(
            transaction
                .select({
                    installationId: appRuntimePendingSecrets.installationId,
                    id: appRuntimePendingSecrets.id,
                    ciphertext: appRuntimePendingSecrets.ciphertext,
                    iv: appRuntimePendingSecrets.iv,
                })
                .from(appRuntimePendingSecrets)
                .where(and(scope, isNotNull(appRuntimePendingSecrets.ciphertext))),
        )
        .onConflictDoUpdate({
            target: [appRuntimeSecrets.installationId, appRuntimeSecrets.id],
            set: { ciphertext: sql`excluded.ciphertext`, iv: sql`excluded.iv` },
        })
    await transaction.delete(appRuntimePendingSecrets).where(scope)
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
    if (candidate.pendingGrants !== null)
        await publishAppRuntimeGrants(transaction, installationId, candidate.pendingGrants)
    await applyPendingSecrets(transaction, identity)
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
        .set({ state: 'active', leaseExpiresAt, pendingGrants: null })
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
    if (Math.min(candidate.leaseExpiresAt.getTime(), leaseExpiresAt.getTime()) <= Date.now())
        throw new AppRuntimeAuthorityError('conflict')
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

async function lockExistingInstallation(
    transaction: AuthTransaction,
    identity: AppRuntimeIdentity,
) {
    const [installation] = await transaction
        .select({ appId: appRuntimeInstallations.appId, uid: appRuntimeInstallations.uid })
        .from(appRuntimeInstallations)
        .where(eq(appRuntimeInstallations.id, identity.installationId))
        .for('update')
    if (!installation) return false
    if (installation.appId !== identity.appId || installation.uid !== identity.uid)
        throw new AppRuntimeAuthorityError('unauthorized')
    return true
}

export async function checkAppRuntimeDependenciesInTransaction(
    transaction: AuthTransaction,
    identity: AppRuntimeIdentity,
    action: 'workers-stopped' | 'removable' | 'purge-data',
): Promise<void> {
    if (!(await lockExistingInstallation(transaction, identity))) return
    const installationId = identity.installationId
    const [pending] = await transaction
        .select({ id: appRuntimeOperations.id })
        .from(appRuntimeOperations)
        .where(
            and(
                eq(appRuntimeOperations.installationId, installationId),
                inArray(appRuntimeOperations.status, ['accepted', 'running']),
            ),
        )
        .limit(1)
    if (pending) throw new AppRuntimeAuthorityError('conflict')
    if (action === 'workers-stopped') return
    const [host] = await transaction
        .select({ id: appRuntimeOwnedProxyHosts.hostId })
        .from(appRuntimeOwnedProxyHosts)
        .where(eq(appRuntimeOwnedProxyHosts.installationId, installationId))
        .limit(1)
    if (host) throw new AppRuntimeAuthorityError('conflict')
    // Platform resumes uncommitted built-in domains with their untouched state; ownership an app
    // committed stays recorded, because its platform state is already retired. The app manager
    // repeats this check after it stopped the app's broker, so a handoff begun before that stop is
    // released too, and no App API request can begin another one afterwards.
    if (action === 'removable')
        await abortInstallationLegacyHandoffsInTransaction(transaction, installationId)
    if (action === 'purge-data') {
        const [live] = await transaction
            .select({ generation: appRuntimeGenerations.generation })
            .from(appRuntimeGenerations)
            .where(
                and(
                    eq(appRuntimeGenerations.installationId, installationId),
                    ne(appRuntimeGenerations.state, 'revoked'),
                ),
            )
            .limit(1)
        if (live) throw new AppRuntimeAuthorityError('conflict')
        await transaction
            .delete(appRuntimeSecrets)
            .where(eq(appRuntimeSecrets.installationId, installationId))
        await transaction
            .delete(appRuntimePendingSecrets)
            .where(eq(appRuntimePendingSecrets.installationId, installationId))
        await transaction
            .delete(appRuntimeRolePermissions)
            .where(eq(appRuntimeRolePermissions.installationId, installationId))
        await transaction
            .delete(appRuntimeGrants)
            .where(eq(appRuntimeGrants.installationId, installationId))
        await transaction
            .delete(legacyFeatureHandoffRequests)
            .where(eq(legacyFeatureHandoffRequests.installationId, installationId))
        await bumpAuthorizationEpoch(transaction, installationId)
    }
}

export async function revokeAppRuntimeGenerationInTransaction(
    transaction: AuthTransaction,
    identity: AppRuntimeIdentity,
    allowMissing = false,
): Promise<void> {
    if (allowMissing) {
        await reserveInstallation(transaction, identity)
        await transaction
            .insert(appRuntimeGenerations)
            .values({
                installationId: identity.installationId,
                generation: identity.generation,
                state: 'revoked',
                leaseExpiresAt: new Date(0),
                capabilities: sql`'[]'::jsonb`,
                permissionKeys: sql`'[]'::jsonb`,
                hasUi: false,
            })
            .onConflictDoNothing()
    } else {
        await loadLockedGeneration(transaction, identity)
    }
    const { installationId, generation } = identity
    await transaction
        .update(appRuntimeGenerations)
        .set({ state: 'revoked', pendingGrants: null })
        .where(
            and(
                eq(appRuntimeGenerations.installationId, installationId),
                eq(appRuntimeGenerations.generation, generation),
            ),
        )
    await transaction.delete(appRuntimePendingSecrets).where(pendingSecretsFor(identity))
    await transaction
        .delete(appRuntimeDelegations)
        .where(
            and(
                eq(appRuntimeDelegations.installationId, installationId),
                eq(appRuntimeDelegations.generation, generation),
            ),
        )
}

function serializeGrant(entry: AppRuntimeStoredGrant): string {
    return JSON.stringify([
        entry.capabilityId,
        entry.scope,
        entry.resourceId,
        entry.allowService,
        entry.permissionKey,
    ])
}

async function publishAppRuntimeGrants(
    transaction: AuthTransaction,
    installationId: string,
    entries: readonly AppRuntimeStoredGrant[],
): Promise<void> {
    const stored = await transaction
        .select()
        .from(appRuntimeGrants)
        .where(eq(appRuntimeGrants.installationId, installationId))
    const currentPolicy = new Set(stored.map(serializeGrant))
    if (
        currentPolicy.size === entries.length &&
        entries.every((entry) => currentPolicy.has(serializeGrant(entry)))
    )
        return
    await transaction
        .delete(appRuntimeGrants)
        .where(eq(appRuntimeGrants.installationId, installationId))
    if (entries.length > 0)
        await transaction
            .insert(appRuntimeGrants)
            .values(entries.map((entry) => ({ installationId, ...entry })))
    await bumpAuthorizationEpoch(transaction, installationId)
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
            (permissionKey !== undefined && !generation.permissionKeys.includes(permissionKey)) ||
            (sameAppRuntimeCapability(capability, APP_RUNTIME_SUPPORT_CAPABILITIES.provider) &&
                !generation.providerProfiles.includes(resourceId))
        )
            throw new AppRuntimeAuthorityError('invalid_input')
        seen.add(target)
        return {
            capabilityId: capability.id,
            scope: capability.scope,
            resourceId,
            allowService,
            permissionKey: permissionKey ?? null,
        }
    })
    if (generation.state === 'preparing') {
        await transaction
            .update(appRuntimeGenerations)
            .set({ pendingGrants: sql`${JSON.stringify(entries)}::text::jsonb` })
            .where(
                and(
                    eq(appRuntimeGenerations.installationId, identity.installationId),
                    eq(appRuntimeGenerations.generation, identity.generation),
                ),
            )
    } else await publishAppRuntimeGrants(transaction, identity.installationId, entries)
    if (generation.leaseExpiresAt.getTime() <= Date.now())
        throw new AppRuntimeAuthorityError('conflict')
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
    // Role assignment edits update the live Platform authorization policy.
    if (generation.state !== 'active' || generation.leaseExpiresAt.getTime() <= Date.now())
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
        const inserted = await transaction
            .insert(appRuntimeRolePermissions)
            .values({ installationId, roleId, key: permissionKey })
            .onConflictDoNothing()
            .returning({ key: appRuntimeRolePermissions.key })
        if (inserted.length > 0) await bumpAuthorizationEpoch(transaction, installationId)
        return
    }
    const deleted = await transaction
        .delete(appRuntimeRolePermissions)
        .where(
            and(
                eq(appRuntimeRolePermissions.installationId, installationId),
                eq(appRuntimeRolePermissions.roleId, roleId),
                eq(appRuntimeRolePermissions.key, permissionKey),
            ),
        )
        .returning({ key: appRuntimeRolePermissions.key })
    if (deleted.length > 0) await bumpAuthorizationEpoch(transaction, installationId)
}
