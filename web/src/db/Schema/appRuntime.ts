import { sql } from 'drizzle-orm'
import {
    bigint,
    boolean,
    check,
    foreignKey,
    index,
    jsonb,
    primaryKey,
    timestamp,
    uniqueIndex,
    uuid,
    varchar,
} from 'drizzle-orm/pg-core'

import { sessions } from './auth.ts'
import { rentnerProxySchema } from './base.ts'
import { bytea } from './columns.ts'
import { roles } from './permissions.ts'

export const appRuntimeInstallations = rentnerProxySchema.table(
    'app_runtime_installations',
    {
        id: varchar('id', { length: 64 }).primaryKey(),
        appId: varchar('app_id', { length: 97 }).notNull(),
        uid: bigint('uid', { mode: 'number' }).notNull(),
        authorizationEpoch: bigint('authorization_epoch', { mode: 'bigint' })
            .notNull()
            .default(sql`0`),
    },
    (table) => [
        uniqueIndex('app_runtime_installations_uid_idx').on(table.uid),
        check('app_runtime_installations_uid_check', sql`${table.uid} between 20000 and 59999`),
    ],
)

export const appRuntimeGenerations = rentnerProxySchema.table(
    'app_runtime_generations',
    {
        installationId: varchar('installation_id', { length: 64 })
            .notNull()
            .references(() => appRuntimeInstallations.id),
        generation: bigint('generation', { mode: 'number' }).notNull(),
        state: varchar('state', { enum: ['preparing', 'active', 'revoked'], length: 10 }).notNull(),
        leaseExpiresAt: timestamp('lease_expires_at', { withTimezone: true }).notNull(),
        capabilities: jsonb('capabilities').$type<readonly string[]>().notNull(),
        permissionKeys: jsonb('permission_keys').$type<readonly string[]>().notNull(),
        hasUi: boolean('has_ui').notNull().default(false),
    },
    (table) => [
        primaryKey({ columns: [table.installationId, table.generation] }),
        check(
            'app_runtime_generations_number_check',
            sql`${table.generation} between 1 and 9007199254740991`,
        ),
        check(
            'app_runtime_generations_state_check',
            sql`${table.state} in ('preparing', 'active', 'revoked')`,
        ),
        uniqueIndex('app_runtime_generations_one_active_idx')
            .on(table.installationId)
            .where(sql`${table.state} = 'active'`),
    ],
)

export const appRuntimeGrants = rentnerProxySchema.table(
    'app_runtime_grants',
    {
        installationId: varchar('installation_id', { length: 64 })
            .notNull()
            .references(() => appRuntimeInstallations.id),
        capabilityId: varchar('capability_id', { length: 64 }).notNull(),
        scope: varchar('scope', { length: 32 }).notNull(),
        resourceId: varchar('resource_id', { length: 64 }).notNull(),
        allowService: boolean('allow_service').notNull().default(false),
        permissionKey: varchar('permission_key', { length: 32 }),
    },
    (table) => [
        primaryKey({
            columns: [table.installationId, table.capabilityId, table.scope, table.resourceId],
        }),
    ],
)

export const appRuntimeRolePermissions = rentnerProxySchema.table(
    'app_runtime_role_permissions',
    {
        installationId: varchar('installation_id', { length: 64 })
            .notNull()
            .references(() => appRuntimeInstallations.id),
        roleId: uuid('role_id')
            .notNull()
            .references(() => roles.id, { onDelete: 'cascade' }),
        key: varchar('key', { length: 32 }).notNull(),
    },
    (table) => [
        primaryKey({ columns: [table.installationId, table.roleId, table.key] }),
        index('app_runtime_role_permissions_role_idx').on(table.roleId),
    ],
)

export const appRuntimeDelegations = rentnerProxySchema.table(
    'app_runtime_delegations',
    {
        id: uuid('id')
            .primaryKey()
            .default(sql`uuidv7()`),
        installationId: varchar('installation_id', { length: 64 }).notNull(),
        generation: bigint('generation', { mode: 'number' }).notNull(),
        sessionId: uuid('session_id')
            .notNull()
            .references(() => sessions.id, { onDelete: 'cascade' }),
        tokenHash: varchar('token_hash', { length: 64 }).notNull(),
        expiresAt: timestamp('expires_at', { withTimezone: true }).notNull(),
    },
    (table) => [
        foreignKey({
            columns: [table.installationId, table.generation],
            foreignColumns: [
                appRuntimeGenerations.installationId,
                appRuntimeGenerations.generation,
            ],
        }),
        uniqueIndex('app_runtime_delegations_hash_idx').on(table.tokenHash),
        index('app_runtime_delegations_session_idx').on(table.sessionId),
        index('app_runtime_delegations_expiry_idx').on(table.expiresAt),
    ],
)

export const appRuntimeSecrets = rentnerProxySchema.table(
    'app_runtime_secrets',
    {
        installationId: varchar('installation_id', { length: 64 })
            .notNull()
            .references(() => appRuntimeInstallations.id),
        id: varchar('id', { length: 64 }).notNull(),
        ciphertext: bytea('ciphertext').notNull(),
        iv: bytea('iv').notNull(),
    },
    (table) => [
        primaryKey({ columns: [table.installationId, table.id] }),
        check('app_runtime_secrets_iv_check', sql`octet_length(${table.iv}) = 12`),
    ],
)

export const appRuntimeEvents = rentnerProxySchema.table(
    'app_runtime_events',
    {
        sequence: bigint('sequence', { mode: 'bigint' }).primaryKey().generatedAlwaysAsIdentity(),
        id: uuid('id')
            .notNull()
            .unique()
            .default(sql`uuidv7()`),
        installationId: varchar('installation_id', { length: 64 })
            .notNull()
            .references(() => appRuntimeInstallations.id),
        type: varchar('type', { length: 64 }).notNull(),
        capabilityId: varchar('capability_id', { length: 64 }).notNull(),
        scope: varchar('scope', { length: 32 }).notNull(),
        resourceId: varchar('resource_id', { length: 64 }).notNull(),
        revision: varchar('revision', { length: 64 }),
        occurredAt: timestamp('occurred_at', { withTimezone: true }).notNull().defaultNow(),
        payload: jsonb('payload').$type<Record<string, unknown>>(),
    },
    (table) => [
        index('app_runtime_events_installation_sequence_idx').on(
            table.installationId,
            table.sequence,
        ),
        index('app_runtime_events_installation_time_idx').on(
            table.installationId,
            table.occurredAt,
        ),
    ],
)

export const appRuntimeEventRetention = rentnerProxySchema.table('app_runtime_event_retention', {
    installationId: varchar('installation_id', { length: 64 })
        .primaryKey()
        .references(() => appRuntimeInstallations.id, { onDelete: 'cascade' }),
    floor: bigint('floor', { mode: 'bigint' })
        .notNull()
        .default(sql`0`),
})
