import { sql } from 'drizzle-orm'
import {
    bigint,
    check,
    index,
    jsonb,
    primaryKey,
    timestamp,
    uuid,
    varchar,
} from 'drizzle-orm/pg-core'
import type {
    AppOperationFailure,
    AppOperationPayload,
    AppOperationResult,
    AppOperationStatus,
} from '@/server/AppRuntime/Types/operations.types.ts'
import { appRuntimeInstallations } from './appRuntime.ts'
import { rentnerProxySchema } from './base.ts'
import { proxyHosts } from './proxyHosts.ts'

export const appRuntimeOwnedProxyHosts = rentnerProxySchema.table(
    'app_runtime_owned_proxy_hosts',
    {
        installationId: varchar('installation_id', { length: 64 })
            .notNull()
            .references(() => appRuntimeInstallations.id, { onDelete: 'restrict' }),
        hostId: varchar('host_id', { length: 64 }).notNull(),
        proxyHostId: uuid('proxy_host_id')
            .notNull()
            .unique()
            .references(() => proxyHosts.id, { onDelete: 'cascade' }),
    },
    (table) => [primaryKey({ columns: [table.installationId, table.hostId] })],
)

export const appRuntimeOperations = rentnerProxySchema.table(
    'app_runtime_operations',
    {
        id: uuid('id').primaryKey(),
        installationId: varchar('installation_id', { length: 64 })
            .notNull()
            .references(() => appRuntimeInstallations.id, { onDelete: 'cascade' }),
        generation: bigint('generation', { mode: 'number' }).notNull(),
        delegationId: uuid('delegation_id'),
        actorUserId: uuid('actor_user_id'),
        requestId: varchar('request_id', { length: 64 }).notNull(),
        status: varchar('status', { length: 16 }).$type<AppOperationStatus>().notNull(),
        input: jsonb('input').$type<AppOperationPayload>().notNull(),
        result: jsonb('result').$type<AppOperationResult>(),
        failure: jsonb('failure').$type<AppOperationFailure>(),
        leaseToken: uuid('lease_token'),
        leaseExpiresAt: timestamp('lease_expires_at', { withTimezone: true }),
        startedAt: timestamp('started_at', { withTimezone: true }),
        createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
    },
    (table) => [
        index('app_runtime_operations_pending_idx')
            .on(table.status, table.createdAt, table.id)
            .where(sql`${table.status} in ('accepted', 'running')`),
        index('app_runtime_operations_installation_pending_idx')
            .on(table.installationId)
            .where(sql`${table.status} in ('accepted', 'running')`),
        check(
            'app_runtime_operations_state_check',
            sql`${table.status} in ('accepted', 'running', 'cancelled', 'succeeded', 'failed') and
                (${table.status} = 'failed') = (${table.failure} is not null) and
                (${table.status} = 'running' or ${table.leaseToken} is null) and
                (${table.leaseToken} is null) = (${table.leaseExpiresAt} is null)`,
        ),
    ],
)

export const appRuntimeOperationRequests = rentnerProxySchema.table(
    'app_runtime_operation_requests',
    {
        installationId: varchar('installation_id', { length: 64 }).notNull(),
        keyHash: varchar('key_hash', { length: 64 }).notNull(),
        payloadHash: varchar('payload_hash', { length: 64 }).notNull(),
        operationId: uuid('operation_id')
            .notNull()
            .references(() => appRuntimeOperations.id, { onDelete: 'cascade' }),
    },
    (table) => [
        primaryKey({ columns: [table.installationId, table.keyHash] }),
        index('app_runtime_operation_requests_operation_idx').on(table.operationId),
    ],
)
