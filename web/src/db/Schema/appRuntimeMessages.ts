import { bigint, index, jsonb, primaryKey, timestamp, varchar } from 'drizzle-orm/pg-core'

import type { AppAuditEventInput, AppNotificationInput } from '../../server/AppRuntime/contract.ts'
import { appRuntimeInstallations } from './appRuntime.ts'
import { rentnerProxySchema } from './base.ts'

export const appRuntimeMessages = rentnerProxySchema.table(
    'app_runtime_messages',
    {
        installationId: varchar('installation_id', { length: 64 })
            .notNull()
            .references(() => appRuntimeInstallations.id, { onDelete: 'cascade' }),
        actor: varchar('actor', { length: 64 }).notNull(),
        kind: varchar('kind', { length: 16 }).$type<'audit' | 'notification'>().notNull(),
        key: varchar('idempotency_key', { length: 64 }).notNull(),
        fingerprint: varchar('fingerprint', { length: 64 }).notNull(),
        generation: bigint('generation', { mode: 'number' }).notNull(),
        payload: jsonb('payload').$type<AppAuditEventInput | AppNotificationInput>().notNull(),
        createdAt: timestamp('created_at', { mode: 'date', withTimezone: true })
            .defaultNow()
            .notNull(),
    },
    (table) => [
        primaryKey({ columns: [table.installationId, table.actor, table.kind, table.key] }),
        index('app_runtime_messages_installation_time_idx').on(
            table.installationId,
            table.createdAt,
        ),
    ],
)
