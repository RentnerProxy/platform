import { sql } from 'drizzle-orm'
import { check, integer, primaryKey, timestamp, varchar } from 'drizzle-orm/pg-core'

import { appRuntimeInstallations } from './appRuntime.ts'
import { rentnerProxySchema } from './base.ts'
import { bytea } from './columns.ts'

/**
 * One row per built-in feature domain that left platform ownership. No row means platform owns
 * the domain; `exported` fences platform workers until the app commits or the handoff is aborted.
 */
export const legacyFeatureHandoffs = rentnerProxySchema.table(
    'legacy_feature_handoffs',
    {
        domain: varchar('domain', { length: 32 }).primaryKey(),
        installationId: varchar('installation_id', { length: 64 })
            .notNull()
            .references(() => appRuntimeInstallations.id),
        state: varchar('state', { enum: ['exported', 'committed'], length: 9 }).notNull(),
        digest: varchar('digest', { length: 64 }).notNull(),
        partCount: integer('part_count').notNull(),
        exportedAt: timestamp('exported_at', { withTimezone: true }).notNull().defaultNow(),
        committedAt: timestamp('committed_at', { withTimezone: true }),
    },
    (table) => [
        check(
            'legacy_feature_handoffs_domain_check',
            sql`${table.domain} in ('monitoring', 'docker-discovery', 'load-balancer', 'dns', 'oidc', 'crowdsec')`,
        ),
        check(
            'legacy_feature_handoffs_state_check',
            sql`${table.state} in ('exported', 'committed')`,
        ),
        check('legacy_feature_handoffs_digest_check', sql`${table.digest} ~ '^[a-f0-9]{64}$'`),
        check(
            'legacy_feature_handoffs_part_count_check',
            sql`${table.partCount} between 0 and 1024`,
        ),
        check(
            'legacy_feature_handoffs_commit_check',
            sql`(${table.state} = 'committed') = (${table.committedAt} is not null)`,
        ),
    ],
)

/** Encrypted snapshot parts of an exported handoff; they are deleted on commit or abort. */
export const legacyFeatureHandoffParts = rentnerProxySchema.table(
    'legacy_feature_handoff_parts',
    {
        domain: varchar('domain', { length: 32 }).notNull(),
        sequence: integer('sequence').notNull(),
        sha256: varchar('sha256', { length: 64 }).notNull(),
        ciphertext: bytea('ciphertext').notNull(),
        iv: bytea('iv').notNull(),
    },
    (table) => [
        primaryKey({ columns: [table.domain, table.sequence] }),
        check(
            'legacy_feature_handoff_parts_sequence_check',
            sql`${table.sequence} between 0 and 1023`,
        ),
        check('legacy_feature_handoff_parts_sha256_check', sql`${table.sha256} ~ '^[a-f0-9]{64}$'`),
        check('legacy_feature_handoff_parts_iv_check', sql`octet_length(${table.iv}) = 12`),
    ],
)
