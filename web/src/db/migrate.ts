import { SQL } from 'bun'
import type { MigrationFailurePhase, MigrationOptions } from './Types/migration.types.ts'
import { sql } from 'drizzle-orm'
import { drizzle } from 'drizzle-orm/bun-sql'
import { migrate } from 'drizzle-orm/bun-sql/migrator'
import { readMigrationFiles } from 'drizzle-orm/migrator'
import { ACTIVE_OWNER_ADVISORY_LOCK_ID, MIGRATION_ADVISORY_LOCK_ID } from '../config/auth.config.ts'
import { ensureAuthorizationRegistryInTransaction } from '../server/Auth/Access/registry.service.ts'
import { validateDatabaseEnvironment } from '../server/env.server.ts'
import * as schema from './schema.ts'

/** The appliance entrypoint keeps serving the retained proxy snapshot on this exit status. */
export const DATABASE_NEWER_THAN_IMAGE_EXIT_CODE = 78

export class DatabaseNewerThanImageError extends Error {
    constructor(
        readonly databaseMigration: string,
        readonly imageMigration: string,
    ) {
        super('database is newer than this image')
        this.name = 'DatabaseNewerThanImageError'
    }
}

const migrationFailurePhases = new WeakMap<object, MigrationFailurePhase>()

function recordMigrationFailurePhase(error: unknown, phase: MigrationFailurePhase): void {
    if ((typeof error === 'object' && error !== null) || typeof error === 'function') {
        migrationFailurePhases.set(error, phase)
    }
}

function getMigrationFailurePhase(error: unknown): MigrationFailurePhase | undefined {
    if ((typeof error === 'object' && error !== null) || typeof error === 'function') {
        return migrationFailurePhases.get(error)
    }
    return undefined
}

/**
 * Drizzle only applies migrations newer than the latest recorded one, so an older image would
 * silently start on a database it cannot understand. Refuse before anything is applied.
 */
async function assertDatabaseNotNewerThanImage(
    reserved: SQL,
    migrationsFolder: string,
): Promise<void> {
    const imageLatest = readMigrationFiles({ migrationsFolder }).reduce(
        (latest, migration) => Math.max(latest, migration.folderMillis),
        0,
    )
    const [history] = await reserved<{ present: boolean }[]>`
        select to_regclass('drizzle.__drizzle_migrations') is not null as present
    `
    if (history?.present !== true) return
    const [recorded] = await reserved<{ latest: string | null }[]>`
        select max(created_at)::text as latest from drizzle.__drizzle_migrations
    `
    const latest = recorded?.latest
    if (latest && BigInt(latest) > BigInt(imageLatest)) {
        throw new DatabaseNewerThanImageError(latest, String(imageLatest))
    }
}

export async function runMigrate(options: MigrationOptions = {}) {
    const DATABASE_URL = options.databaseUrl ?? validateDatabaseEnvironment().DATABASE_URL
    const migrationsFolder = options.migrationsFolder ?? './web/drizzle'
    const client = new SQL(DATABASE_URL)
    let reserved: Awaited<ReturnType<typeof client.reserve>> | undefined
    let migrationLockHeld = false
    let operationError: unknown
    let cleanupError: unknown
    let failurePhase: MigrationFailurePhase = 'database connection'

    try {
        try {
            reserved = await client.reserve()
            await reserved`select pg_advisory_lock(${MIGRATION_ADVISORY_LOCK_ID})`
            migrationLockHeld = true

            await reserved`CREATE SCHEMA IF NOT EXISTS "rentnerproxy";`

            const db = drizzle(reserved, { schema })

            failurePhase = 'schema migration'
            await assertDatabaseNotNewerThanImage(reserved, migrationsFolder)
            console.log('Running migrations...')
            await migrate(db, { migrationsFolder })
            console.log('Migrations completed!')

            failurePhase = 'authorization registry'
            await db.transaction(async (transaction) => {
                await transaction.execute(
                    sql`select pg_advisory_xact_lock(${ACTIVE_OWNER_ADVISORY_LOCK_ID})`,
                )
                await ensureAuthorizationRegistryInTransaction(transaction)
            })
            console.log('Authorization registry synchronized!')
        } catch (error) {
            recordMigrationFailurePhase(error, failurePhase)
            operationError = error
        }
    } finally {
        if (reserved !== undefined) {
            try {
                if (migrationLockHeld) {
                    const unlockResult = await reserved<{ unlocked: boolean }[]>`
                        select pg_advisory_unlock(${MIGRATION_ADVISORY_LOCK_ID}) as unlocked
                    `
                    if (unlockResult[0]?.unlocked !== true) {
                        cleanupError ??= new Error('migration advisory lock was not released')
                    }
                }
            } catch (error) {
                cleanupError ??= error
            } finally {
                try {
                    await reserved.release()
                } catch (error) {
                    cleanupError ??= error
                }
            }
        }

        try {
            await client.close()
        } catch (error) {
            cleanupError ??= error
        }
    }

    if (operationError !== undefined) throw operationError
    if (cleanupError !== undefined) throw cleanupError
}

if (import.meta.main) {
    runMigrate().catch(function (error) {
        if (error instanceof DatabaseNewerThanImageError) {
            console.error(
                `The database holds migration ${error.databaseMigration}, which is newer than this image's latest migration ${error.imageMigration}. The database was left unchanged. Start the image that last migrated it, or a newer one.`,
            )
            process.exitCode = DATABASE_NEWER_THAN_IMAGE_EXIT_CODE
            return
        }
        const phase = getMigrationFailurePhase(error) ?? 'database connection'
        const advice =
            phase === 'database connection'
                ? 'Check DATABASE_URL and database availability, then retry.'
                : phase === 'schema migration'
                  ? 'Inspect the migration state or restore a known-good backup before retrying.'
                  : 'Correct the authorization registry state and retry; restore a known-good backup only if required.'
        console.error(`Migration failed during ${phase}. ${advice}`)
        process.exitCode = 1
    })
}
