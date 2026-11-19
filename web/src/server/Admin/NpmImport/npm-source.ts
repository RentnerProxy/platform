import type { NpmRecord, NpmSource } from './Types/npm-source.types.ts'
// oxlint-disable-next-line import/no-unassigned-import -- Keep SQLite parsing out of client bundles.
import '@tanstack/react-start/server-only'

import { Database } from 'bun:sqlite'
import { z } from 'zod'
import contract from '../../../../../core/src/npm-import-contract.json'

export const NPM_IMPORT_MAX_BYTES = 32 * 1024 * 1024
const MAX_ROWS = 500

// Exact Knex migration names shipped by the upstream v2.16.0 tag.
export const NPM_216_MIGRATIONS = contract.migrations

const REQUIRED_COLUMNS = contract.tables

export class NpmSourceError extends Error {
    constructor(readonly code: 'invalid_source' | 'unsupported_schema' | 'source_limit') {
        super(code)
    }
}

function queryRows(database: Database, sql: string): NpmRecord[] {
    return database.query(sql).all() as NpmRecord[]
}

function assertSchema(database: Database): void {
    const catalog = queryRows(
        database,
        "select name, type, sql from sqlite_schema where name not like 'sqlite_%'",
    )
    const objects = new Map(catalog.map((row) => [row.name, row]))
    for (const [table, required] of Object.entries(REQUIRED_COLUMNS)) {
        const object = objects.get(table)
        if (
            object?.type !== 'table' ||
            typeof object.sql !== 'string' ||
            !/^\s*create\s+table\b/iu.test(object.sql)
        ) {
            throw new NpmSourceError('unsupported_schema')
        }
        // Table names are constants controlled by this module, never source input.
        const columns = queryRows(database, `pragma table_info(${table})`)
        const present = new Set(columns.map((row) => row.name))
        if (required.some((column) => !present.has(column))) {
            throw new NpmSourceError('unsupported_schema')
        }
    }
    const migrations = queryRows(database, 'select name from knex_migrations limit 100')
    const actual = new Set(migrations.map((row) => row.name))
    if (
        migrations.length !== NPM_216_MIGRATIONS.length ||
        actual.size !== NPM_216_MIGRATIONS.length ||
        NPM_216_MIGRATIONS.some((name) => !actual.has(name))
    ) {
        throw new NpmSourceError('unsupported_schema')
    }
}

function boundedRows(database: Database, sql: string): NpmRecord[] {
    const rows = queryRows(database, sql)
    if (rows.length > MAX_ROWS) throw new NpmSourceError('source_limit')
    return rows
}

export function readNpmSqliteSource(path: string): NpmSource {
    let database: Database | undefined
    try {
        database = new Database(path, { readonly: true, strict: true })
        assertSchema(database)
        const proxyHosts = boundedRows(database, contract.queries.proxyHosts)
        const redirectHosts = boundedRows(database, contract.queries.redirectHosts)
        const accessLists = boundedRows(database, contract.queries.accessLists)
        const accessClients = boundedRows(database, contract.queries.accessClients)
        // Never read NPM's plaintext access_list_auth.password into the process.
        const authCounts = boundedRows(database, contract.queries.authCounts)
        // Certificate metadata only. PEM files, ACME state, and DNS credentials are separate.
        const certificates = boundedRows(database, contract.queries.certificates)
        const authRowCount = Number(
            queryRows(database, 'select count(*) as count from access_list_auth')[0]?.count ?? 0,
        )
        if (authRowCount > MAX_ROWS) throw new NpmSourceError('source_limit')
        const deadHosts = boundedRows(database, contract.queries.deadHosts)
        const streams = boundedRows(database, contract.queries.streams)
        return {
            schema: 'npm-2.16-schema',
            proxyHosts,
            redirectHosts,
            accessLists,
            accessClients,
            authCounts,
            certificates,
            deadHosts,
            streams,
        }
    } catch (error) {
        if (error instanceof NpmSourceError) throw error
        throw new NpmSourceError('invalid_source')
    } finally {
        database?.close()
    }
}

const nativeController = '/usr/local/bin/rentnerproxy-controller'
const row = z.record(z.string(), z.unknown())
const rows = z.array(row).max(MAX_ROWS)
const nativeResult = z.union([
    z.strictObject({
        source: z.strictObject({
            schema: z.literal('npm-2.16-schema'),
            proxyHosts: rows,
            redirectHosts: rows,
            accessLists: rows,
            accessClients: rows,
            authCounts: rows,
            certificates: rows,
            deadHosts: rows,
            streams: rows,
        }),
    }),
    z.strictObject({ error: z.enum(['invalid_source', 'unsupported_schema', 'source_limit']) }),
])

export async function readNpmSqliteUpload(path: string): Promise<NpmSource> {
    if (process.platform !== 'linux' || !(await Bun.file(nativeController).exists())) {
        return readNpmSqliteSource(path)
    }
    const reader = Bun.spawn([nativeController, '--read-npm-sqlite', path], {
        env: {},
        stdin: 'ignore',
        stdout: 'pipe',
        stderr: 'ignore',
        signal: AbortSignal.timeout(6_000),
    })
    let value: unknown
    try {
        const [output, exit] = await Promise.all([
            new Response(reader.stdout).json(),
            reader.exited,
        ])
        if (exit !== 0) throw new NpmSourceError('invalid_source')
        value = output
    } catch {
        throw new NpmSourceError('invalid_source')
    }
    const parsed = nativeResult.safeParse(value)
    if (!parsed.success) throw new NpmSourceError('invalid_source')
    if ('error' in parsed.data) throw new NpmSourceError(parsed.data.error)
    return parsed.data.source
}
