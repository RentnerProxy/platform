import { expect, test } from 'bun:test'
import { and, count, eq, inArray, sql } from 'drizzle-orm'

import { LEGACY_HANDOFF_LIMITS } from '@/config/legacy-handoff.config.ts'
import {
    appRuntimeInstallations,
    legacyFeatureHandoffParts,
    legacyFeatureHandoffs,
} from '@/db/schema.ts'
import { appProviderProfiles } from '@/server/AppRuntime/contract.ts'
import type { AppRuntimeJsonValue } from '@/server/AppRuntime/Types/authority.types.ts'
import type { AuthTransaction } from '@/server/Auth/Core/Types/database.types.ts'
import type {
    LegacyFeatureDomain,
    LegacyFeatureHandoffSource,
} from '@/server/LegacyHandoff/Types/legacy-handoff.types.ts'

const integrationEnabled =
    process.env.RENTNERPROXY_DATABASE_INTEGRATION === '1' && Boolean(process.env.DATABASE_URL)
const integrationTest = integrationEnabled ? test : test.skip
const failure = (code: string) => ({ code })

const domain: LegacyFeatureDomain = 'crowdsec'
const secretMarker = 'legacy-credential-' + crypto.randomUUID()
const parts: AppRuntimeJsonValue[] = [
    { settings: { enabled: true, interval: 60 } },
    { credential: secretMarker },
    { history: [1, 2, 3] },
]

function source(overrides: Partial<LegacyFeatureHandoffSource> = {}) {
    const calls = { exported: 0, retired: 0, inspected: 0 }
    const handoff: LegacyFeatureHandoffSource = {
        domain,
        inspect: async () => {
            calls.inspected += 1
            return { configured: true, references: parts.length }
        },
        export: async (_transaction, emit) => {
            calls.exported += 1
            for (const part of parts) {
                // oxlint-disable-next-line no-await-in-loop -- Parts are emitted in order.
                await emit(part)
            }
        },
        retire: async () => {
            calls.retired += 1
        },
        ...overrides,
    }
    return { handoff, calls }
}

/** Create this test's installations, refusing a database where another handoff holds the domain. */
async function claimDomain(installations: readonly { id: string; appId: string }[]) {
    const { db } = await import('@/db/index.ts')
    const [held] = await db
        .select({ installationId: legacyFeatureHandoffs.installationId })
        .from(legacyFeatureHandoffs)
        .where(eq(legacyFeatureHandoffs.domain, domain))
    if (held) throw new Error('Another ' + domain + ' handoff exists; use an isolated database.')
    const uidBase = 20_000 + Math.floor(Math.random() * 39_000)
    await db
        .insert(appRuntimeInstallations)
        .values(installations.map((entry, index) => ({ ...entry, uid: uidBase + index })))
}

/** Remove only the handoff and installations this test created. */
async function releaseDomain(installationIds: readonly string[]) {
    const { db } = await import('@/db/index.ts')
    await db.transaction(async (transaction) => {
        const [row] = await transaction
            .select({ installationId: legacyFeatureHandoffs.installationId })
            .from(legacyFeatureHandoffs)
            .where(eq(legacyFeatureHandoffs.domain, domain))
            .for('update')
        if (row && installationIds.includes(row.installationId)) {
            await transaction
                .delete(legacyFeatureHandoffParts)
                .where(eq(legacyFeatureHandoffParts.domain, domain))
            await transaction
                .delete(legacyFeatureHandoffs)
                .where(eq(legacyFeatureHandoffs.domain, domain))
        }
        await transaction
            .delete(appRuntimeInstallations)
            .where(inArray(appRuntimeInstallations.id, [...installationIds]))
    })
}

/** Wait until another session queues for the domain lock in the given mode. */
async function awaitLockWaiter(mode: 'ExclusiveLock' | 'ShareLock') {
    const { db } = await import('@/db/index.ts')
    const key = appProviderProfiles.indexOf(domain)
    for (let attempt = 0; attempt < 100; attempt += 1) {
        // oxlint-disable-next-line no-await-in-loop -- Poll the lock table until the waiter appears.
        const [state] = await db.execute<{ waiting: boolean }>(sql`
            select exists (
                select from pg_locks
                where locktype = 'advisory' and not granted and mode = ${mode}
                    and classid = (${LEGACY_HANDOFF_LIMITS.advisoryLockClass})::oid
                    and objid = (${key})::oid and objsubid = 2
            ) as waiting`)
        if (state?.waiting) return
        // oxlint-disable-next-line no-await-in-loop -- See above.
        await Bun.sleep(50)
    }
    throw new Error('No session queued for the domain lock')
}

/** Hand a value that only looks like wire JSON to a source's emit. */
function emitAs(value: unknown): AppRuntimeJsonValue {
    return value as AppRuntimeJsonValue
}

function useKey(fill: number) {
    const original = process.env.APP_ENCRYPTION_KEY
    process.env.APP_ENCRYPTION_KEY = Buffer.alloc(32, fill).toString('base64')
    return () => {
        if (original === undefined) delete process.env.APP_ENCRYPTION_KEY
        else process.env.APP_ENCRYPTION_KEY = original
    }
}

integrationTest(
    'handoffs fence platform writers, resume with the same export and retire platform state once',
    async () => {
        const { db } = await import('@/db/index.ts')
        const journal = await import('@/server/LegacyHandoff/journal.server.ts')
        const ownership = await import('@/server/LegacyHandoff/ownership.server.ts')
        const run = <T>(work: (transaction: AuthTransaction) => Promise<T>) =>
            db.transaction(async (transaction) => {
                await transaction.execute(sql`select set_config('lock_timeout', '2000ms', true)`)
                return work(transaction)
            })
        const installations = [crypto.randomUUID(), crypto.randomUUID()]
        const [first, second] = installations as [string, string]
        const restoreKey = useKey(71)
        const storedParts = async () =>
            (
                await db
                    .select({ total: count() })
                    .from(legacyFeatureHandoffParts)
                    .where(eq(legacyFeatureHandoffParts.domain, domain))
            )[0]?.total
        const owner = () =>
            run((transaction) => ownership.readLegacyFeatureOwnerInTransaction(transaction, domain))
        const gate = () =>
            run((transaction) =>
                ownership.withPlatformOwnedLegacyFeature(transaction, domain, async () => 'wrote'),
            )
        const readPart = (installationId: string, sequence: number) =>
            run((transaction) =>
                journal.readLegacyFeatureHandoffPartInTransaction(
                    transaction,
                    domain,
                    installationId,
                    sequence,
                ),
            )

        try {
            await claimDomain([
                { id: first, appId: 'test.handoff-one' },
                { id: second, appId: 'test.handoff-two' },
            ])
            const { handoff, calls } = source()
            const begin = (installationId: string, from = handoff) =>
                run((transaction) =>
                    journal.beginLegacyFeatureHandoffInTransaction(
                        transaction,
                        from,
                        installationId,
                    ),
                )

            // Platform owns every domain until a handoff starts; the preview sees the source state.
            expect(await gate()).toEqual({ owned: true, value: 'wrote' })
            const before = await run((transaction) =>
                journal.inspectLegacyFeaturesInTransaction(transaction, { [domain]: handoff }),
            )
            expect(before.map((status) => status.domain)).toEqual([...appProviderProfiles])
            expect(before.every((status) => status.ownership.owner === 'platform')).toBe(true)
            expect(before.find((status) => status.domain === domain)?.inspection).toEqual({
                configured: true,
                references: parts.length,
            })
            expect(before.find((status) => status.domain === 'dns')?.inspection).toBeUndefined()

            await expect(begin(crypto.randomUUID())).rejects.toMatchObject(failure('not_found'))
            expect(await owner()).toEqual({ owner: 'platform' })

            const exported = await begin(first)
            expect(exported).toMatchObject({
                owner: 'handoff',
                installationId: first,
                partCount: 3,
            })
            const digest = exported.owner === 'handoff' ? exported.digest : ''
            expect(digest).toMatch(/^[a-f0-9]{64}$/u)
            expect(await begin(first)).toEqual(exported)
            expect(calls.exported).toBe(1)
            await expect(begin(second)).rejects.toMatchObject(failure('conflict'))
            expect(await gate()).toEqual({ owned: false })
            expect(await owner()).toEqual(exported)
            const during = await run((transaction) =>
                journal.inspectLegacyFeaturesInTransaction(transaction, { [domain]: handoff }),
            )
            expect(during.find((status) => status.domain === domain)).toEqual({
                domain,
                ownership: exported,
            })

            // Parts are encrypted at rest and readable only by the importing installation.
            const raw = await db
                .select()
                .from(legacyFeatureHandoffParts)
                .where(eq(legacyFeatureHandoffParts.domain, domain))
            expect(raw.map((part) => part.sequence).toSorted()).toEqual([0, 1, 2])
            expect(raw.some((part) => Buffer.from(part.ciphertext).includes(secretMarker))).toBe(
                false,
            )
            expect(
                await Promise.all(parts.map((_, sequence) => readPart(first, sequence))),
            ).toEqual(parts)
            for (const sequence of [-1, 3, 1.5]) {
                // oxlint-disable-next-line no-await-in-loop -- Each read is its own transaction.
                await expect(readPart(first, sequence)).rejects.toMatchObject(failure('not_found'))
            }
            await expect(readPart(second, 0)).rejects.toMatchObject(failure('not_found'))

            // A tampered or missing part is reported; aborting and exporting again restores it.
            const partAt = (sequence: number) =>
                and(
                    eq(legacyFeatureHandoffParts.domain, domain),
                    eq(legacyFeatureHandoffParts.sequence, sequence),
                )
            await db
                .update(legacyFeatureHandoffParts)
                .set({ sha256: 'f'.repeat(64) })
                .where(partAt(0))
            await expect(readPart(first, 0)).rejects.toMatchObject(failure('corrupt'))
            await db.delete(legacyFeatureHandoffParts).where(partAt(1))
            await expect(readPart(first, 1)).rejects.toMatchObject(failure('corrupt'))
            await expect(
                run((transaction) =>
                    journal.abortLegacyFeatureHandoffInTransaction(transaction, domain, second),
                ),
            ).rejects.toMatchObject(failure('conflict'))
            await run((transaction) =>
                journal.abortLegacyFeatureHandoffInTransaction(transaction, domain, first),
            )
            await run((transaction) =>
                journal.abortLegacyFeatureHandoffInTransaction(transaction, domain, first),
            )
            expect(await owner()).toEqual({ owner: 'platform' })
            expect(await storedParts()).toBe(0)
            expect(await gate()).toEqual({ owned: true, value: 'wrote' })
            const resumed = await begin(first)
            expect(resumed).toMatchObject({ owner: 'handoff', digest, partCount: 3 })
            expect(await readPart(first, 1)).toEqual(parts[1]!)

            // Only the exact export commits; a failed retirement leaves the handoff resumable.
            const commit = (installationId: string, value: string, from = handoff) =>
                run((transaction) =>
                    journal.commitLegacyFeatureHandoffInTransaction(
                        transaction,
                        from,
                        installationId,
                        value,
                    ),
                )
            await expect(commit(first, 'a'.repeat(64))).rejects.toMatchObject(failure('conflict'))
            await expect(commit(second, digest)).rejects.toMatchObject(failure('conflict'))
            const failing = source({
                retire: async () => {
                    throw new Error('retirement interrupted')
                },
            })
            await expect(commit(first, digest, failing.handoff)).rejects.toThrow(
                'retirement interrupted',
            )
            expect(await owner()).toMatchObject({ owner: 'handoff', digest })
            expect(await storedParts()).toBe(3)

            const committed = await commit(first, digest)
            expect(committed).toEqual({ owner: 'app', installationId: first, digest })
            expect(calls.retired).toBe(1)
            expect(await commit(first, digest)).toEqual(committed)
            expect(calls.retired).toBe(1)
            expect(await storedParts()).toBe(0)
            expect(await gate()).toEqual({ owned: false })
            await expect(readPart(first, 0)).rejects.toMatchObject(failure('not_found'))
            expect(await begin(first)).toEqual(committed)
            await expect(begin(second)).rejects.toMatchObject(failure('conflict'))
            await expect(
                run((transaction) =>
                    journal.abortLegacyFeatureHandoffInTransaction(transaction, domain, first),
                ),
            ).rejects.toMatchObject(failure('conflict'))
            const after = await run((transaction) =>
                journal.inspectLegacyFeaturesInTransaction(transaction, { [domain]: handoff }),
            )
            expect(after.find((status) => status.domain === domain)).toEqual({
                domain,
                ownership: committed,
            })
            expect(calls.exported).toBe(2)
            await expect(
                run((transaction) =>
                    journal.commitLegacyFeatureHandoffInTransaction(
                        transaction,
                        { ...handoff, domain: 'oidc' },
                        first,
                        digest,
                    ),
                ),
            ).rejects.toMatchObject(failure('not_found'))
        } finally {
            restoreKey()
            await releaseDomain(installations)
        }
    },
)

integrationTest('invalid or incomplete exports never fence a domain', async () => {
    const { db } = await import('@/db/index.ts')
    const journal = await import('@/server/LegacyHandoff/journal.server.ts')
    const ownership = await import('@/server/LegacyHandoff/ownership.server.ts')
    const installationId = crypto.randomUUID()
    const restoreKey = useKey(72)
    const begin = (exporter: LegacyFeatureHandoffSource['export']) =>
        db.transaction((transaction) =>
            journal.beginLegacyFeatureHandoffInTransaction(
                transaction,
                source({ export: exporter }).handoff,
                installationId,
            ),
        )

    try {
        await claimDomain([{ id: installationId, appId: 'test.handoff-invalid' }])
        const oversized = 'x'.repeat(LEGACY_HANDOFF_LIMITS.partBytes)
        // Values whose serialized text leaves the wire contract although their own members pass.
        class UnsafeNumber {
            toJSON() {
                return 2 ** 53
            }
        }
        class Vanishing {
            toJSON() {
                return undefined
            }
        }
        const throwingGetter = {
            get value(): never {
                throw new Error('getter failed')
            },
        }
        const invalid: LegacyFeatureHandoffSource['export'][] = [
            async (_transaction, emit) => {
                await emit({ value: Number.NaN })
            },
            async (_transaction, emit) => {
                await emit(oversized)
            },
            async (_transaction, emit) => {
                await emit(emitAs(new UnsafeNumber()))
            },
            async (_transaction, emit) => {
                await emit(emitAs(new Vanishing()))
            },
            async (_transaction, emit) => {
                for (let index = 0; index <= LEGACY_HANDOFF_LIMITS.maximumParts; index += 1) {
                    // oxlint-disable-next-line no-await-in-loop -- The limit is reached in order.
                    await emit(index)
                }
            },
            // Sources that swallow a rejection or never await still cannot record a partial snapshot.
            async (_transaction, emit) => {
                await emit(1)
                await emit(oversized).catch(() => undefined)
            },
            async (_transaction, emit) => {
                await emit(1)
                await emit(emitAs(throwingGetter)).catch(() => undefined)
            },
            async (_transaction, emit) => {
                void emit(1)
                void emit({ value: Number.NaN })
            },
        ]
        for (const exporter of invalid) {
            // oxlint-disable-next-line no-await-in-loop -- Every attempt must roll back alone.
            await expect(begin(exporter)).rejects.toMatchObject(failure('invalid_export'))
        }

        // A failing export still settles every accepted part before begin rejects.
        let storedBeforeFailure = false
        await expect(
            begin(async (_transaction, emit) => {
                void emit({ accepted: true }).then(() => {
                    storedBeforeFailure = true
                })
                throw new Error('export failed')
            }),
        ).rejects.toThrow('export failed')
        expect(storedBeforeFailure).toBe(true)

        // Without the encryption key nothing is stored, even when the source did not await.
        delete process.env.APP_ENCRYPTION_KEY
        await expect(
            begin(async (_transaction, emit) => {
                void emit({ key: 'missing' })
            }),
        ).rejects.toThrow()
        process.env.APP_ENCRYPTION_KEY = Buffer.alloc(32, 72).toString('base64')
        expect(
            await db.transaction((transaction) =>
                ownership.readLegacyFeatureOwnerInTransaction(transaction, domain),
            ),
        ).toEqual({ owner: 'platform' })

        // Handoffs need a fresh snapshot after the lock and their own transaction.
        await expect(
            db.transaction(
                (transaction) =>
                    journal.beginLegacyFeatureHandoffInTransaction(
                        transaction,
                        source().handoff,
                        installationId,
                    ),
                { isolationLevel: 'repeatable read' },
            ),
        ).rejects.toThrow('read committed')
        await expect(
            db.transaction((transaction) =>
                ownership.withPlatformOwnedLegacyFeature(transaction, domain, () =>
                    journal.beginLegacyFeatureHandoffInTransaction(
                        transaction,
                        source().handoff,
                        installationId,
                    ),
                ),
            ),
        ).rejects.toThrow('platform writer')

        // Parts emitted without awaiting are still stored before the export is recorded, while a
        // late part after the export finished is refused.
        let late: ((part: AppRuntimeJsonValue) => Promise<void>) | undefined
        const empty = await begin(async (_transaction, emit) => {
            late = emit
            void emit('a')
            void emit('b')
        })
        expect(empty).toMatchObject({ owner: 'handoff', partCount: 2 })
        await expect(late!('c')).rejects.toMatchObject(failure('invalid_export'))
        expect(
            await db
                .select({ sequence: legacyFeatureHandoffParts.sequence })
                .from(legacyFeatureHandoffParts)
                .where(eq(legacyFeatureHandoffParts.domain, domain))
                .orderBy(legacyFeatureHandoffParts.sequence),
        ).toEqual([{ sequence: 0 }, { sequence: 1 }])
    } finally {
        restoreKey()
        await releaseDomain([installationId])
    }
})

integrationTest(
    'a handoff waits for running platform writers, turns new ones away and holds back the preview',
    async () => {
        const { db } = await import('@/db/index.ts')
        const journal = await import('@/server/LegacyHandoff/journal.server.ts')
        const ownership = await import('@/server/LegacyHandoff/ownership.server.ts')
        const installationId = crypto.randomUUID()
        const restoreKey = useKey(73)
        const writer = Promise.withResolvers<void>()
        const writerStarted = Promise.withResolvers<void>()
        const exporting = Promise.withResolvers<void>()
        const exportStarted = Promise.withResolvers<void>()
        let exportEntered = false
        let writing: Promise<unknown> | undefined
        let beginning: Promise<unknown> | undefined
        let previewing: Promise<unknown> | undefined

        try {
            await claimDomain([{ id: installationId, appId: 'test.handoff-fence' }])
            // A platform writer inside its transaction delays the fence until it commits.
            const written = db.transaction((transaction) =>
                ownership.withPlatformOwnedLegacyFeature(transaction, domain, async () => {
                    writerStarted.resolve()
                    await writer.promise
                    return 'written before the fence'
                }),
            )
            writing = written
            await Promise.race([writerStarted.promise, written])
            const begun = db.transaction((transaction) =>
                journal.beginLegacyFeatureHandoffInTransaction(
                    transaction,
                    source({
                        export: async (_transaction, emit) => {
                            exportEntered = true
                            exportStarted.resolve()
                            await exporting.promise
                            await emit({ fenced: true })
                        },
                    }).handoff,
                    installationId,
                ),
            )
            beginning = begun
            // The handoff is queued behind the writer and has not started its export.
            await awaitLockWaiter('ExclusiveLock')
            expect(exportEntered).toBe(false)
            writer.resolve()
            expect(await written).toEqual({ owned: true, value: 'written before the fence' })

            // While the export runs, a new writer skips at once instead of waiting.
            await Promise.race([exportStarted.promise, begun])
            const started = performance.now()
            expect(
                await db.transaction((transaction) =>
                    ownership.withPlatformOwnedLegacyFeature(
                        transaction,
                        domain,
                        async () => 'late',
                    ),
                ),
            ).toEqual({ owned: false })
            expect(performance.now() - started).toBeLessThan(1_000)

            // The preview waits for the handoff and then reports it instead of a stale inspection.
            const inspected = db.transaction((transaction) =>
                journal.inspectLegacyFeaturesInTransaction(transaction, {
                    [domain]: source().handoff,
                }),
            )
            previewing = inspected
            await awaitLockWaiter('ShareLock')
            exporting.resolve()
            const fenced = await begun
            expect(fenced).toMatchObject({ owner: 'handoff', partCount: 1 })
            expect((await inspected).find((status) => status.domain === domain)).toEqual({
                domain,
                ownership: fenced,
            })
        } finally {
            writer.resolve()
            exporting.resolve()
            await Promise.allSettled([writing, beginning, previewing])
            restoreKey()
            await releaseDomain([installationId])
        }
    },
)
