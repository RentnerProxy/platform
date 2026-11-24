import { expect, test } from 'bun:test'
import { eq } from 'drizzle-orm'

import { appRuntimeInstallations, legacyFeatureHandoffs } from '@/db/schema.ts'

const integrationEnabled =
    process.env.RENTNERPROXY_DATABASE_INTEGRATION === '1' && Boolean(process.env.DATABASE_URL)
const integrationTest = integrationEnabled ? test : test.skip

integrationTest('built-in workers are admitted only while platform owns their domain', async () => {
    const { db } = await import('@/db/index.ts')
    const { isLegacyFeaturePlatformOwned } =
        await import('@/server/LegacyHandoff/worker-admission.server.ts')
    const domain = 'oidc'
    const installationId = crypto.randomUUID()
    const [held] = await db
        .select({ installationId: legacyFeatureHandoffs.installationId })
        .from(legacyFeatureHandoffs)
        .where(eq(legacyFeatureHandoffs.domain, domain))
    if (held) throw new Error('Another oidc handoff exists; use an isolated database.')

    try {
        expect(await isLegacyFeaturePlatformOwned(domain)).toBe(true)
        await db.insert(appRuntimeInstallations).values({
            id: installationId,
            appId: 'test.handoff-admission',
            uid: 20_000 + Math.floor(Math.random() * 39_000),
        })
        await db.insert(legacyFeatureHandoffs).values({
            domain,
            installationId,
            state: 'exported',
            digest: 'a'.repeat(64),
            partCount: 0,
        })
        // A running export fences the platform worker just like a committed handoff.
        expect(await isLegacyFeaturePlatformOwned(domain)).toBe(false)
        await db
            .update(legacyFeatureHandoffs)
            .set({ state: 'committed', committedAt: new Date() })
            .where(eq(legacyFeatureHandoffs.domain, domain))
        expect(await isLegacyFeaturePlatformOwned(domain)).toBe(false)
        expect(await isLegacyFeaturePlatformOwned('monitoring')).toBe(true)
    } finally {
        await db.transaction(async (transaction) => {
            await transaction
                .delete(legacyFeatureHandoffs)
                .where(eq(legacyFeatureHandoffs.installationId, installationId))
            await transaction
                .delete(appRuntimeInstallations)
                .where(eq(appRuntimeInstallations.id, installationId))
        })
    }
})
