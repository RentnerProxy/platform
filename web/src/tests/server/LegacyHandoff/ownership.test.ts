import { expect, test } from 'bun:test'

import { appProviderProfiles } from '@/server/AppRuntime/contract.ts'
import type { AuthTransaction } from '@/server/Auth/Core/Types/database.types.ts'
import {
    lockLegacyFeatureDomain,
    withPlatformOwnedLegacyFeature,
} from '@/server/LegacyHandoff/ownership.server.ts'
import type { LegacyFeatureDomain } from '@/server/LegacyHandoff/Types/legacy-handoff.types.ts'

test('an unknown domain is refused before any lock is taken', async () => {
    let executed = false
    const transaction = {
        execute: async () => {
            executed = true
            return []
        },
    } as unknown as AuthTransaction
    const unknown = 'billing' as LegacyFeatureDomain

    await expect(lockLegacyFeatureDomain(transaction, unknown)).rejects.toThrow(TypeError)
    await expect(
        withPlatformOwnedLegacyFeature(transaction, unknown, async () => 'written'),
    ).rejects.toThrow(TypeError)
    expect(executed).toBe(false)
})

test('a writer that cannot take the shared domain lock skips without reading ownership', async () => {
    const queries: string[] = []
    const transaction = {
        execute: async () => {
            queries.push('lock')
            return [{ locked: false }]
        },
        select: () => {
            throw new Error('ownership must not be read without the lock')
        },
    } as unknown as AuthTransaction
    let ran = false

    for (const domain of appProviderProfiles) {
        // oxlint-disable-next-line no-await-in-loop -- Each domain is checked on its own.
        const result = await withPlatformOwnedLegacyFeature(transaction, domain, async () => {
            ran = true
        })
        expect(result).toEqual({ owned: false })
    }
    expect(ran).toBe(false)
    expect(queries).toHaveLength(appProviderProfiles.length)
})
