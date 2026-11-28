import { afterEach, beforeEach, describe, expect, test } from 'bun:test'
import { updateNotificationConfigurationSchema } from '@/lib/Notifications/validation.ts'
import {
    buildNotificationConfiguration,
    DEFAULT_NOTIFICATION_CONFIGURATION,
    openNotificationDestination,
    summarizeNotificationConfiguration,
} from '@/server/Notifications/notification-settings.ts'
import { storedNotificationConfigurationSchema } from '@/server/Notifications/notification-settings.validation.ts'
import type { UpdateNotificationConfigurationInput } from '@/lib/Notifications/Types/validation.types.ts'

const originalKey = process.env.APP_ENCRYPTION_KEY
beforeEach(() => {
    process.env.APP_ENCRYPTION_KEY = Buffer.alloc(32, 45).toString('base64')
})
afterEach(() => {
    if (originalKey === undefined) delete process.env.APP_ENCRYPTION_KEY
    else process.env.APP_ENCRYPTION_KEY = originalKey
})

function input(): UpdateNotificationConfigurationInput {
    return {
        expectedRevision: 0,
        enabled: true,
        channels: [
            {
                id: '00000000-0000-4000-8000-000000000001',
                name: 'Office webhook',
                kind: 'webhook',
                enabled: true,
                events: ['certificate_renewal', 'ddns', 'proxy_configuration'],
                minimumSeverity: 'warning',
                thresholdSeconds: 60,
                recovery: true,
                destination: {
                    kind: 'webhook',
                    url: 'https://receiver.example.test/secret-path?secret=query',
                    authorizationToken: 'secret-bearer',
                    allowedPrivateCidrs: [],
                },
            },
        ],
    }
}

describe('notification channel secrets and revisions', () => {
    test('retains server ownership through edits and never exposes it in public summaries', async () => {
        const original = await buildNotificationConfiguration(
            DEFAULT_NOTIFICATION_CONFIGURATION,
            input(),
        )
        const ownerUserId = '00000000-0000-4000-8000-000000000099'
        const current = {
            ...original,
            channels: original.channels.map((channel) =>
                Object.assign({}, channel, { ownerUserId }),
            ),
        }
        const { destination: _destination, ...policy } = input().channels[0]!
        const updated = await buildNotificationConfiguration(current, {
            expectedRevision: current.revision,
            enabled: true,
            channels: [{ ...policy, name: 'Changed' }],
        })
        expect(storedNotificationConfigurationSchema.safeParse(updated).success).toBeTrue()
        expect(updated.channels[0]?.ownerUserId).toBe(ownerUserId)
        expect(JSON.stringify(summarizeNotificationConfiguration(updated))).not.toContain(
            ownerUserId,
        )
        expect(
            updateNotificationConfigurationSchema.safeParse({
                ...input(),
                channels: [{ ...input().channels[0], ownerUserId }],
            }).success,
        ).toBeFalse()
    })

    test('encrypts the complete destination and returns a write-only public summary', async () => {
        const stored = await buildNotificationConfiguration(
            DEFAULT_NOTIFICATION_CONFIGURATION,
            input(),
        )
        expect(storedNotificationConfigurationSchema.safeParse(stored).success).toBeTrue()
        const serialized = JSON.stringify(stored)
        for (const secret of [
            'receiver.example.test',
            'secret-path',
            'secret-bearer',
            'secret=query',
        ])
            expect(serialized).not.toContain(secret)
        const restored = storedNotificationConfigurationSchema.parse(JSON.parse(serialized))
        expect(await openNotificationDestination(restored.channels[0]!)).toEqual(
            input().channels[0]!.destination!,
        )
        const summary = JSON.stringify(summarizeNotificationConfiguration(restored))
        expect(summary).not.toContain('ciphertext')
        expect(summary).not.toContain('destination":')
        expect(summary).toContain('"hasAuthorization":true')
    })

    test('retains a write-only destination without revoking unchanged channel jobs', async () => {
        const current = await buildNotificationConfiguration(
            DEFAULT_NOTIFICATION_CONFIGURATION,
            input(),
        )
        const { destination: _destination, ...policy } = input().channels[0]!
        const updated = await buildNotificationConfiguration(current, {
            expectedRevision: current.revision,
            enabled: true,
            channels: [policy],
        })
        expect(updated.revision).toBe(2)
        expect(updated.channels[0]?.revision).toBe(1)
        expect(updated.channels[0]?.destination).toEqual(current.channels[0]?.destination)
        const renamed = await buildNotificationConfiguration(updated, {
            expectedRevision: 2,
            enabled: true,
            channels: [{ ...policy, name: 'Renamed' }],
        })
        expect(renamed.channels[0]?.revision).toBe(3)
    })

    test('does not reuse the generation of a removed channel when its ID is re-added', async () => {
        const original = await buildNotificationConfiguration(
            DEFAULT_NOTIFICATION_CONFIGURATION,
            input(),
        )
        const removed = await buildNotificationConfiguration(original, {
            expectedRevision: 1,
            enabled: true,
            channels: [],
        })
        const readded = await buildNotificationConfiguration(removed, {
            ...input(),
            expectedRevision: 2,
        })
        expect(readded.channels[0]?.id).toBe(original.channels[0]?.id)
        expect(readded.channels[0]?.revision).toBeGreaterThan(original.channels[0]!.revision)
        expect(
            storedNotificationConfigurationSchema.safeParse({ ...readded, revision: 1 }).success,
        ).toBeFalse()
    })

    test('requires an explicit complete replacement when changing a destination kind', async () => {
        const current = await buildNotificationConfiguration(
            DEFAULT_NOTIFICATION_CONFIGURATION,
            input(),
        )
        const { destination: _destination, ...policy } = input().channels[0]!
        await expect(
            buildNotificationConfiguration(current, {
                expectedRevision: 1,
                enabled: true,
                channels: [{ ...policy, kind: 'email' }],
            }),
        ).rejects.toMatchObject({ code: 'destination_required' })
        const changed = await buildNotificationConfiguration(current, {
            expectedRevision: 1,
            enabled: true,
            channels: [
                {
                    ...policy,
                    destination: {
                        kind: 'webhook',
                        url: 'https://different.example.test/events',
                        authorizationToken: null,
                        allowedPrivateCidrs: [],
                    },
                },
            ],
        })
        expect(await openNotificationDestination(changed.channels[0]!)).toMatchObject({
            authorizationToken: null,
            url: 'https://different.example.test/events',
        })
        expect(changed.channels[0]?.hasAuthorization).toBeFalse()
    })

    test('binds ciphertext to its channel and fails closed on a wrong application key', async () => {
        const current = await buildNotificationConfiguration(
            DEFAULT_NOTIFICATION_CONFIGURATION,
            input(),
        )
        await expect(
            openNotificationDestination({
                ...current.channels[0]!,
                id: '00000000-0000-4000-8000-000000000002',
            }),
        ).rejects.toMatchObject({ message: 'configuration_unavailable' })
        process.env.APP_ENCRYPTION_KEY = Buffer.alloc(32, 46).toString('base64')
        await expect(openNotificationDestination(current.channels[0]!)).rejects.toMatchObject({
            message: 'configuration_unavailable',
        })
    })

    test('rejects stale revisions, missing destinations and blocked network configuration', async () => {
        await expect(
            buildNotificationConfiguration(DEFAULT_NOTIFICATION_CONFIGURATION, {
                ...input(),
                expectedRevision: 1,
            }),
        ).rejects.toMatchObject({ code: 'configuration_conflict' })
        const { destination: _destination, ...policy } = input().channels[0]!
        await expect(
            buildNotificationConfiguration(DEFAULT_NOTIFICATION_CONFIGURATION, {
                ...input(),
                channels: [policy],
            }),
        ).rejects.toMatchObject({ code: 'destination_required' })
        await expect(
            buildNotificationConfiguration(DEFAULT_NOTIFICATION_CONFIGURATION, {
                ...input(),
                channels: [
                    {
                        ...policy,
                        destination: {
                            kind: 'webhook',
                            url: 'http://169.254.169.254/metadata',
                            authorizationToken: null,
                            allowedPrivateCidrs: ['10.0.0.0/8'],
                        },
                    },
                ],
            }),
        ).rejects.toMatchObject({ code: 'destination_blocked' })
    })

    test('keeps restored configuration paused until explicit activation', async () => {
        const paused = {
            ...DEFAULT_NOTIFICATION_CONFIGURATION,
            revision: 1,
            pausedAfterRestore: true,
        }
        const saved = await buildNotificationConfiguration(paused, {
            ...input(),
            expectedRevision: 1,
            enabled: false,
        })
        expect(saved.pausedAfterRestore).toBeTrue()
        const enabled = await buildNotificationConfiguration(saved, {
            ...input(),
            expectedRevision: 2,
        })
        expect(enabled.pausedAfterRestore).toBeFalse()
        expect(
            storedNotificationConfigurationSchema.safeParse({
                ...enabled,
                pausedAfterRestore: true,
            }).success,
        ).toBeFalse()
    })

    test('bounds and strictly validates channel administration inputs', () => {
        expect(updateNotificationConfigurationSchema.safeParse(input()).success).toBeTrue()
        expect(
            updateNotificationConfigurationSchema.safeParse({ ...input(), token: 'unexpected' })
                .success,
        ).toBeFalse()
        expect(
            updateNotificationConfigurationSchema.safeParse({
                ...input(),
                channels: [input().channels[0], input().channels[0]],
            }).success,
        ).toBeFalse()
        expect(
            updateNotificationConfigurationSchema.safeParse({
                ...input(),
                channels: [{ ...input().channels[0], thresholdSeconds: 86_401 }],
            }).success,
        ).toBeFalse()
        expect(
            updateNotificationConfigurationSchema.safeParse({
                ...input(),
                channels: [{ ...input().channels[0], kind: 'email' }],
            }).success,
        ).toBeFalse()
    })
})

const withCategories = (appCategories: unknown) => ({
    ...input(),
    channels: [{ ...input().channels[0]!, events: ['app_incident'], appCategories }],
})

const parse = (value: unknown) =>
    updateNotificationConfigurationSchema.safeParse(withCategories(value)).success

describe('app incident subscriptions on a channel', () => {
    test('older channels without app categories stay valid', () => {
        expect(updateNotificationConfigurationSchema.safeParse(input()).success).toBeTrue()
        const channel = input().channels[0]!
        expect(channel.appCategories).toBeUndefined()
    })

    test('accepts qualified app category keys and refuses everything else', () => {
        expect(parse(['acme.monitor/disk', 'acme.monitor/upstream-down'])).toBeTrue()
        expect(parse([])).toBeTrue()
        expect(parse(['acme.monitor/disk', 'acme.monitor/disk'])).toBeFalse()
        for (const key of [
            'disk',
            '/disk',
            'acme.monitor/',
            'Acme.Monitor/disk',
            'acme.monitor/Disk',
            'acme/disk',
            'x'.repeat(300),
        ])
            expect(parse([key])).toBeFalse()
        const many = Array.from({ length: 65 }, (_, index) => `acme.monitor/category-${index}`)
        expect(parse(many.slice(0, 64))).toBeTrue()
        expect(parse(many)).toBeFalse()
    })

    test('keeps the categories through edits, revisions and summaries', async () => {
        const channel = {
            ...input().channels[0]!,
            events: ['app_incident' as const],
            appCategories: ['acme.monitor/disk'],
        }
        const built = await buildNotificationConfiguration(DEFAULT_NOTIFICATION_CONFIGURATION, {
            ...input(),
            channels: [channel],
        })
        expect(storedNotificationConfigurationSchema.safeParse(built).success).toBeTrue()
        expect(built.channels[0]?.appCategories).toEqual(['acme.monitor/disk'])
        expect(summarizeNotificationConfiguration(built).channels[0]?.appCategories).toEqual([
            'acme.monitor/disk',
        ])
        // The same policy without a new destination keeps its revision; a changed list revises it.
        const { destination: _destination, ...policy } = channel
        const same = await buildNotificationConfiguration(built, {
            expectedRevision: built.revision,
            enabled: true,
            channels: [policy],
        })
        expect(same.channels[0]?.revision).toBe(built.channels[0]?.revision)
        const changed = await buildNotificationConfiguration(built, {
            expectedRevision: built.revision,
            enabled: true,
            channels: [{ ...policy, appCategories: ['acme.monitor/upstream'] }],
        })
        expect(changed.channels[0]?.revision).toBe(built.revision + 1)
    })
})
