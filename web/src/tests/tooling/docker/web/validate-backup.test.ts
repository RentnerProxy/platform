import { describe, expect, test } from 'bun:test'
import { createCipheriv, createHash } from 'node:crypto'

import {
    appDatabaseEvidenceSql,
    assertBackupAppState,
    assertCompatibleBackupHistory,
    assertLegacyHandoffParts,
    assertSupportedBackupVersion,
    decryptBackupSecret,
    isMigrationJournal,
    maximumHandoffPartCiphertextBytes,
    parseAppDatabaseEvidence,
    validateNotificationBackupSecrets,
} from '../../../../../../docker/web/validate-backup.ts'
import { LEGACY_HANDOFF_LIMITS } from '@/config/legacy-handoff.config.ts'
import { NOTIFICATION_LIMITS, NOTIFICATION_SECRET_CONTEXT } from '@/config/notifications.config.ts'
import type {
    BackupMigrationJournal,
    BackupMigrationRow,
} from '../../../../../../docker/web/Types/validate-backup.types.ts'

const fixtureKey = Buffer.alloc(32, 3)
const fixtureIv = Buffer.alloc(12, 4)
const fixtureContext = 'typed-backup-fixture'

const notificationId = '0198d98a-0000-7000-8000-000000000001'

function notificationFixture(id = notificationId) {
    const cipher = createCipheriv('aes-256-gcm', fixtureKey, fixtureIv)
    cipher.setAAD(Buffer.from(NOTIFICATION_SECRET_CONTEXT + id, 'utf8'))
    return {
        id,
        destination: {
            ciphertext: Buffer.concat([
                cipher.update(
                    JSON.stringify({ kind: 'email', recipients: ['synthetic@example.test'] }),
                ),
                cipher.final(),
                cipher.getAuthTag(),
            ]).toString('base64url'),
            iv: fixtureIv.toString('base64url'),
        },
    }
}

function notificationConfiguration() {
    return {
        version: 1,
        revision: 1,
        enabled: true,
        pausedAfterRestore: false,
        channels: [notificationFixture()],
    }
}

describe('notification backup encryption contract', () => {
    test('authenticates every destination with the configured channel-specific context', () => {
        const configuration = notificationConfiguration()
        configuration.channels.push(notificationFixture('0198d98a-0000-7000-8000-000000000002'))
        expect(() => validateNotificationBackupSecrets(fixtureKey, configuration)).not.toThrow()
        expect(() =>
            validateNotificationBackupSecrets(fixtureKey, JSON.stringify(configuration)),
        ).not.toThrow()
        expect(() =>
            validateNotificationBackupSecrets(fixtureKey, { ...configuration, channels: [] }),
        ).not.toThrow()
        expect(() =>
            validateNotificationBackupSecrets(fixtureKey, {
                ...configuration,
                revision: 4_294_967_295,
            }),
        ).not.toThrow()
    })

    test('rejects a wrong backup key or channel attribution without exposing secrets', () => {
        const configuration = notificationConfiguration()
        expect(() => validateNotificationBackupSecrets(Buffer.alloc(32, 8), configuration)).toThrow(
            'invalid encrypted notification backup configuration',
        )
        configuration.channels[0]!.id = '0198d98a-0000-7000-8000-000000000002'
        expect(() => validateNotificationBackupSecrets(fixtureKey, configuration)).toThrow(
            'invalid encrypted notification backup configuration',
        )
    })

    test('checks later channels even when disabled and the first is valid', () => {
        const configuration = notificationConfiguration()
        configuration.enabled = false
        const corrupt = notificationFixture('0198d98a-0000-7000-8000-000000000002')
        corrupt.destination.ciphertext = Buffer.alloc(32).toString('base64url')
        configuration.channels.push(corrupt)
        expect(() => validateNotificationBackupSecrets(fixtureKey, configuration)).toThrow(
            'invalid encrypted notification backup configuration',
        )
    })

    test.each([
        null,
        '{broken',
        { ...notificationConfiguration(), version: 2 },
        { ...notificationConfiguration(), revision: 4_294_967_296 },
        { ...notificationConfiguration(), revision: -1 },
        { ...notificationConfiguration(), revision: 1.5 },
        { ...notificationConfiguration(), pausedAfterRestore: undefined },
        {
            ...notificationConfiguration(),
            channels: Array.from({ length: NOTIFICATION_LIMITS.channels + 1 }, () =>
                notificationFixture(),
            ),
        },
        {
            ...notificationConfiguration(),
            channels: [notificationFixture(), notificationFixture()],
        },
        {
            ...notificationConfiguration(),
            channels: [{ ...notificationFixture(), id: notificationId.toUpperCase() }],
        },
        {
            ...notificationConfiguration(),
            channels: [
                {
                    ...notificationFixture(),
                    destination: {
                        ciphertext: 'A'.repeat(65_537),
                        iv: fixtureIv.toString('base64url'),
                    },
                },
            ],
        },
        {
            ...notificationConfiguration(),
            channels: [
                {
                    ...notificationFixture(),
                    destination: { ciphertext: 'AA==', iv: fixtureIv.toString('base64url') },
                },
            ],
        },
        {
            ...notificationConfiguration(),
            channels: [
                {
                    ...notificationFixture(),
                    destination: {
                        ciphertext: notificationFixture().destination.ciphertext,
                        iv: 'A'.repeat(15),
                    },
                },
            ],
        },
        { ...notificationConfiguration(), extra: 'A'.repeat(2 * 1_024 * 1_024) },
    ])('rejects malformed or oversized notification storage %#', (configuration) => {
        expect(() => validateNotificationBackupSecrets(fixtureKey, configuration)).toThrow(
            'invalid encrypted notification backup configuration',
        )
    })
})

function encryptedFixture(): Buffer {
    const cipher = createCipheriv('aes-256-gcm', fixtureKey, fixtureIv)
    cipher.setAAD(Buffer.from(fixtureContext, 'utf8'))
    return Buffer.concat([cipher.update('synthetic fixture'), cipher.final(), cipher.getAuthTag()])
}

describe('typed backup secret validation', () => {
    test('authenticates ciphertext with its original key and context', () => {
        expect(
            decryptBackupSecret(fixtureKey, encryptedFixture(), fixtureIv, fixtureContext).toString(),
        ).toBe('synthetic fixture')
    })

    test('rejects a different key or context', () => {
        const ciphertext = encryptedFixture()
        for (const [key, context] of [
            [Buffer.alloc(32, 5), fixtureContext],
            [fixtureKey, 'different-fixture-context'],
        ] as const) {
            expect(() => decryptBackupSecret(key, ciphertext, fixtureIv, context)).toThrow(
                'backup application key cannot decrypt persisted secrets',
            )
        }
    })

    test('rejects modified ciphertext', () => {
        const ciphertext = encryptedFixture()
        ciphertext[0] = (ciphertext[0] ?? 0) ^ 1
        expect(() =>
            decryptBackupSecret(fixtureKey, ciphertext, fixtureIv, fixtureContext),
        ).toThrow('backup application key cannot decrypt persisted secrets')
    })

    test.each([
        [Buffer.alloc(31), fixtureIv, encryptedFixture()],
        [fixtureKey, Buffer.alloc(11), encryptedFixture()],
        [fixtureKey, fixtureIv, Buffer.alloc(16)],
    ])('rejects invalid key, IV or ciphertext dimensions %#', (key, iv, ciphertext) => {
        expect(() => decryptBackupSecret(key, ciphertext, iv, fixtureContext)).toThrow(
            'invalid encrypted backup secret',
        )
    })
})

describe('typed backup journal validation', () => {
    test('accepts the fields needed to verify a migration history', () => {
        expect(
            isMigrationJournal({ entries: [{ tag: '0000_fixture', when: 1_788_000_000_000 }] }),
        ).toBe(true)
    })

    test.each([
        [null],
        [[]],
        [{ entries: 'invalid-fixture' }],
        [{ entries: [null] }],
        [{ entries: [{ tag: 1, when: 1 }] }],
        [{ entries: [{ tag: '0000_fixture', when: 'invalid-fixture' }] }],
    ])('rejects malformed journal input %#', (input) => {
        expect(isMigrationJournal(input)).toBe(false)
    })
})

describe('compatible backup migration prefixes', () => {
    const migrations = [
        { tag: 'fixture_beta_base', when: 1_788_000_000_000, sql: 'select 1;\n' },
        { tag: 'fixture_beta_saved_state', when: 1_788_000_001_000, sql: 'select 2;\n' },
        { tag: 'fixture_later_target', when: 1_788_000_002_000, sql: 'select 3;\n' },
    ] as const
    const journal: BackupMigrationJournal = {
        entries: migrations.map(({ tag, when }) => ({ tag, when })),
    }
    const rows: BackupMigrationRow[] = migrations.map(({ sql, when }) => ({
        hash: createHash('sha256').update(sql).digest('hex'),
        created_at: String(when),
    }))
    const readMigration = (tag: string): Promise<Uint8Array> => {
        const migration = migrations.find((entry) => entry.tag === tag)
        if (!migration) throw new Error('Unexpected synthetic migration')
        return Promise.resolve(Buffer.from(migration.sql))
    }

    test('accepts a shorter v4 beta baseline without reading the later target suffix', async () => {
        assertSupportedBackupVersion({ version: 4 })
        const requested: string[] = []
        await assertCompatibleBackupHistory(rows.slice(0, 2), journal, (tag) => {
            requested.push(tag)
            return readMigration(tag)
        })
        expect(requested).toEqual(['fixture_beta_base', 'fixture_beta_saved_state'])
    })

    test('continues to accept the complete target history and numeric timestamps', async () => {
        await expect(
            assertCompatibleBackupHistory(
                rows.map((row) => ({ ...row, created_at: BigInt(row.created_at) })),
                journal,
                readMigration,
            ),
        ).resolves.toBeUndefined()
    })

    test.each([
        ['empty', []],
        ['longer than the target', [...rows, rows[0]!]],
    ] as const)('rejects %s history before loading SQL', async (_label, input) => {
        const requested: string[] = []
        await expect(
            assertCompatibleBackupHistory(input, journal, (tag) => {
                requested.push(tag)
                return readMigration(tag)
            }),
        ).rejects.toThrow('unsupported backup database version')
        expect(requested).toEqual([])
    })

    test.each([
        ['modified hash', [{ ...rows[0]!, hash: '0'.repeat(64) }]],
        ['modified timestamp', [{ ...rows[0]!, created_at: migrations[0].when + 1 }]],
        ['reordered entries', [rows[1]!, rows[0]!]],
        ['missing middle entry', [rows[0]!, rows[2]!]],
        ['duplicate entry', [rows[0]!, rows[0]!]],
    ] as const)('rejects a %s', async (_label, input) => {
        await expect(assertCompatibleBackupHistory(input, journal, readMigration)).rejects.toThrow(
            'backup migration history is incompatible with the target image',
        )
    })

    test('rejects SQL content that no longer matches the stored hash', async () => {
        await expect(
            assertCompatibleBackupHistory(rows.slice(0, 1), journal, () =>
                Promise.resolve(Buffer.from('select 999;\n')),
            ),
        ).rejects.toThrow('backup migration history is incompatible with the target image')
    })
})

describe('backup format version boundary', () => {
    test('accepts legacy and portable application backup formats', () => {
        expect(() => assertSupportedBackupVersion({ version: 4 })).not.toThrow()
        expect(() => assertSupportedBackupVersion({ version: 5 })).not.toThrow()
        expect(() => assertSupportedBackupVersion({ version: 6 })).not.toThrow()
    })

    test.each([[null], [[]], [{}], [{ version: 3 }], [{ version: 7 }], [{ version: '4' }]])(
        'rejects unsupported metadata before database validation %#',
        (metadata) => {
            expect(() => assertSupportedBackupVersion(metadata)).toThrow(
                'unsupported backup metadata version (supported: v4, v5, v6)',
            )
        },
    )
})

function evidence(
    overrides: Partial<Record<'installations' | 'references' | 'generations', unknown[]>> = {},
) {
    return {
        installations: [{ id: 'greeting', appId: 'fixture.greeting', uid: 20000 }],
        references: ['greeting'],
        generations: [{ installationId: 'greeting', generation: 3 }],
        ...overrides,
    }
}

describe('app rows against the installation journal', () => {
    const journal = [
        { id: 'greeting', appId: 'fixture.greeting', uid: 20000, generation: 3 },
        { id: 'reserved', appId: 'fixture.reserved', uid: 20001, generation: 0 },
    ]

    test('accepts rows of active installations whose journal is not behind the database', () => {
        expect(() => assertBackupAppState(journal, evidence())).not.toThrow()
        expect(() =>
            assertBackupAppState(
                journal,
                evidence({ generations: [{ installationId: 'greeting', generation: 2 }] }),
            ),
        ).not.toThrow()
        expect(() =>
            assertBackupAppState(
                [],
                evidence({ installations: [], references: [], generations: [] }),
            ),
        ).not.toThrow()
    })

    test.each([
        ['an unknown installation', ['greeting', 'removed']],
        ['a reserved installation without authority', ['reserved']],
        ['a non-string identity', [7]],
        [
            'more references than an inventory can hold',
            Array.from({ length: 257 }, () => 'greeting'),
        ],
    ])('rejects dependent rows of %s', (_label, references) => {
        expect(() => assertBackupAppState(journal, evidence({ references }))).toThrow(
            'App database rows reference installations outside the backup inventory',
        )
    })

    test('rejects a recorded generation beyond the journal', () => {
        expect(() =>
            assertBackupAppState(
                journal,
                evidence({ generations: [{ installationId: 'greeting', generation: 4 }] }),
            ),
        ).toThrow('App database generation is ahead of the native installation journal')
    })

    test.each([
        ['an unknown installation', [{ installationId: 'removed', generation: 1 }], 'outside'],
        ['a malformed entry', [null], 'outside'],
        ['an unsafe number', [{ installationId: 'greeting', generation: 2 ** 53 }], 'schema'],
        ['a textual number', [{ installationId: 'greeting', generation: '3' }], 'schema'],
        [
            'too many entries',
            Array.from({ length: 257 }, () => ({ installationId: 'greeting', generation: 1 })),
            'schema',
        ],
    ] as const)('rejects generation evidence with %s', (_label, generations, reason) => {
        expect(() =>
            assertBackupAppState(journal, evidence({ generations: [...generations] })),
        ).toThrow(
            reason === 'outside'
                ? 'App database rows reference installations outside the backup inventory'
                : 'Invalid application schema evidence',
        )
    })

    test('keeps rejecting installation identities that differ from the journal', () => {
        expect(() =>
            assertBackupAppState(
                journal,
                evidence({
                    installations: [{ id: 'greeting', appId: 'fixture.other', uid: 20000 }],
                }),
            ),
        ).toThrow('App database identities differ from the native installation journal')
    })

    test('parses one bounded JSON document with all three row lists', () => {
        expect(parseAppDatabaseEvidence(JSON.stringify(evidence()))).toEqual(evidence())
    })

    test.each([
        undefined,
        { installations: [], references: [], generations: [] },
        '{broken',
        'null',
        '[]',
        JSON.stringify({ installations: [], references: [] }),
        JSON.stringify({ installations: {}, references: [], generations: [] }),
        JSON.stringify({ ...evidence(), padding: 'x'.repeat(256 * 1024) }),
    ])('rejects malformed database evidence %#', (value) => {
        expect(() => parseAppDatabaseEvidence(value)).toThrow(
            'Invalid application schema evidence',
        )
    })

    test('reads every installation-scoped table and the handoff journal only when it exists', () => {
        const tables = [
            'app_runtime_generations',
            'app_runtime_grants',
            'app_runtime_role_permissions',
            'app_runtime_delegations',
            'app_runtime_secrets',
            'app_runtime_pending_secrets',
            'app_runtime_events',
            'app_runtime_event_retention',
            'app_runtime_messages',
            'app_runtime_owned_proxy_hosts',
            'app_runtime_operations',
            'app_runtime_operation_requests',
        ]
        const legacy = appDatabaseEvidenceSql(false)
        const current = appDatabaseEvidenceSql(true)
        for (const table of tables) {
            expect(legacy).toContain('SELECT installation_id FROM rentnerproxy.' + table + ' ')
            expect(current).toContain('SELECT installation_id FROM rentnerproxy.' + table + ' ')
        }
        expect(legacy).not.toContain('legacy_feature_handoffs')
        expect(current).toContain(
            'SELECT installation_id FROM rentnerproxy.legacy_feature_handoffs ',
        )
        expect(current.match(/LIMIT 257/gu)).toHaveLength(3)
    })
})

describe('legacy feature handoff parts in a backup', () => {
    const exported = {
        domain: 'dns',
        installation_id: 'greeting',
        state: 'exported',
        part_count: 3,
    }
    const committed = { ...exported, domain: 'oidc', state: 'committed', part_count: 2 }
    const empty = { ...exported, domain: 'crowdsec', part_count: 0 }
    const parts = { domain: 'dns', count: 3, distinct: 3, first: 0, last: 2 }

    test('accepts exactly the parts of exported handoffs and none of committed ones', () => {
        expect(() => assertLegacyHandoffParts([exported, committed, empty], [parts])).not.toThrow()
        expect(() => assertLegacyHandoffParts([], [])).not.toThrow()
    })

    test('restates the runtime part limit plus the authentication tag', () => {
        expect(maximumHandoffPartCiphertextBytes).toBe(LEGACY_HANDOFF_LIMITS.partBytes + 16)
    })

    test.each([
        ['an exported handoff without parts', [exported], []],
        ['a missing part', [exported], [{ ...parts, count: 2, distinct: 2, last: 1 }]],
        ['a duplicated sequence', [exported], [{ ...parts, distinct: 2 }]],
        ['a sequence gap', [exported], [{ ...parts, first: 1, last: 3 }]],
        ['an extra part', [exported], [{ ...parts, count: 4, distinct: 4, last: 3 }]],
        [
            'parts of a committed handoff',
            [committed],
            [{ ...parts, domain: 'oidc', count: 2, distinct: 2, last: 1 }],
        ],
        [
            'parts of an empty export',
            [empty],
            [{ ...parts, domain: 'crowdsec', count: 1, distinct: 1, last: 0 }],
        ],
        ['parts without a journal row', [], [parts]],
        ['two summaries of one domain', [exported], [parts, parts]],
        ['a malformed summary', [exported], [null]],
        ['a duplicated journal row', [exported, exported], [parts]],
        ['an unknown state', [{ ...exported, state: 'aborted' }], [parts]],
        ['a missing installation', [{ ...exported, installation_id: null }], [parts]],
        ['a fractional count', [{ ...exported, part_count: 2.5 }], [parts]],
        ['a negative count', [{ ...exported, part_count: -1 }], []],
        ['an oversized count', [{ ...exported, part_count: 1025 }], []],
        ['a malformed journal row', ['dns'], []],
        [
            'too many journal rows',
            Array.from({ length: 65 }, (_, index) => ({ ...empty, domain: String(index) })),
            [],
        ],
    ] as const)('rejects %s', (_label, handoffs, summaries) => {
        expect(() => assertLegacyHandoffParts([...handoffs], [...summaries])).toThrow(
            'Invalid legacy feature handoff parts',
        )
    })
})
