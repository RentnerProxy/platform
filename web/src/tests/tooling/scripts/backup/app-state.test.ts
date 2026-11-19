import { expect, test } from 'bun:test'
import { createHash } from 'node:crypto'
import { mkdir, mkdtemp, open, readFile, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import {
    appStateInstallations,
    appStateName,
    maximumAppStateBytes,
    readAppStateMember,
} from '../../../../../../scripts/backup/app-state.ts'
import {
    parseBackupMetadata,
    validateStateArchiveFile,
} from '../../../../../../scripts/backup/format.ts'
import {
    createRecoveryKey,
    decryptBackup,
    encryptBackup,
} from '../../../../../../scripts/backup/offhost/envelope.ts'
import { publishProductionBackup } from '../../../../../../scripts/backup/publication.ts'
import { assertBackupAppRows } from '../../../../../../docker/web/validate-backup.ts'
import { readSnapshotMetadata } from '../../../../../../scripts/backup/restore-snapshot.ts'
import { postgresCommand } from '../../../../../../scripts/backup/volume-commands.ts'

const digest = (data: Buffer) => ({
    bytes: data.length,
    sha256: createHash('sha256').update(data).digest('hex'),
})
const legacyInstallation = { id: 'kiri-1', appId: 'dev.example.kiri', uid: 20000, generation: 3 }
const installation = { ...legacyInstallation, authorityRecorded: true }
const snapshot = Buffer.from(
    JSON.stringify({
        formatVersion: 1,
        installations: {
            'kiri-1': {
                ...installation,
                removal: 'installed',
                databaseProvisioned: false,
                written: null,
            },
        },
        data: { 20000: [{ path: 'note', mode: 384, contents: 'a2lyaQ==' }] },
    }),
)

test('checks installation identity including the candidate-only case', () => {
    expect(appStateInstallations(snapshot)).toEqual([installation])
    expect(() => assertBackupAppRows([installation], [{ ...installation }])).not.toThrow()
    expect(() => assertBackupAppRows([legacyInstallation], [installation])).not.toThrow()
    expect(() => assertBackupAppRows([legacyInstallation], [])).toThrow()
    expect(() => assertBackupAppRows([{ ...legacyInstallation, generation: 0 }], [])).not.toThrow()
    expect(
        appStateInstallations(
            Buffer.from(
                JSON.stringify({
                    formatVersion: 1,
                    installations: { 'kiri-1': legacyInstallation },
                }),
            ),
        ),
    ).toEqual([legacyInstallation])
    expect(() => assertBackupAppRows([], [installation])).toThrow()
    expect(() => assertBackupAppRows([installation], [{ ...installation, uid: 20001 }])).toThrow()
    expect(() => assertBackupAppRows([installation], [])).toThrow()
    const reserved = { ...installation, authorityRecorded: false }
    expect(() => assertBackupAppRows([reserved], [])).not.toThrow()
    expect(() => assertBackupAppRows([reserved], [installation])).toThrow()

    const bytes = Buffer.from(
        JSON.stringify({ formatVersion: 1, installations: { 'kiri-1': reserved } }),
    )
    expect(appStateInstallations(bytes)).toEqual([reserved])
    expect(() =>
        assertBackupAppRows(
            [installation, { ...installation, id: 'kiri-2', uid: 20001 }],
            [installation, installation],
        ),
    ).toThrow()
})

test('app snapshot survives publication and encrypted recovery and rejects downgrade, substitution and omission', async () => {
    const workspace = await mkdtemp(join(tmpdir(), 'rp-kiri-backup-'))
    try {
        const staging = join(workspace, 'staging')
        const input = join(workspace, 'input')
        const source = join(workspace, 'source')
        const restored = join(workspace, 'restored')
        const encrypted = join(workspace, 'backup.enc')
        await Promise.all([mkdir(staging), mkdir(input)])
        const archive = async (name: string, member: string) => {
            const output = join(staging, name)
            const child = Bun.spawn(['tar', '-cf', output, '-C', input, member], {
                stdout: 'ignore',
                stderr: 'pipe',
            })
            expect(await child.exited, await new Response(child.stderr).text()).toBe(0)
            return digest(await readFile(output))
        }
        const crowdsec = await archive('crowdsec-state.tar', '.')
        await writeFile(join(input, appStateName), snapshot)
        const controller = await archive('controller-state.tar', appStateName)
        const key = Buffer.from(Buffer.alloc(32, 15).toString('base64'))
        const dump = Buffer.from('synthetic-main-database')
        await Promise.all([
            writeFile(join(staging, 'app-encryption-key'), key),
            writeFile(join(staging, 'postgres.dump'), dump),
        ])
        const base = {
            format: 'rentnerproxy-production-backup',
            createdAt: '2026-11-18T00:00:00.000Z',
            redis: 'excluded',
            applicationEncryptionKey: { ...digest(key), file: 'app-encryption-key' },
            postgres: {
                ...digest(dump),
                database: 'rentnerproxy',
                user: 'rentnerproxy',
                dump: 'postgres.dump',
            },
            controllerState: { ...controller, archive: 'controller-state.tar' },
            crowdSecState: { ...crowdsec, archive: 'crowdsec-state.tar' },
            deployment: { publicOrigin: 'https://kiri.example.test', trustedProxyCidrs: '' },
            source: {
                imageId: null,
                revision: null,
                version: 'synthetic',
                buildSha256: 'a'.repeat(64),
            },
        }
        const metadata = parseBackupMetadata({
            ...base,
            version: 5,
            applications: { ...digest(snapshot), installations: [installation] },
        })
        const sized = (bytes: number) =>
            parseBackupMetadata({
                ...metadata,
                applications: { ...digest(snapshot), bytes, installations: [installation] },
            })
        expect(maximumAppStateBytes).toBe(64 * 1024 ** 2)
        expect(() => sized(maximumAppStateBytes)).not.toThrow()
        expect(() => sized(maximumAppStateBytes + 1)).toThrow()
        await publishProductionBackup(staging, source, metadata)
        const id = digest(await readFile(join(source, 'metadata.json'))).sha256
        expect((await readSnapshotMetadata(source, id)).metadata).toEqual(metadata)
        await expect(readSnapshotMetadata(source, '0'.repeat(64))).rejects.toThrow(
            'identity mismatch',
        )
        const preflight = postgresCommand('inventory', '/backup', true, id)
        expect(preflight).toContain('--app-backup verify /backup/' + appStateName)
        expect(preflight.indexOf('--app-backup verify')).toBeLessThan(
            preflight.indexOf('gosu postgres postgres'),
        )
        expect(preflight).toContain('--check-app-restore-inventory /backup ' + id)
        expect(() => postgresCommand('inventory', '/backup', true)).toThrow()

        const recoveryKey = createRecoveryKey()
        await encryptBackup(source, encrypted, recoveryKey)
        await decryptBackup(encrypted, restored, recoveryKey)
        const file = await open(join(restored, 'controller-state.tar'), 'r')
        try {
            const entries = await validateStateArchiveFile(file, 'controller')
            const recovered = await readAppStateMember(file, entries, metadata)
            expect(recovered).toEqual(snapshot)
            const nativeController =
                process.env.RENTNERPROXY_TEST_CONTROLLER ?? Bun.which('rentnerproxy-controller')
            if (process.platform === 'linux' && nativeController) {
                const member = join(workspace, appStateName)
                await writeFile(member, recovered!, { flag: 'wx', mode: 0o600 })
                const inspect = Bun.spawn([nativeController, '--app-backup', 'inspect', member], {
                    stdout: 'ignore',
                    stderr: 'pipe',
                })
                expect(await inspect.exited, await new Response(inspect.stderr).text()).toBe(0)
            }
            await expect(
                readAppStateMember(file, entries, parseBackupMetadata({ ...base, version: 4 })),
            ).rejects.toThrow()
            await expect(readAppStateMember(file, [], metadata)).rejects.toThrow()
            const changed = parseBackupMetadata({
                ...metadata,
                applications: {
                    ...digest(snapshot),
                    installations: [{ ...installation, uid: 20001 }],
                },
            })
            await expect(readAppStateMember(file, entries, changed)).rejects.toThrow()
        } finally {
            await file.close()
        }
    } finally {
        await rm(workspace, { recursive: true, force: true })
    }
})
