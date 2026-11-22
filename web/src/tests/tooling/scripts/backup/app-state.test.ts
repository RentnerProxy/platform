import { expect, spyOn, test } from 'bun:test'
import * as filesystem from 'node:fs/promises'
import { pathToFileURL } from 'node:url'
import { copyCoverageFixtureModules } from '@/tests/Helpers/coverageFixture.ts'
import { createHash } from 'node:crypto'
import { mkdir, mkdtemp, open, readFile, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import {
    appStateInstallations,
    appStateName,
    controllerAllocation,
    inspectPortableAppStateFile,
    maximumAppStateBytes,
    portableAppStateName,
    readAppStateMember,
    validateAppStateMember,
} from '../../../../../../scripts/backup/app-state.ts'
import {
    parseBackupMetadata,
    validateStateArchiveFile,
} from '../../../../../../scripts/backup/format.ts'
import * as productionEnvelope from '../../../../../../scripts/backup/offhost/envelope.ts'
import { publishProductionBackup } from '../../../../../../scripts/backup/publication.ts'
import { assertBackupAppRows } from '../../../../../../docker/web/validate-backup.ts'
import {
    readSnapshotMetadata,
    snapshotProductionRestore,
} from '../../../../../../scripts/backup/restore-snapshot.ts'
import { maximumBackupMetadataBytes } from '../../../../../../scripts/backup/validation.ts'
import { postgresCommand } from '../../../../../../scripts/backup/volume-commands.ts'

const digest = (data: Buffer) => ({
    bytes: data.length,
    sha256: createHash('sha256').update(data).digest('hex'),
})
const legacyInstallation = { id: 'kiri-1', appId: 'dev.example.kiri', uid: 20000, generation: 3 }
const installation = { ...legacyInstallation, authorityRecorded: true }
const singleSnapshot = Buffer.from(
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
    expect(appStateInstallations(singleSnapshot)).toEqual([installation])
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

test('streams portable app members and rejects corrupt or ambiguous app state', async () => {
    const workspace = await mkdtemp(join(tmpdir(), 'rp-portable-app-backup-'))
    const staging = join(workspace, 'staging')
    const published = join(workspace, 'published')
    const restore = join(workspace, 'restore')
    const path = join(workspace, portableAppStateName)
    const archive = join(staging, 'controller-state.tar')
    const target = join(workspace, 'snapshot')
    const corruptTarget = join(workspace, 'corrupt-snapshot')
    const data = Buffer.from('{}')
    const checkpoint = Buffer.from('{}')
    const packageBytes = Buffer.alloc(192 * 1024, 0x8a)
    const database = Buffer.from('PGDMP')
    const header = Buffer.from(
        JSON.stringify({
            formatVersion: 2,
            installations: {
                [installation.id]: {
                    appId: installation.appId,
                    uid: installation.uid,
                    generation: installation.generation,
                    authorityRecorded: installation.authorityRecorded,
                },
            },
            members: [
                { kind: 'data', key: 'files', ...digest(data) },
                { kind: 'checkpoint', key: 'catalog', ...digest(checkpoint) },
                { kind: 'package', key: digest(packageBytes).sha256, ...digest(packageBytes) },
                { kind: 'database', key: String(installation.uid), ...digest(database) },
            ],
        }),
    )
    const prefix = Buffer.alloc(12)
    prefix.write('RPAPPB2\0')
    prefix.writeUInt32BE(header.length, 8)
    const snapshot = Buffer.concat([prefix, header, data, checkpoint, packageBytes, database])
    const applications = { ...digest(snapshot), installations: [installation] }
    try {
        await Promise.all([mkdir(staging), mkdir(restore), writeFile(path, snapshot)])
        const file = await open(path, 'r')
        try {
            let progress = 0
            expect(await inspectPortableAppStateFile(file, undefined, () => progress++)).toEqual(
                applications,
            )
            expect(progress).toBeGreaterThanOrEqual(6)
        } finally {
            await file.close()
        }
        const tar = Bun.spawn(['tar', '-cf', archive, '-C', workspace, portableAppStateName], {
            stdout: 'ignore',
            stderr: 'pipe',
        })
        expect(await tar.exited, await new Response(tar.stderr).text()).toBe(0)
        const crowdSec = join(staging, 'crowdsec-state.tar')
        const emptyArchive = Bun.spawn(['tar', '-cf', crowdSec, '-C', restore, '.'], {
            stdout: 'ignore',
            stderr: 'pipe',
        })
        expect(await emptyArchive.exited, await new Response(emptyArchive.stderr).text()).toBe(0)
        const key = Buffer.from(Buffer.alloc(32, 0x42).toString('base64'))
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
            controllerState: {
                ...digest(await readFile(archive)),
                archive: 'controller-state.tar',
            },
            crowdSecState: { ...digest(await readFile(crowdSec)), archive: 'crowdsec-state.tar' },
            deployment: { publicOrigin: 'https://kiri.example.test', trustedProxyCidrs: '' },
            source: { imageId: 'sha256:' + '0'.repeat(64), revision: null, version: null },
        }
        const metadata = parseBackupMetadata({ ...base, version: 6, applications })
        expect(() =>
            parseBackupMetadata({
                ...base,
                version: 6,
                applications: { ...applications, bytes: 8 * 1024 ** 3 + 1 },
            }),
        ).toThrow()
        await publishProductionBackup(staging, published, metadata)
        expect((await filesystem.readdir(published)).toSorted()).toEqual([
            'app-encryption-key',
            'controller-state.tar',
            'crowdsec-state.tar',
            'metadata.json',
            'postgres.dump',
        ])
        expect((await snapshotProductionRestore(published, restore)).metadata).toEqual(metadata)
        expect(await readFile(join(restore, portableAppStateName))).toEqual(snapshot)
        const stateFile = await open(join(restore, 'controller-state.tar'), 'r+')
        try {
            const entries = await validateStateArchiveFile(stateFile, 'controller')
            const [entry] = entries
            expect(entry?.name).toBe(portableAppStateName)
            const capacity = await validateAppStateMember(stateFile, entries, metadata, { target })
            expect(await readFile(target)).toEqual(snapshot)
            if (process.platform !== 'win32')
                expect((await filesystem.stat(target)).mode & 0o777).toBe(0o600)
            expect(controllerAllocation(entries, metadata, capacity).payloadBytes).toBeGreaterThan(
                snapshot.length,
            )
            for (const invalid of [
                [],
                [...entries, { ...entry!, name: appStateName }],
                [{ ...entry!, name: 'nested/' + portableAppStateName }],
                [{ ...entry!, name: portableAppStateName + '/data' }],
                [{ ...entry!, name: '.rentnerproxy-app-state-v3' }],
            ]) {
                // oxlint-disable-next-line no-await-in-loop -- Each malformed archive must fail independently.
                await expect(validateAppStateMember(stateFile, invalid, metadata)).rejects.toThrow(
                    'does not match backup version',
                )
            }
            const legacy = parseBackupMetadata({ ...base, version: 5, applications })
            await expect(validateAppStateMember(stateFile, entries, legacy)).rejects.toThrow(
                'does not match backup version',
            )
            const plain = parseBackupMetadata({ ...base, version: 4 })
            await expect(validateAppStateMember(stateFile, entries, plain)).rejects.toThrow(
                'does not match backup version',
            )
            const mismatched = parseBackupMetadata({
                ...metadata,
                applications: { ...applications, installations: [{ ...installation, uid: 20001 }] },
            })
            await expect(validateAppStateMember(stateFile, entries, mismatched)).rejects.toThrow(
                'identities differ',
            )
            await stateFile.write(Buffer.of(0), 0, 1, entry!.bodyOffset + snapshot.length - 1)
            await expect(
                validateAppStateMember(stateFile, entries, metadata, { target: corruptTarget }),
            ).rejects.toThrow('member checksum mismatch')
            await expect(filesystem.stat(corruptTarget)).rejects.toThrow()
            await stateFile.write(Buffer.alloc(4, 0xff), 0, 4, entry!.bodyOffset + 8)
            await expect(validateAppStateMember(stateFile, entries, metadata)).rejects.toThrow(
                'header size',
            )
        } finally {
            await stateFile.close()
        }
    } finally {
        await rm(workspace, { recursive: true, force: true })
    }
})

test('app snapshot survives publication and encrypted recovery and rejects downgrade, substitution and omission', async () => {
    const workspace = await mkdtemp(join(tmpdir(), 'rp-kiri-backup-'))
    try {
        const installations = Array.from({ length: 256 }, (_, index) => ({
            id: 'kiri-' + String(index).padStart(59, '0'),
            appId: 'dev.example.' + String(index).padStart(86, 'a'),
            uid: 20000 + index,
            generation: Number.MAX_SAFE_INTEGER,
            authorityRecorded: true,
        }))
        const slots = Object.fromEntries(
            installations.map((slot) => [
                slot.id,
                Object.assign(
                    { removal: 'installed', databaseProvisioned: false, written: null },
                    slot,
                ),
            ]),
        )
        const data = Object.fromEntries(
            installations.map((slot) => [
                slot.uid,
                [{ path: 'note', mode: 384, contents: 'a2lyaQ==' }],
            ]),
        )
        const snapshot = Buffer.from(
            JSON.stringify({ formatVersion: 1, installations: slots, data }),
        )
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
            applications: { ...digest(snapshot), installations },
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
        const published = await readFile(join(source, 'metadata.json'))
        expect(published.length).toBeGreaterThan(65_536)
        const id = digest(published).sha256
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

        const recoveryKey = productionEnvelope.createRecoveryKey()
        // Exercise the application member through the fallback envelope with deterministic
        // workspace capacity. Native envelope interoperability has its own fixture.
        let envelope = productionEnvelope
        const controllerPath = '/usr/local/bin/rentnerproxy-controller'
        if (process.platform === 'linux' && (await Bun.file(controllerPath).exists())) {
            const moduleName = 'scripts/backup/offhost/envelope.ts'
            const code = join(workspace, 'code')
            await copyCoverageFixtureModules(code, [moduleName], {
                [controllerPath]: join(workspace, 'absent-controller'),
            })
            envelope = await import(pathToFileURL(join(code, moduleName)).href)
        }
        const statfs = filesystem.statfs
        const fixtureStats = await statfs(workspace)
        const capacity = spyOn(filesystem, 'statfs').mockImplementation(((
            ...args: Parameters<typeof statfs>
        ) => {
            if (args[0] === workspace && !args[1]?.bigint) {
                return Promise.resolve({
                    ...fixtureStats,
                    bavail: Math.ceil((4 * 1024 ** 3) / fixtureStats.bsize),
                })
            }
            return statfs(...args)
        }) as typeof statfs)
        try {
            await envelope.encryptBackup(source, encrypted, recoveryKey)
            await envelope.decryptBackup(encrypted, restored, recoveryKey)
            expect(capacity.mock.calls.some(([path]) => path === workspace)).toBe(true)
        } finally {
            capacity.mockRestore()
        }
        expect((await readSnapshotMetadata(restored, id)).metadata).toEqual(metadata)
        expect(maximumBackupMetadataBytes).toBe(512 * 1024)
        const padded = Buffer.alloc(maximumBackupMetadataBytes, 32)
        published.copy(padded)
        await writeFile(join(input, 'metadata.json'), padded)
        expect((await readSnapshotMetadata(input)).metadata).toEqual(metadata)
        await writeFile(join(input, 'metadata.json'), Buffer.concat([padded, Buffer.from(' ')]))
        await expect(readSnapshotMetadata(input)).rejects.toThrow('too large')
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
