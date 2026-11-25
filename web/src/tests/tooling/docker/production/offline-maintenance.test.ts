// oxlint-disable no-await-in-loop -- Verify malformed proof records against one private fixture file.
import { expect, test } from 'bun:test'
import { createHash } from 'node:crypto'
import { chmod, chown, mkdir, mkdtemp, readdir, readFile, rm, writeFile } from 'node:fs/promises'
import { dirname, join } from 'node:path'
import { tmpdir } from 'node:os'
import { copyCoverageFixtureModules } from '@/tests/Helpers/coverageFixture.ts'
import { PORTABLE_APP_BACKUP_VERSION } from '@/config/compatibility.config.ts'
import { portableAppState } from '@/tests/Helpers/portableAppStateFixture.ts'
import { encodeCapturedInstallations } from '../../../../../../scripts/backup/captured-inventory.ts'
import {
    readIsolatedValidationProof,
    readIsolatedValidationCapacity,
} from '../../../../../../docker/production/backups/maintenance.ts'

test.skipIf(process.getuid?.() !== 0)(
    'offline restore accepts only a bounded root-owned isolated-validation proof',
    async () => {
        const root = await mkdtemp(join(tmpdir(), 'rp-validation-proof-')),
            path = join(root, 'proof.json'),
            backupId = 'a'.repeat(64)
        try {
            await writeFile(path, JSON.stringify({ schemaVersion: 1, backupId }), { mode: 0o600 })
            expect(await readIsolatedValidationProof(path)).toBe(backupId)
            await expect(readIsolatedValidationCapacity(path)).rejects.toThrow(
                'repeated with capacity evidence',
            )
            const capacity = {
                schemaVersion: 2,
                backupId,
                databaseBytes: 3 * 1024 ** 3,
                sqlBytes: 5 * 1024 ** 3,
            }
            await writeFile(path, JSON.stringify(capacity))
            expect(await readIsolatedValidationProof(path)).toBe(backupId)
            expect(await readIsolatedValidationCapacity(path)).toEqual({
                backupId,
                databaseBytes: capacity.databaseBytes,
                sqlBytes: capacity.sqlBytes,
            })
            await chmod(path, 0o666)
            await expect(readIsolatedValidationProof(path)).rejects.toThrow('Invalid isolated')
            await chmod(path, 0o600)
            await chown(path, 1, 1)
            await expect(readIsolatedValidationProof(path)).rejects.toThrow('Invalid isolated')
            await chown(path, 0, 0)
            for (const value of [
                null,
                [],
                { schemaVersion: 2, backupId },
                { schemaVersion: 2, backupId, databaseBytes: -1, sqlBytes: 1 },
                {
                    schemaVersion: 2,
                    backupId,
                    databaseBytes: 1,
                    sqlBytes: Number.MAX_SAFE_INTEGER + 1,
                },
                { schemaVersion: '1', backupId },
                { schemaVersion: 1, backupId: 'bad' },
            ]) {
                await writeFile(path, JSON.stringify(value))
                await expect(readIsolatedValidationProof(path)).rejects.toThrow('Invalid isolated')
            }
            await writeFile(path, ' '.repeat(257))
            await expect(readIsolatedValidationProof(path)).rejects.toThrow('Invalid isolated')
            await rm(path)
            await mkdir(path)
            await expect(readIsolatedValidationProof(path)).rejects.toThrow('Invalid isolated')
        } finally {
            await rm(root, { recursive: true, force: true })
        }
    },
)

test.skipIf(process.platform !== 'linux')(
    'backup metadata FIFOs are rejected without waiting for a writer',
    async () => {
        const root = await mkdtemp(join(tmpdir(), 'rp-backup-fifo-')),
            snapshot = join(root, 'snapshot')
        try {
            await mkdir(snapshot)
            const fifo = Bun.spawnSync(['mkfifo', join(root, 'metadata.json')])
            expect(fifo.exitCode).toBe(0)
            const module = new URL(
                '../../../../../../scripts/backup/restore-snapshot.ts',
                import.meta.url,
            ).href
            const child = Bun.spawn(
                [
                    process.execPath,
                    '--no-env-file',
                    '-e',
                    `const {snapshotProductionRestore}=await import(${JSON.stringify(module)});try{await snapshotProductionRestore(process.env.INPUT,process.env.SNAPSHOT);process.exit(1)}catch(error){process.exit(error.message.includes('backup file is missing, invalid or too large')?0:2)}`,
                ],
                {
                    env: { ...process.env, INPUT: root, SNAPSHOT: snapshot },
                    stdout: 'ignore',
                    stderr: 'ignore',
                },
            )
            const timer = setTimeout(() => child.kill('SIGKILL'), 4000)
            try {
                expect(await child.exited).toBe(0)
            } finally {
                clearTimeout(timer)
                if (child.exitCode === null) child.kill('SIGKILL')
            }
        } finally {
            await rm(root, { recursive: true, force: true })
        }
    },
    10000,
)

test
    .skipIf(process.platform !== 'linux' || process.getuid?.() !== 0)
    .each([
        'matching-journal',
        'wrong-journal',
        'wrong-backup-id',
        'malformed-metadata',
        'legacy-metadata',
        'worker-failure',
    ] as const)('Compose portable app recovery dispatch handles %s', async (scenario) => {
    const root = await mkdtemp(join(tmpdir(), 'rp-compose-portable-apps-'))
    const code = join(root, 'code')
    const snapshot = join(root, 'snapshot')
    const state = join(root, 'state')
    const bin = join(root, 'bin')
    const bootstrap = join(root, 'bootstrap.ts')
    const calls = join(root, 'calls')
    const module = 'docker/production/backups/maintenance.ts'
    const proof = { bytes: 1, sha256: 'a'.repeat(64) }
    const version =
        scenario === 'legacy-metadata'
            ? { version: 4 }
            : {
                  version: PORTABLE_APP_BACKUP_VERSION,
                  applications: {
                      ...proof,
                      installations: [
                          { id: 'greeting', appId: 'fixture/greeting', uid: 20000, generation: 1 },
                      ],
                  },
              }
    const metadata =
        scenario === 'malformed-metadata'
            ? '{'
            : JSON.stringify({
                  ...version,
                  format: 'rentnerproxy-production-backup',
                  redis: 'excluded',
                  createdAt: '2026-10-22T00:00:00Z',
                  postgres: {
                      ...proof,
                      dump: 'postgres.dump',
                      database: 'rentnerproxy',
                      user: 'rentnerproxy',
                  },
                  applicationEncryptionKey: { ...proof, file: 'app-encryption-key' },
                  controllerState: { ...proof, archive: 'controller-state.tar' },
                  crowdSecState: { ...proof, archive: 'crowdsec-state.tar' },
                  deployment: { publicOrigin: 'https://proxy.test', trustedProxyCidrs: '' },
                  source: { imageId: 'sha256:' + proof.sha256, revision: null, version: null },
              })
    const id = createHash('sha256').update(metadata).digest('hex')
    try {
        await Promise.all([mkdir(snapshot), mkdir(state), mkdir(bin)])
        await copyCoverageFixtureModules(code, [module], {
            "'/backup'": JSON.stringify(snapshot),
            '"/backup"': JSON.stringify(snapshot),
            '/var/lib/rentnerproxy': state,
            '/opt/rentnerproxy/web/docker/web/bootstrap-secrets.ts': bootstrap,
            '/usr/lib/postgresql/18/bin:/usr/local/bin:/usr/bin:/bin': [
                bin,
                dirname(process.execPath),
                '/usr/local/bin',
                '/usr/bin',
                '/bin',
            ].join(':'),
        })
        await Promise.all([
            writeFile(join(snapshot, 'metadata.json'), metadata),
            writeFile(
                bootstrap,
                `
                    import { appendFileSync } from 'node:fs'
                    if (process.argv[2] !== 'inspect-production-restore') process.exit(95)
                    appendFileSync(${JSON.stringify(calls)}, 'inspect journal\\n')
                    console.log(${JSON.stringify(scenario === 'wrong-journal' ? 'b'.repeat(64) : id)})
                `,
            ),
            writeFile(
                join(bin, 'bash'),
                `#!/usr/bin/env -S bun --no-env-file
                    import { appendFileSync } from 'node:fs'
                    if (process.argv[2] !== '-c') process.exit(96)
                    appendFileSync(${JSON.stringify(calls)}, 'restore worker\\n' + process.argv[3])
                    process.exit(${scenario === 'worker-failure' ? 9 : 0})
                `,
                { mode: 0o755 },
            ),
        ])
        const result = Bun.spawn(
            [
                process.execPath,
                '--no-env-file',
                join(code, module),
                'restore-portable-apps',
                scenario === 'wrong-backup-id' ? 'c'.repeat(64) : id,
            ],
            { stdin: 'ignore', stdout: 'pipe', stderr: 'pipe' },
        )
        const [exit, stdout, stderr] = await Promise.all([
            result.exited,
            new Response(result.stdout).text(),
            new Response(result.stderr).text(),
        ])
        expect(stdout).toBe('')
        if (scenario === 'matching-journal') {
            expect(exit, stderr).toBe(0)
            expect(stderr).toBe('')
        } else {
            expect(exit).toBe(1)
            expect(stderr).toContain('Offline maintenance failed.')
        }
        const invoked = await readFile(calls, 'utf8').catch(() => '')
        if (scenario === 'matching-journal' || scenario === 'worker-failure') {
            expect(invoked.startsWith('inspect journal\nrestore worker\n')).toBe(true)
            expect(invoked).toContain(
                '--app-backup restore-portable ' + snapshot + '/.rentnerproxy-app-state-v2',
            )
        } else if (scenario === 'wrong-journal' || scenario === 'legacy-metadata') {
            expect(invoked).toBe('inspect journal\n')
        } else {
            expect(invoked).toBe('')
        }
    } finally {
        await rm(root, { recursive: true, force: true })
    }
})

test
    .skipIf(process.platform !== 'linux' || process.getuid?.() !== 0)
    .each(['apps', 'empty'] as const)(
    'offline backup archives captured %s state and checks the dump against it',
    async (scenario) => {
        const root = await mkdtemp(join(tmpdir(), 'rp-offline-app-backup-'))
        const code = join(root, 'code')
        const output = join(root, 'output')
        const state = join(root, 'state')
        const bin = join(root, 'bin')
        const bootstrap = join(root, 'bootstrap.ts')
        const source = join(root, 'backup-source.json')
        const envelope = join(root, 'app-state')
        const calls = join(root, 'calls')
        const module = 'docker/production/backups/maintenance.ts'
        const { snapshot, applications } = portableAppState()
        try {
            await Promise.all([
                mkdir(output, { mode: 0o700 }),
                mkdir(join(state, 'proxy/certificates'), { recursive: true }),
                mkdir(join(state, 'crowdsec'), { recursive: true }),
                mkdir(bin),
            ])
            await copyCoverageFixtureModules(code, [module], {
                "'/backup": "'" + output,
                '/var/lib/rentnerproxy': state,
                '/usr/share/rentnerproxy/backup-source.json': source,
                '/opt/rentnerproxy/web/docker/web/bootstrap-secrets.ts': bootstrap,
                '/usr/lib/postgresql/18/bin:/usr/local/bin:/usr/bin:/bin': [
                    bin,
                    dirname(process.execPath),
                    '/usr/local/bin',
                    '/usr/bin',
                    '/bin',
                ].join(':'),
            })
            await Promise.all([
                writeFile(join(state, 'proxy/routes.json'), '{"routes":[]}'),
                writeFile(
                    source,
                    JSON.stringify({
                        imageId: null,
                        revision: null,
                        version: '1.0.0-beta.4',
                        buildSha256: 'b'.repeat(64),
                    }),
                ),
                scenario === 'apps' ? writeFile(envelope, snapshot) : Promise.resolve(),
                writeFile(
                    bootstrap,
                    `
                        import { writeFileSync } from 'node:fs'
                        if (process.argv[2] !== 'export-app-key') process.exit(95)
                        writeFileSync(${JSON.stringify(output + '/app-encryption-key')}, 'A'.repeat(43) + '=\\n', { mode: 0o600 })
                    `,
                ),
                writeFile(
                    join(bin, 'bash'),
                    `#!/usr/bin/env -S bun --no-env-file
                        import { appendFileSync, existsSync, readFileSync } from 'node:fs'
                        if (process.argv[2] !== '-c') process.exit(96)
                        const script = process.argv[3]
                        appendFileSync(${JSON.stringify(calls)}, script + '\\n--\\n')
                        if (script.includes('--app-backup capture-portable')) {
                            if (existsSync(${JSON.stringify(envelope)})) process.stdout.write(readFileSync(${JSON.stringify(envelope)}))
                        } else if (script.includes('pg_dump')) process.stdout.write('fixture-dump')
                        else process.exit(97)
                    `,
                    { mode: 0o755 },
                ),
                writeFile(join(bin, 'pg_restore'), '#!/bin/sh\nexit 0\n', { mode: 0o755 }),
            ])
            const result = Bun.spawn(
                [process.execPath, '--no-env-file', join(code, module), 'backup'],
                {
                    env: { ...process.env, PUBLIC_ORIGIN: 'https://proxy.test' },
                    stdin: 'ignore',
                    stdout: 'pipe',
                    stderr: 'pipe',
                },
            )
            const [exit, stderr] = await Promise.all([
                result.exited,
                new Response(result.stderr).text(),
            ])
            expect(exit, stderr).toBe(0)
            const metadata = JSON.parse(
                await readFile(join(output, 'complete/metadata.json'), 'utf8'),
            ) as { version: number; applications?: unknown }
            const invoked = await readFile(calls, 'utf8')
            expect(invoked.indexOf('capture-portable')).toBeLessThan(invoked.indexOf('pg_dump'))
            expect((await readdir(join(output, 'complete'))).toSorted()).toEqual([
                'app-encryption-key',
                'controller-state.tar',
                'crowdsec-state.tar',
                'metadata.json',
                'postgres.dump',
            ])
            if (scenario === 'apps') {
                expect(metadata.version).toBe(PORTABLE_APP_BACKUP_VERSION)
                expect(metadata.applications).toEqual(applications)
                expect(invoked).toContain(
                    '--check-live-app-inventory ' +
                        encodeCapturedInstallations(applications.installations),
                )
                expect(invoked).not.toContain('--app-backup empty')
            } else {
                expect(metadata.version).toBe(4)
                expect(metadata.applications).toBeUndefined()
                expect(invoked).toContain('--app-backup empty')
                expect(invoked).not.toContain('--check-live-app-inventory')
            }
        } finally {
            await rm(root, { recursive: true, force: true })
        }
    },
)
