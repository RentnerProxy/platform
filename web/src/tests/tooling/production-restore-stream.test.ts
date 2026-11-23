import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { chmod, mkdir, mkdtemp, readFile, rm, stat, writeFile } from 'node:fs/promises'
import { join, resolve } from 'node:path'
import { test } from 'bun:test'
import { portableAppStateName } from '../../../../scripts/backup/app-state.ts'
import { PORTABLE_APP_BACKUP_VERSION } from '@/config/compatibility.config.ts'

const root = resolve(import.meta.dir, '../../../..')
const hash = (bytes: Uint8Array) => createHash('sha256').update(bytes).digest('hex')
const artifact = (bytes: Uint8Array) => ({ bytes: bytes.length, sha256: hash(bytes) })
const portableDatabaseBytes = 1024 ** 3
const isolatedCapacity = ['5242880', '8388608']

function fixtureTar(name = './', contents: string | Uint8Array = '') {
    const bytes = typeof contents === 'string' ? Buffer.from(contents) : contents
    const header = Buffer.alloc(512)
    header.write(name)
    header.write('0000700\0', 100)
    header.write(bytes.length.toString(8).padStart(11, '0') + '\0', 124)
    header.fill(32, 148, 156)
    header[156] = bytes.length ? 48 : 53
    header.write(
        header
            .reduce((sum, byte) => sum + byte, 0)
            .toString(8)
            .padStart(6, '0') + '\0 ',
        148,
    )
    const body = Buffer.alloc(Math.ceil(bytes.length / 512) * 512)
    body.set(bytes)
    return Buffer.concat([header, body, Buffer.alloc(1024)])
}

function portableAppFixture() {
    const id = 'greeting'
    const slot = { appId: 'fixture/greeting', uid: 20000, generation: 1, authorityRecorded: true }
    const files = Buffer.from('{}')
    const checkpoint = Buffer.from('{}')
    const pkg = Buffer.from('synthetic signed package')
    const database = Buffer.from('PGDMP synthetic app database')
    const header = Buffer.from(
        JSON.stringify({
            formatVersion: 2,
            installations: { [id]: slot },
            members: [
                { kind: 'data', key: 'files', ...artifact(files) },
                { kind: 'checkpoint', key: 'catalog', ...artifact(checkpoint) },
                { kind: 'package', key: hash(pkg), ...artifact(pkg) },
                {
                    kind: 'database',
                    key: String(slot.uid),
                    ...artifact(database),
                    allocationBytes: portableDatabaseBytes,
                },
            ],
        }),
    )
    const prefix = Buffer.alloc(12)
    prefix.write('RPAPPB2\0')
    prefix.writeUInt32BE(header.length, 8)
    const member = Buffer.concat([prefix, header, files, checkpoint, pkg, database])
    return {
        controller: fixtureTar(portableAppStateName, member),
        metadata: {
            version: PORTABLE_APP_BACKUP_VERSION,
            applications: { ...artifact(member), installations: [{ id, ...slot }] },
        },
    }
}

type RestoreScenario =
    | 'success'
    | 'source-swap'
    | 'bad-hash'
    | 'invalid-index'
    | 'null-index'
    | 'legacy-index'
    | 'legacy-image'
    | 'database-failure'
    | 'stopped-configured'
    | 'fresh-target'
    | 'resume'
    | 'wrong-backup'
    | 'resume-missing'
    | 'inventory-running'
    | 'inventory-transport-failure'
    | 'inventory-stopped'
    | 'inventory-pending'
    | 'inventory-cleanup-failure'
    | 'prepare-failure'
    | 'replacement-failure'
    | 'off-host-pause-failure'
    | 'portable-success'
    | 'portable-missing-capacity'
    | 'portable-insufficient-capacity'

async function restore(scenario: RestoreScenario) {
    await mkdir(join(root, 'tmp'), { recursive: true })
    const directory = await mkdtemp(join(root, 'tmp', 'restore-stream-'))
    const input = join(directory, 'input'),
        bin = join(directory, 'bin')
    await Promise.all([mkdir(input), mkdir(bin)])
    const dump = Buffer.alloc(6 * 1024 ** 2 + 7, 137)
    const key = Buffer.from(Buffer.alloc(32, 17).toString('base64') + '\n')
    const tar = fixtureTar()
    const index =
        scenario === 'invalid-index'
            ? '{"certificates":{},"eventJournalVersion":2}'
            : scenario === 'legacy-index' || scenario === 'legacy-image'
              ? '{"certificates":{},"eventJournalVersion":0}'
              : scenario === 'null-index'
                ? 'null'
                : undefined
    const portable = scenario.startsWith('portable-') ? portableAppFixture() : undefined
    const controller =
        portable?.controller ??
        (index ? fixtureTar('certificates/certificate-metadata.json', index) : tar)
    const metadata = {
        format: 'rentnerproxy-production-backup',
        ...(portable?.metadata ?? { version: 4 }),
        createdAt: '2026-10-22T00:00:00Z',
        redis: 'excluded',
        postgres: {
            ...artifact(dump),
            database: 'rentnerproxy',
            user: 'rentnerproxy',
            dump: 'postgres.dump',
        },
        applicationEncryptionKey: { ...artifact(key), file: 'app-encryption-key' },
        controllerState: { ...artifact(controller), archive: 'controller-state.tar' },
        crowdSecState: { ...artifact(tar), archive: 'crowdsec-state.tar' },
        deployment: { publicOrigin: 'https://proxy.test', trustedProxyCidrs: '' },
        source: { imageId: 'sha256:' + 'a'.repeat(64), revision: null, version: null },
    }
    const metadataBytes = JSON.stringify(metadata)
    const backupId = hash(Buffer.from(metadataBytes))
    await Promise.all([
        writeFile(join(input, 'metadata.json'), metadataBytes),
        writeFile(
            join(input, 'postgres.dump'),
            scenario === 'bad-hash' ? Buffer.alloc(dump.length) : dump,
        ),
        writeFile(join(input, 'app-encryption-key'), key),
        writeFile(join(input, 'controller-state.tar'), controller),
        writeFile(join(input, 'crowdsec-state.tar'), tar),
        writeFile(join(directory, 'compose.yml'), 'fixture only; docker is replaced'),
    ])
    const compatibility = join(directory, 'compatibility.ts')
    await writeFile(
        compatibility,
        'export const isSupportedBackupVersion = version => ' +
            (scenario === 'legacy-image' ? 'version === 4' : 'version === 4 || version === 5'),
    )
    const decoder = join(bin, 'controller')
    await writeFile(
        decoder,
        `#!/usr/bin/env -S bun --no-env-file
import {readFileSync} from 'node:fs'
if (process.env.FIXTURE_SCENARIO === 'legacy-image' || process.argv[2] !== '--check-backup-state' || process.argv[3] !== 'certificate-index') process.exit(98)
const doc = readFileSync(0)
const actual = process.env.RENTNERPROXY_TEST_CONTROLLER
if (actual) process.exit(Bun.spawnSync([actual,'--check-backup-state','certificate-index'], {stdin: doc,stdout:'ignore',stderr:'ignore'}).exitCode ?? 97)
process.exit(JSON.parse(doc.toString()).eventJournalVersion === 0 ? 0 : 1)
`,
        { mode: 0o755 },
    )
    const fake = join(bin, 'docker')
    await writeFile(
        fake,
        `#!/usr/bin/env -S bun --no-env-file
import { appendFileSync, existsSync, readFileSync, unlinkSync, writeFileSync, statSync } from 'node:fs'
import { createHash } from 'node:crypto'
const args = process.argv.slice(2), command = args.join(' ')
const directory = process.env.FIXTURE_DIRECTORY, scenario = process.env.FIXTURE_SCENARIO
appendFileSync(directory + '/calls', JSON.stringify(args) + '\\n')
if (command.includes('config --format=json')) {
    if (scenario === 'source-swap') writeFileSync(directory + '/input/postgres.dump','swapped after validation')
    console.log(JSON.stringify({ services: { rentnerproxy: { image:'fixture',environment:{ PUBLIC_ORIGIN:'https://proxy.test' } } } }))
} else if (command.startsWith('image inspect ')) {
    console.log('sha256:' + 'a'.repeat(64))
} else if (args.includes('metadata')) {
    const doc = readFileSync(0,'utf8')
    if (!args.includes('certificate-index') || !args.includes('--network=none') || !args.includes('--interactive') || args.includes('--volume')) process.exit(99)
    const [shell, ...values] = args.slice(args.indexOf('-ceu') + 1)
    const script = shell.replace('/opt/rentnerproxy/web/web/src/lib/ApplicationVersion/backupCompatibility.ts', directory + '/compatibility.ts').replace('/usr/local/bin/rentnerproxy-controller',directory + '/bin/controller')
    process.exit(Bun.spawnSync(['bash','-ceu',script,...values], {stdin:Buffer.from(doc),stdout:'ignore',stderr:'ignore'}).exitCode ?? 97)
} else if (command.includes('inspect-production-restore')) {
    if (scenario === 'resume' || scenario === 'inventory-pending') console.log(process.env.FIXTURE_BACKUP_ID)
    if (scenario === 'wrong-backup') console.log('b'.repeat(64))
} else if (command.includes('ps --status running --quiet')) {
    if (['inventory-running', 'inventory-transport-failure', 'inventory-cleanup-failure', 'inventory-pending', 'portable-insufficient-capacity'].includes(scenario)) console.log('existing-appliance')
} else if (args.includes('inventory') && scenario.startsWith('portable-')) {
    if (!args.some(arg => arg.includes('--check-portable-restore-capacity'))) process.exit(77)
    console.log(scenario === 'portable-insufficient-capacity' ? 'insufficient-capacity' : 'accepted')
} else if (args.includes('inventory') && args.some(arg => arg.includes('CHECK_APP_INVENTORY'))) {
    if (!args.includes('--rm')) process.exit(78)
    if (scenario === 'inventory-cleanup-failure' || scenario === 'inventory-transport-failure') {
        const name = args[args.indexOf('--name') + 1], label = args[args.indexOf('--label') + 1]
        writeFileSync(directory + '/maintenance', JSON.stringify({ name, label }))
    }
    if (scenario === 'inventory-transport-failure') process.exit(9)
    console.log(scenario.startsWith('inventory-') ? 'rejected' : 'accepted')
} else if (command.startsWith('container ls ') && existsSync(directory + '/maintenance')) {
    const {name} = JSON.parse(readFileSync(directory + '/maintenance'))
    console.log(JSON.stringify({ ID:'c'.repeat(64), Names:name }))
} else if (command.startsWith('container inspect ') && existsSync(directory + '/maintenance')) {
    const {name,label} = JSON.parse(readFileSync(directory + '/maintenance')), [key, value] = label.split('=')
    console.log(JSON.stringify({ Id:'c'.repeat(64), Name:'/' + name, Config:{ Labels:{ [key]:value } } }))
} else if (command.startsWith('container rm ') && existsSync(directory + '/maintenance')) {
    if (scenario === 'inventory-cleanup-failure') process.exit(9)
    unlinkSync(directory + '/maintenance')
} else if (command.includes('--initialize-restore-target')) {
    if (scenario === 'prepare-failure') process.exit(9)
} else if (command.includes('begin-production-restore')) {
    if (scenario === 'off-host-pause-failure') { console.error('do-not-leak SYNTHETIC-BOOTSTRAP-SECRET'); process.exit(9) }
    if (scenario.startsWith('portable-')) writeFileSync(directory + '/pending-backup', process.env.FIXTURE_BACKUP_ID)
} else if (args.includes('restore-portable-apps')) {
    const pending = readFileSync(directory + '/pending-backup', 'utf8')
    const mount = args[args.indexOf('--volume') + 1]
    if (args.at(-1) !== pending || !mount.endsWith(':/backup:ro')) process.exit(87)
    const member = readFileSync(mount.slice(0, -11) + '/${portableAppStateName}')
    if (createHash('sha256').update(member).digest('hex') !== process.env.FIXTURE_PORTABLE_HASH) process.exit(88)
} else if (command.includes('pg_restore')) {
    const mount = args[args.indexOf('--volume') + 1]
    if (!mount.endsWith(':/backup:ro')) process.exit(81)
    const snapshot = mount.slice(0,-11)
    const dump = readFileSync(snapshot + '/postgres.dump')
    if (createHash('sha256').update(dump).digest('hex') !== process.env.FIXTURE_DUMP_HASH) process.exit(82)
    if ((statSync(snapshot + '/postgres.dump').mode & 0o777) !== 0o600) process.exit(83)
    if (readFileSync(0).length !== 0) process.exit(84)
    if (!command.includes('< /backup/postgres.dump') || command.includes('dump_path=')) process.exit(85)
    if (scenario === 'database-failure' || (scenario === 'replacement-failure' && args.includes('RENTNERPROXY_RESTORE_PHASE=database'))) { console.error('do-not-leak RESTORE_PHASE=render ERROR: 23514'); process.exit(9) }
    if (args.includes('--network=none') && scenario.startsWith('portable-')) {
        console.log('Backup database and application metadata verified.')
        if (scenario !== 'portable-missing-capacity' && command.includes('PORTABLE_RESTORE_CAPACITY='))
            console.log('PORTABLE_RESTORE_CAPACITY=${isolatedCapacity.join(',')}')
    }
} else if (args.includes('up') && !args.includes('--force-recreate')) {
    // Model old enabled automation being admitted by a normal pre-restore boot.
    writeFileSync(directory + '/old-worker-started', 'unsafe normal startup')
}

`,
    )
    await chmod(fake, 0o755)
    try {
        const child = Bun.spawn({
            cmd: [
                process.execPath,
                '--no-env-file',
                join(root, 'scripts/production-restore.ts'),
                '--input',
                input,
                '--confirm-replace',
                ...(['resume', 'wrong-backup', 'resume-missing', 'inventory-pending'].includes(
                    scenario,
                )
                    ? ['--resume']
                    : []),
            ],
            cwd: root,
            env: {
                ...process.env,
                PATH: bin + ':' + process.env.PATH,
                FIXTURE_DIRECTORY: directory,
                FIXTURE_SCENARIO: scenario,
                FIXTURE_DUMP_HASH: hash(dump),
                FIXTURE_BACKUP_ID: backupId,
                FIXTURE_PORTABLE_HASH: portable?.metadata.applications.sha256 ?? '',
                RENTNERPROXY_COMPOSE_FILE: join(directory, 'compose.yml'),
            },
            stdin: 'ignore',
            stdout: 'pipe',
            stderr: 'pipe',
        })
        const [exit, stdout, stderr] = await Promise.all([
            child.exited,
            new Response(child.stdout).text(),
            new Response(child.stderr).text(),
        ])
        const calls: string[][] = (await readFile(join(directory, 'calls'), 'utf8').catch(() => ''))
            .trim()
            .split('\n')
            .filter(Boolean)
            .map((line) => JSON.parse(line))
        const pg = calls.filter((args) => args.some((arg) => arg.includes('pg_restore')))
        if (pg.length) {
            const mount = pg[0]![pg[0]!.indexOf('--volume') + 1]!
            assert.ok(pg.every((args) => args[args.indexOf('--volume') + 1] === mount))
            await assert.rejects(stat(mount.slice(0, -11)), /ENOENT/)
        }
        const oldWorkerStarted = await stat(join(directory, 'old-worker-started'))
            .then(() => true)
            .catch(() => false)
        return { exit, stdout, stderr, calls, pg, oldWorkerStarted, backupId }
    } finally {
        await rm(directory, { recursive: true, force: true })
    }
}

test.skipIf(process.platform === 'win32')(
    'restore CLI uses the same verified multi-MiB snapshot for both PostgreSQL phases despite source replacement',
    async () => {
        const result = await restore('source-swap')
        assert.equal(result.exit, 0, result.stderr)
        assert.equal(result.pg.length, 2)
        assert.ok(result.pg.every((args) => !args.includes('--interactive')))
        assert.match(result.stdout, /Production restore completed/)
        assert.ok(result.calls.some((args) => args.includes('--force-recreate')))
    },
)

test.skipIf(process.platform === 'win32')(
    'portable restore validates capacity and imports the same backup before completion',
    async () => {
        const { backupId, calls, exit, pg, stderr } = await restore('portable-success')
        assert.equal(exit, 0, stderr)
        assert.equal(pg.length, 2)
        const inventory = calls.findIndex((args) => args.includes('inventory'))
        const capacity = calls[inventory]!.slice(calls[inventory]!.indexOf('inventory') + 2)
        assert.equal(capacity.length, 6)
        assert.deepEqual(capacity.slice(0, 2), isolatedCapacity)
        assert.ok(Number(capacity[2]) >= 2 * portableDatabaseBytes)
        assert.ok(Number(capacity[3]) > 0)
        assert.deepEqual(capacity.slice(4), ['0', '5'])
        assert.ok(
            calls[inventory]!.some((arg) =>
                arg.includes(
                    '--check-portable-app-restore-inventory /backup ' + backupId + ' false',
                ),
            ),
        )
        const importApps = calls.findIndex((args) => args.includes('restore-portable-apps'))
        const stages = [
            calls.indexOf(pg[0]!),
            calls.findIndex((args) => args.includes('stop')),
            inventory,
            calls.findIndex((args) => args.includes('--initialize-restore-target')),
            calls.findIndex((args) => args.includes('begin-production-restore')),
            calls.indexOf(pg[1]!),
            calls.findIndex((args) =>
                args.some((arg) => arg.includes('--exclude=' + portableAppStateName)),
            ),
            importApps,
            calls.findIndex((args) => args.includes('complete-app-key-restore')),
            calls.findIndex((args) => args.includes('complete-production-restore')),
            calls.findIndex((args) => args.includes('--force-recreate')),
        ]
        assert.ok(
            stages.every((stage, index) => stage > (stages[index - 1] ?? -1)),
            stages.join(','),
        )
        const worker = calls[importApps]!
        assert.ok(worker.includes('--entrypoint=bun'))
        assert.deepEqual(worker.slice(-4), [
            '--no-env-file',
            '/opt/rentnerproxy/web/backup-maintenance.js',
            'restore-portable-apps',
            backupId,
        ])
        assert.equal(worker[worker.indexOf('--volume') + 1], pg[0]![pg[0]!.indexOf('--volume') + 1])
    },
)

test.skipIf(process.platform === 'win32').each([
    ['portable-missing-capacity', /Isolated restore capacity evidence is unavailable/],
    [
        'portable-insufficient-capacity',
        /Portable application restore target lacks verified storage capacity/,
    ],
] as const)('%s fails before changing stored state', async (scenario, message) => {
    const { calls, exit, pg, stderr } = await restore(scenario)
    assert.equal(exit, 1)
    assert.match(stderr, message)
    assert.equal(pg.length, 1)
    assert.ok(
        !calls.some((args) =>
            args.some((arg) =>
                [
                    '--initialize-restore-target',
                    'begin-production-restore',
                    'begin-app-key-restore',
                    'restore-portable-apps',
                    '--force-recreate',
                ].includes(arg),
            ),
        ),
    )
    const stop = calls.findIndex((args) => args.includes('stop'))
    const inventory = calls.findIndex((args) => args.includes('inventory'))
    const restart = calls.findIndex((args) => args.includes('start'))
    if (scenario === 'portable-missing-capacity') {
        assert.deepEqual([stop, inventory, restart], [-1, -1, -1])
    } else {
        assert.ok(stop >= 0 && inventory > stop && restart > inventory)
    }
})

test
    .skipIf(process.platform === 'win32')
    .each([
        'inventory-running',
        'inventory-transport-failure',
        'inventory-stopped',
        'inventory-pending',
        'inventory-cleanup-failure',
    ] as const)('inventory rejection preserves the target lifecycle for %s', async (scenario) => {
    const { exit, calls, stderr } = await restore(scenario)
    assert.equal(exit, 1)
    const stop = calls.findIndex((args) => args.includes('stop'))
    const inventory = calls.findIndex((args) => args.includes('inventory'))
    const cleanup = calls.findIndex((args, i) => i > inventory && args.includes('ls'))
    assert.ok(stop >= 0 && inventory > stop && cleanup > inventory)
    assert.ok(
        !calls.some((args) => args.includes('begin-production-restore') || args.includes('up')),
    )
    const start = calls.findIndex((args) => args.includes('start'))
    if (scenario === 'inventory-running' || scenario === 'inventory-transport-failure') {
        assert.ok(start > cleanup)
        assert.ok(calls.some((args, i) => i > start && args.includes('exec')))
    } else {
        assert.equal(start, -1)
    }
    if (scenario === 'inventory-cleanup-failure' || scenario === 'inventory-transport-failure') {
        assert.ok(
            calls.some((args, i) => i > cleanup && args.includes('rm') && args.includes('--force')),
        )
    }
    assert.match(
        stderr,
        scenario === 'inventory-cleanup-failure'
            ? /cleanup unresolved/i
            : /check target application inventory/,
    )
})

test
    .skipIf(process.platform === 'win32')
    .each(['invalid-index', 'legacy-index', 'legacy-image', 'null-index'] as const)(
    'checks the recovered %s before quiescing the target',
    async (scenario) => {
        const { calls, exit, stderr } = await restore(scenario)
        if (scenario === 'null-index') {
            assert.equal(exit, 1)
            assert.match(stderr, /invalid certificate state metadata/)
            assert.equal(calls.length, 0)
            return
        }
        const checked = calls.findIndex((args) => args.includes('metadata'))
        assert.ok(checked >= 0)
        const stopped = calls.findIndex((args) => args.includes('stop'))
        if (scenario === 'legacy-index' || scenario === 'legacy-image') {
            assert.equal(exit, 0, stderr)
            assert.ok(stopped > checked)
        } else {
            assert.equal(exit, 1)
            assert.match(stderr, /validate controller backup metadata/)
            assert.equal(stopped, -1)
        }
    },
)

test.skipIf(process.platform === 'win32')(
    'restore CLI rejects corrupted input before any Docker call',
    async () => {
        const result = await restore('bad-hash')
        assert.equal(result.exit, 1)
        assert.equal(result.calls.length, 0)
        assert.match(result.stderr, /checksum mismatch/)
    },
)

test.skipIf(process.platform === 'win32')(
    'restore PostgreSQL diagnostics remain allowlisted without stdin or appliance startup after failure',
    async () => {
        const result = await restore('database-failure')
        assert.equal(result.exit, 1)
        assert.match(result.stderr, /Restore database phase: render/)
        assert.match(result.stderr, /SQLSTATE: 23514/)
        assert.ok(!result.stderr.includes('do-not-leak'))
        assert.ok(!result.calls.some((args) => args.includes('up') || args.includes('start')))
    },
)

test.skipIf(process.platform === 'win32').each(['stopped-configured', 'fresh-target'] as const)(
    'restore prepares a %s target with database-only maintenance before any normal startup',
    async (scenario) => {
        const result = await restore(scenario)
        assert.equal(result.exit, 0, result.stderr)
        assert.equal(result.oldWorkerStarted, false)
        const stop = result.calls.findIndex((args) => args.includes('stop'))
        const prepare = result.calls.findIndex((args) =>
            args.includes('--initialize-restore-target'),
        )
        const journal = result.calls.findIndex((args) => args.includes('begin-production-restore'))
        const replace = result.calls.findIndex((args) =>
            args.includes('RENTNERPROXY_RESTORE_PHASE=database'),
        )
        const complete = result.calls.findIndex((args) =>
            args.includes('complete-production-restore'),
        )
        const starts = result.calls.filter((args) => args.includes('up') || args.includes('start'))
        assert.ok(stop >= 0 && stop < prepare && prepare < journal && journal < replace)
        assert.equal(starts.length, 1)
        assert.ok(starts[0]!.includes('--force-recreate'))
        assert.ok(result.calls.indexOf(starts[0]!) > complete && complete > replace)
        const preparation = result.calls[prepare]!
        assert.ok(preparation.includes('run') && preparation.includes('--no-deps'))
        assert.ok(preparation.includes('--entrypoint=/usr/local/bin/rentnerproxy-production'))
        assert.ok(
            !result.calls.some(
                (args) => args.includes('exec') && result.calls.indexOf(args) < complete,
            ),
        )
    },
)

test.skipIf(process.platform === 'win32')(
    'same-backup resume retains the initialized cluster and pending key contract without normal pre-start',
    async () => {
        const result = await restore('resume')
        assert.equal(result.exit, 0, result.stderr)
        assert.equal(result.oldWorkerStarted, false)
        assert.ok(!result.calls.some((args) => args.includes('--initialize-restore-target')))
        const journal = result.calls.find((args) => args.includes('begin-production-restore'))!
        assert.ok(journal.includes('RENTNERPROXY_RESTORE_RESUME=true'))
        assert.ok(result.calls.some((args) => args.includes('begin-app-key-restore')))
        assert.equal(result.calls.filter((args) => args.includes('up')).length, 1)
        assert.ok(result.calls.find((args) => args.includes('up'))!.includes('--force-recreate'))
    },
)

test.skipIf(process.platform === 'win32').each(['wrong-backup', 'resume-missing'] as const)(
    '%s rejects before stopping or preparing the target',
    async (scenario) => {
        const result = await restore(scenario)
        assert.equal(result.exit, 1)
        assert.equal(result.oldWorkerStarted, false)
        assert.ok(
            !result.calls.some(
                (args) =>
                    args.includes('stop') ||
                    args.includes('up') ||
                    args.includes('--initialize-restore-target'),
            ),
        )
    },
)

test.skipIf(process.platform === 'win32').each(['prepare-failure', 'replacement-failure'] as const)(
    '%s leaves the target stopped without automatic startup or premature journal completion',
    async (scenario) => {
        const result = await restore(scenario)
        assert.equal(result.exit, 1)
        assert.equal(result.oldWorkerStarted, false)
        assert.ok(result.calls.some((args) => args.includes('stop')))
        assert.ok(
            !result.calls.some(
                (args) =>
                    args.includes('up') ||
                    args.includes('start') ||
                    args.includes('complete-production-restore'),
            ),
        )
        assert.equal(
            result.calls.some((args) => args.includes('begin-production-restore')),
            scenario === 'replacement-failure',
        )
    },
)

test.skipIf(process.platform === 'win32')(
    'off-host pause failure leaves writers stopped before key/database replacement',
    async () => {
        const result = await restore('off-host-pause-failure')
        assert.equal(result.exit, 1)
        assert.match(result.stderr, /pause off-host backups/)
        assert.match(result.stderr, /appliance remains stopped/)
        assert.match(
            result.stderr,
            /If the restore journal was written, rerun the same backup with --resume --confirm-replace/,
        )
        assert.equal(result.stderr.includes('SYNTHETIC-BOOTSTRAP-SECRET'), false)
        assert.equal(result.stderr.includes('do-not-leak'), false)
        assert.ok(result.calls.some((args) => args.includes('stop')))
        assert.ok(result.calls.some((args) => args.includes('begin-production-restore')))
        assert.ok(
            !result.calls.some(
                (args) =>
                    args.includes('begin-app-key-restore') ||
                    args.includes('RENTNERPROXY_RESTORE_PHASE=database') ||
                    args.includes('up') ||
                    args.includes('start') ||
                    args.includes('complete-production-restore'),
            ),
        )
    },
)
