// oxlint-disable no-await-in-loop -- The probe drives one appliance after another.
import assert from 'node:assert/strict'
import { execFile } from 'node:child_process'
import { randomUUID } from 'node:crypto'
import { mkdir, mkdtemp, readdir, readFile, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'
import { promisify } from 'node:util'
import { waitForSmoke } from '../../../../scripts/smoke/wait.ts'
import { PORTABLE_APP_BACKUP_VERSION } from '../../../../web/src/config/compatibility.config.ts'
import {
    catalogInstallSchema,
    catalogSnapshotSchema,
    type CatalogSnapshot,
} from '../../../../web/src/lib/AppCatalog/contract.ts'

const appId = 'rentnerproxy.greeting'
const managerSocket = '/run/rentnerproxy/app-ui/web.sock'
const webUser = '10002:10002'
const repositoryRoot = resolve(import.meta.dir, '../../../..')
const execute = promisify(execFile)

const [image, output] = process.argv.slice(2)
assert.ok(image && output, 'Expected an appliance image and an evidence directory')

// Host credentials must never reach the appliances or their Compose interpolation.
const environment: NodeJS.ProcessEnv = { ...process.env, COMPOSE_DISABLE_ENV_FILE: '1' }
for (const name of Object.keys(environment))
    if (
        /^(?:SMTP_|PUBLIC_ORIGIN$|PROXY_|RENTNERPROXY_|APP_ENCRYPTION_KEY$|DATABASE_URL$|POSTGRES_)/u.test(
            name,
        )
    )
        delete environment[name]

async function run(file: string, args: string[], timeout = 60_000, env = environment) {
    const { stdout } = await execute(file, args, {
        cwd: repositoryRoot,
        env,
        maxBuffer: 16 * 1024 * 1024,
        timeout,
        windowsHide: true,
    })
    return stdout.trim()
}

const docker = (args: string[], timeout?: number) => run('docker', args, timeout)

async function waitFor(label: string, timeoutMs: number, predicate: () => Promise<boolean>) {
    await waitForSmoke(predicate, {
        timeoutMs,
        intervalMs: 2_000,
        // Assertions are final. Command failures can be a restarting manager or appliance.
        retryOnError: (error) => !(error instanceof assert.AssertionError),
        timeoutError: () => new Error('Timed out waiting for ' + label),
    })
}

async function createTarget(root: string, name: string, offline: boolean) {
    const directory = join(root, name)
    await mkdir(directory)
    const compose = (await readFile(join(repositoryRoot, 'docker-compose.yml'), 'utf8')).replaceAll(
        '\r\n',
        '\n',
    )
    // The probe reaches the appliances with docker exec. Published host ports could collide.
    const ports = /\n {8}ports:\n(?: {12}- .+\n)+/u
    assert.match(compose, ports)
    const file = join(directory, 'docker-compose.yml')
    await writeFile(file, compose.replace(ports, offline ? '\n        network_mode: none\n' : '\n'))
    await writeFile(
        join(directory, '.env'),
        [
            'RENTNERPROXY_IMAGE=' + image,
            'PUBLIC_ORIGIN=https://management.offline-restore.invalid',
            'PROXY_TRUSTED_PROXY_CIDRS=127.0.0.1/32,::1/128',
            'SMTP_HOST=smtp.offline-restore.invalid',
            'SMTP_PORT=587',
            'SMTP_SECURE=false',
            'SMTP_USER=offline-restore',
            'SMTP_PASSWORD=offline-restore-' + randomUUID(),
            'SMTP_FROM=RentnerProxy <noreply@offline-restore.invalid>',
            '',
        ].join('\n'),
    )
    const project = 'rp-offline-restore-' + name + '-' + randomUUID().slice(0, 8)
    const env = {
        ...environment,
        COMPOSE_ENV_FILES: join(directory, '.env'),
        RENTNERPROXY_COMPOSE_FILE: file,
    }
    return {
        project,
        env,
        compose: (args: string[], timeout?: number) =>
            run('docker', ['compose', '--project-name', project, '--file', file, ...args], timeout, env),
    }
}

type Target = Awaited<ReturnType<typeof createTarget>>

async function healthyAppliance(target: Target) {
    const id = await target.compose(['ps', '--all', '--quiet', 'rentnerproxy'])
    assert.match(id, /^[a-f0-9]{12,64}$/u, 'the appliance container exists')
    try {
        await waitFor('a healthy appliance', 300_000, async () => {
            const state = await docker([
                'inspect',
                '--format',
                '{{.State.Status}}|{{if .State.Health}}{{.State.Health.Status}}{{end}}',
                id,
            ])
            assert.notEqual(state.split('|')[0], 'exited', 'the appliance exited')
            return state === 'running|healthy'
        })
    } catch (error) {
        console.error(await docker(['logs', '--tail', '80', id]).catch(() => ''))
        throw error
    }
    return id
}

async function catalog(container: string, body?: unknown) {
    const args = ['exec', '--user', webUser, container, 'curl', '--silent', '--show-error']
    args.push('--fail-with-body', '--max-time', '20', '--unix-socket', managerSocket)
    if (body !== undefined)
        args.push('--header', 'Content-Type: application/json', '--data-binary', JSON.stringify(body))
    args.push('http://localhost/v1/catalog' + (body === undefined ? '' : '/install'))
    return JSON.parse(await docker(args)) as unknown
}

const snapshot = async (container: string) => catalogSnapshotSchema.parse(await catalog(container))

const order = (version: string) => version.split('.').map(Number)

function newestRelease(entries: CatalogSnapshot['entries']) {
    const releases = entries.filter(
        (entry) =>
            entry.appId === appId &&
            entry.availability === 'available' &&
            /^\d+\.\d+\.\d+$/u.test(entry.version),
    )
    releases.sort((left, right) => {
        const a = order(left.version)
        const b = order(right.version)
        return a[0]! - b[0]! || a[1]! - b[1]! || a[2]! - b[2]!
    })
    const release = releases.at(-1)
    assert.ok(release, 'the signed catalog offers an installable Greeting release')
    return { appId, version: release.version, archiveSha256: release.archiveSha256 }
}

async function runningRelease(container: string, installationId: string) {
    let installation: CatalogSnapshot['installations'][number] | undefined
    await waitFor('the running Greeting installation', 180_000, async () => {
        installation = (await snapshot(container)).installations.find(
            (entry) => entry.installationId === installationId,
        )
        assert.notEqual(installation?.state, 'recoveryRequired', 'Greeting requires recovery')
        return installation?.state === 'running'
    })
    assert.ok(installation)
    return {
        appId: installation.appId,
        version: installation.version,
        archiveSha256: installation.archiveSha256,
    }
}

const psql = (container: string, database: string, sql: string) =>
    docker([
        'exec',
        container,
        'gosu',
        'postgres',
        'psql',
        '--no-psqlrc',
        '--no-password',
        '--host=/var/run/postgresql',
        '--username=postgres',
        '--quiet',
        '--tuples-only',
        '--no-align',
        '--set=ON_ERROR_STOP=1',
        '--dbname=' + database,
        '--command',
        sql,
    ])

const probeNotes = (container: string, uid: number) =>
    psql(
        container,
        'rp_app_' + uid,
        "SELECT string_agg(note, ',' ORDER BY id) FROM app.offline_restore_probe;",
    )

async function restore(target: Target, backup: string) {
    await run(
        process.execPath,
        [
            '--no-env-file',
            'scripts/production-restore.ts',
            '--project',
            target.project,
            '--input',
            backup,
            '--confirm-replace',
        ],
        900_000,
        target.env,
    )
    return healthyAppliance(target)
}

const platform = await docker(['image', 'inspect', '--format', '{{.Os}}/{{.Architecture}}', image])
const root = await mkdtemp(join(tmpdir(), 'rentnerproxy-offline-restore-'))
const targets: Target[] = []
try {
    const source = await createTarget(root, 'source', false)
    const offline = await createTarget(root, 'offline', true)
    targets.push(source, offline)

    // Install the signed Greeting the same way the administration does, from the live catalog.
    await source.compose(['up', '--detach'], 300_000)
    let container = await healthyAppliance(source)
    let catalogState: CatalogSnapshot | undefined
    await waitFor('the signed app catalog', 240_000, async () => {
        catalogState = await snapshot(container)
        return catalogState.state === 'ready'
    })
    const release = newestRelease(catalogState!.entries)
    const submitted = catalogInstallSchema.parse(await catalog(container, release))
    assert.notEqual(submitted.status, 'failed', 'the manager accepts the Greeting installation')
    let installationId = ''
    await waitFor('the Greeting installation', 300_000, async () => {
        const install = (await snapshot(container)).install
        assert.notEqual(install?.status, 'failed', 'the Greeting installation failed')
        if (install?.status === 'installed') installationId = install.installationId
        return installationId !== ''
    })
    assert.deepEqual(await runningRelease(container, installationId), release)

    const databases = await psql(
        container,
        'postgres',
        "SELECT datname FROM pg_database WHERE datname ~ '^rp_app_[0-9]+$';",
    )
    const uid = Number(/^rp_app_(\d+)$/u.exec(databases)?.[1])
    assert.ok(Number.isSafeInteger(uid), 'Greeting has exactly one app database')
    await psql(
        container,
        'rp_app_' + uid,
        `SET ROLE rp_migrate_${uid}; ` +
            'CREATE TABLE app.offline_restore_probe (id integer PRIMARY KEY, note text NOT NULL); ' +
            "INSERT INTO app.offline_restore_probe VALUES (1, 'captured');",
    )

    // The operator backup quiesces the running appliance and restarts it.
    const backups = join(root, 'backups')
    await run(
        process.execPath,
        [
            '--no-env-file',
            'scripts/production-backup.ts',
            '--project',
            source.project,
            '--output',
            backups,
        ],
        900_000,
        source.env,
    )
    const [entry, ...extra] = await readdir(backups)
    assert.ok(entry && extra.length === 0, 'the backup created one artifact')
    const backup = join(backups, entry)
    const metadata = JSON.parse(await readFile(join(backup, 'metadata.json'), 'utf8')) as {
        version?: number
        applications?: { installations?: { id?: string; uid?: number }[] }
    }
    assert.equal(metadata.version, PORTABLE_APP_BACKUP_VERSION)
    assert.deepEqual(
        metadata.applications?.installations?.map((installation) => ({
            id: installation.id,
            uid: installation.uid,
        })),
        [{ id: installationId, uid }],
    )
    // Nothing of the source remains, so the restored target has only the backup.
    await source.compose(['down', '--volumes', '--remove-orphans'], 180_000)

    container = await restore(offline, backup)
    assert.equal(
        await docker(['exec', container, 'ls', '/sys/class/net']),
        'lo',
        'the restored appliance has no network',
    )
    assert.deepEqual(await runningRelease(container, installationId), release)
    assert.equal(await probeNotes(container, uid), 'captured')
    console.log('Greeting ' + release.version + ' restored and running without a network')

    // Restoring again replaces the installed app, its data and database in place.
    await psql(
        container,
        'rp_app_' + uid,
        "INSERT INTO app.offline_restore_probe VALUES (2, 'after restore');",
    )
    container = await restore(offline, backup)
    assert.deepEqual(await runningRelease(container, installationId), release)
    assert.equal(await probeNotes(container, uid), 'captured')
    console.log('Greeting ' + release.version + ' replaced in place without a network')

    await mkdir(output, { recursive: true })
    await writeFile(
        join(output, 'greeting-offline-restore.json'),
        JSON.stringify(
            {
                platform,
                release,
                backupVersion: metadata.version,
                restoredWithoutNetwork: true,
                replacedInPlace: true,
                laterWritesRemoved: true,
            },
            null,
            4,
        ) + '\n',
    )
} finally {
    for (const target of targets)
        await target.compose(['down', '--volumes', '--remove-orphans'], 180_000).catch(
            (error: unknown) => console.error('Could not remove ' + target.project + ': ' + error),
        )
    await rm(root, { force: true, recursive: true })
}
