import assert from 'node:assert/strict'
import { spawn } from 'node:child_process'
import { randomBytes } from 'node:crypto'
import { mkdir, writeFile } from 'node:fs/promises'
import { join } from 'node:path'
import { createInterface } from 'node:readline'
import { waitForSmoke } from '../../../../../scripts/smoke/wait.ts'
import { exerciseProviders } from './providers.ts'

const root = '/tmp/reference-ipc'
const appSocket = root + '/app/app.sock'
const coreSocket = root + '/core/core.sock'
const wrongSocket = root + '/wrong/app.sock'
const appContext = root + '/app/bootstrap.json'
const wrongAppContext = root + '/wrong/bootstrap.json'
const managerContext = root + '/manager/bootstrap.json'
const wrongManagerContext = root + '/manager/wrong-listener.json'
const activeGenerationFile = root + '/manager/active'
const brokerBinary = root + '/broker'
const appUid = '21001'
const brokerUid = '21002'
const wrongUid = '21003'
const socketGroup = '21004'
const installationId = 'reference-install'

type Docker = (args: string[], timeout?: number) => Promise<string>
interface Reply {
    status: number
    body: unknown
}
interface CallOptions {
    body?: Record<string, unknown>
    installationId?: string
    generation?: number
    wrongCredential?: boolean
    wrongPeer?: boolean
}

const rejected = { status: 403, body: { error: 'installationContextRejected' } }

function reply(output: string): Reply {
    const result = JSON.parse(output) as Reply
    assert.ok(Number.isInteger(result.status) && result.status >= 100 && result.status <= 599)
    return result
}

async function prepare(
    docker: Docker,
    container: string,
    work: string,
    broker: string,
    generation: number,
) {
    const local = join(work, 'credentials-' + generation)
    const stage = root + '/staging'
    await mkdir(local, { mode: 0o700 })
    const app = {
        appSocket,
        coreSocket,
        installationId,
        generation,
        appCredential: randomBytes(32).toString('hex'),
        coreCredential: randomBytes(32).toString('hex'),
    }
    const manager = {
        ...app,
        appUid: Number(appUid),
        brokerUid: Number(brokerUid),
        activeGenerationFile,
    }
    const files = {
        app: JSON.stringify(app),
        manager: JSON.stringify(manager),
        wrongApp: JSON.stringify({ ...app, appSocket: wrongSocket }),
        wrongManager: JSON.stringify({ ...manager, appSocket: wrongSocket }),
        active: generation + '\n',
    }
    await Promise.all(
        Object.entries(files).map(([name, value]) =>
            writeFile(join(local, name), value, { mode: 0o600 }),
        ),
    )
    await docker(['exec', container, 'install', '-d', '-m', '0700', stage])
    await docker(['cp', local + '/.', container + ':' + stage])
    await docker(['cp', broker, container + ':' + root + '/broker-build'])
    await docker([
        'exec',
        container,
        'sh',
        '-ceu',
        [
            'install -d -m 0710 -o ' + appUid + ' -g ' + socketGroup + ' ' + root + '/app',
            'install -d -m 0710 -o ' + brokerUid + ' -g ' + socketGroup + ' ' + root + '/core',
            'install -d -m 0710 -o ' + wrongUid + ' -g ' + socketGroup + ' ' + root + '/wrong',
            'install -d -m 0700 -o ' + brokerUid + ' ' + root + '/manager',
            'install -m 0555 ' + root + '/broker-build ' + brokerBinary,
            'install -m 0400 -o ' + appUid + ' ' + stage + '/app ' + appContext,
            'install -m 0400 -o ' + wrongUid + ' ' + stage + '/wrongApp ' + wrongAppContext,
            'install -m 0400 -o ' + brokerUid + ' ' + stage + '/manager ' + managerContext,
            'install -m 0400 -o ' +
                brokerUid +
                ' ' +
                stage +
                '/wrongManager ' +
                wrongManagerContext,
            'install -m 0600 -o ' + brokerUid + ' ' + stage + '/active ' + activeGenerationFile,
            'rm ' +
                stage +
                '/app ' +
                stage +
                '/manager ' +
                stage +
                '/wrongApp ' +
                stage +
                '/wrongManager ' +
                stage +
                '/active ' +
                root +
                '/broker-build',
            'rmdir ' + stage,
        ].join('\n'),
    ])
}

async function verifyRevocation(docker: Docker, container: string, generation: number) {
    const process = spawn(
        'docker',
        [
            'exec',
            '--interactive',
            '--user',
            appUid + ':' + socketGroup,
            container,
            brokerBinary,
            'hold-core',
            appContext,
            brokerUid,
        ],
        { windowsHide: true },
    )
    const lines = createInterface({ input: process.stdout })
    const read = lines[Symbol.asyncIterator]()
    const exited = new Promise<number | null>((done) => {
        process.once('close', done)
        process.once('error', () => done(null))
    })
    process.stderr.resume()
    process.stdin.on('error', () => {})
    const timeout = setTimeout(() => process.kill(), 20_000)
    try {
        assert.equal((await read.next()).value, 'ready', 'The held connection did not authorize')
        await docker([
            'exec',
            '--user',
            brokerUid + ':' + socketGroup,
            container,
            'sh',
            '-ceu',
            'printf "%s\\n" "$1" > "$2.next"; mv -- "$2.next" "$2"',
            'retire-generation',
            String(generation + 1),
            activeGenerationFile,
        ])
        process.stdin.end('\n')
        assert.equal((await read.next()).value, 'revoked', 'The held connection retained access')
        assert.equal(await exited, 0)
        return { before: 202, after: 403, sameConnection: true }
    } finally {
        clearTimeout(timeout)
        lines.close()
        process.kill()
        await exited
    }
}

/** Start the test broker and the separately packaged app as distinct Linux users. */
export async function exerciseSockets(
    docker: Docker,
    container: string,
    work: string,
    broker: string,
    backend: string,
    generation: number,
    bunVersion: string,
) {
    await prepare(docker, container, work, broker, generation)
    const execAs = (uid: string, ...args: string[]) =>
        docker(['exec', '--user', uid + ':' + socketGroup, container, ...args], 6_000)
    const start = (uid: string, ...args: string[]) =>
        docker(['exec', '--detach', '--user', uid + ':' + socketGroup, container, ...args])
    const startApp = (uid: string, context: string) =>
        start(uid, 'sh', '-ceu', 'exec 3<"$1"; exec "$2"', 'start-app', context, backend)
    await start(brokerUid, brokerBinary, 'serve', managerContext)
    await Promise.all([startApp(appUid, appContext), startApp(wrongUid, wrongAppContext)])
    const callApp = async (method: string, path: string, options: CallOptions = {}) =>
        reply(
            await execAs(
                brokerUid,
                brokerBinary,
                'call-app',
                managerContext,
                method,
                path,
                JSON.stringify(options),
            ),
        )
    const callCore = async (
        path: string,
        options: CallOptions = {},
        uid = appUid,
        context = appContext,
    ) =>
        reply(
            await execAs(
                uid,
                brokerBinary,
                'call-core',
                context,
                brokerUid,
                'GET',
                path,
                JSON.stringify(options),
            ),
        )
    const ready = () => callApp('GET', '/app/v1/ready')
    let readinessError: unknown
    await waitForSmoke(
        async () => {
            await docker(['exec', container, 'test', '-S', wrongSocket])
            return (await ready()).status === 200
        },
        {
            timeoutMs: 15_000,
            intervalMs: 200,
            retryOnError(error) {
                readinessError = error
                return true
            },
            timeoutError: () =>
                new Error('Private reference sockets did not become ready', {
                    cause: readinessError,
                }),
        },
    )
    const core = { installationId, generation }
    assert.deepEqual(await ready(), { status: 200, body: { ready: true, bun: bunVersion, core } })
    assert.deepEqual(await callCore('/platform/v1/context'), { status: 200, body: core })
    const wrongListener: unknown = JSON.parse(
        await execAs(
            brokerUid,
            brokerBinary,
            'call-app',
            wrongManagerContext,
            'GET',
            '/app/v1/ready',
            JSON.stringify({ wrongPeer: true }),
        ),
    )
    assert.deepEqual(wrongListener, {
        error: 'peerUidRejected',
        expectedUid: Number(appUid),
        actualUid: Number(wrongUid),
    })
    assert.deepEqual(
        await callCore('/platform/v1/context', {}, wrongUid, wrongAppContext),
        rejected,
        'The platform accepted valid fixture credentials from a different Linux UID',
    )

    const invalid: CallOptions[] = [
        { installationId: 'another-installation' },
        { generation: generation - 1 },
        { wrongCredential: true },
    ]
    await Promise.all(
        invalid.map(async (options) => {
            assert.deepEqual(await callApp('GET', '/app/v1/ready', options), rejected)
            assert.deepEqual(await callCore('/platform/v1/context', options), rejected)
        }),
    )
    assert.deepEqual(await callCore('/platform/v1/secrets'), {
        status: 403,
        body: { error: 'scopeDenied' },
    })
    const mode = (path: string) => docker(['exec', container, 'stat', '-c', '%u:%g:%a', path])
    assert.equal(await mode(appSocket), appUid + ':' + socketGroup + ':660')
    assert.equal(await mode(coreSocket), brokerUid + ':' + socketGroup + ':660')
    const providers = await exerciseProviders((body) => callApp('POST', '/app/v1/probe', { body }))
    return {
        ready,
        verifyRevocation: () => verifyRevocation(docker, container, generation),
        evidence: {
            generation,
            providers,
            appSocket: {
                wrongPeerRejected: true,
                wrongInstallation: 403,
                stale: 403,
                wrongCredential: 403,
            },
            coreSocket: {
                wrongPeer: 403,
                wrongInstallation: 403,
                stale: 403,
                wrongCredential: 403,
                scopeDenied: 403,
            },
        },
    }
}
