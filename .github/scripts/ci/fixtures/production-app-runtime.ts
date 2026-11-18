#!/usr/local/bin/bun

import assert from 'node:assert/strict'
import { setTimeout as delay } from 'node:timers/promises'

interface Bootstrap {
    readonly installationId: string
    readonly generation: number
    readonly appId: string
    readonly appSocket: string
    readonly coreSocket: string
    readonly appCredential: string
    readonly coreCredential: string
}

const notifyCapability = { id: 'notifications.publish.v1', scope: 'installation' }
const identity = {
    appId: 'rentnerproxy.runtime-check',
    installationId: 'production-app-check',
    uid: 20_991,
    generation: 1,
}
const dataDirectory = '/var/lib/rentnerproxy/apps/20991/data'
const databaseUrlFile = dataDirectory + '/database-url'
const progressFile = dataDirectory + '/fixture-progress'
const controllerTokenFile = '/run/rentnerproxy/controller-token/value'

async function waitFor<T>(probe: () => Promise<T | undefined>): Promise<T> {
    for (let attempt = 0; attempt < 100; attempt += 1) {
        // oxlint-disable-next-line no-await-in-loop -- A failed probe can be retried within the fixture budget.
        const result = await probe()
        if (result !== undefined) return result
        // oxlint-disable-next-line no-await-in-loop -- Pace dependent readiness probes.
        await delay(100)
    }
    throw new Error('App runtime fixture timed out')
}

async function verifyApp(bootstrap: Bootstrap): Promise<void> {
    const request = (route: string, input?: unknown, key?: string) =>
        fetch('http://app-runtime/platform/v1/' + route, {
            unix: bootstrap.coreSocket,
            signal: AbortSignal.timeout(4_000),
            method: input === undefined ? 'GET' : 'POST',
            headers: {
                Authorization: 'Bearer ' + bootstrap.coreCredential,
                'X-App-Installation': bootstrap.installationId,
                'X-App-Generation': String(bootstrap.generation),
                ...(input !== undefined && { 'Content-Type': 'application/json' }),
                ...(key !== undefined && { 'Idempotency-Key': key }),
            },
            ...(input !== undefined && { body: JSON.stringify(input) }),
        })
    let stage = 'preparation'
    try {
        assert.equal(process.getuid?.(), identity.uid)
        const context = await request('context')
        assert.equal(context.status, 200)
        const contextResult: unknown = await context.json()
        assert.deepEqual(contextResult, {
            appId: identity.appId,
            installationId: identity.installationId,
            generation: 1,
            runtimeProfile: 'rentnerproxy-linux-v1',
            versions: { appProtocol: '1.0.0', platformApi: '1.0.0' },
            capabilities: [notifyCapability],
        })
        const authorization = { capability: notifyCapability, resourceId: identity.installationId }
        assert.equal((await request('authorization', authorization)).status, 401)

        Bun.serve({
            unix: bootstrap.appSocket,
            fetch(incoming) {
                if (
                    incoming.headers.get('Authorization') !== 'Bearer ' + bootstrap.appCredential ||
                    incoming.headers.get('X-App-Installation') !== bootstrap.installationId ||
                    incoming.headers.get('X-App-Generation') !== String(bootstrap.generation)
                )
                    return new Response(null, { status: 401 })
                return new URL(incoming.url).pathname === '/app/v1/health'
                    ? Response.json({ healthy: true })
                    : Response.json({ ready: true, protocolVersion: '1.0.0', providers: [] })
            },
        })

        stage = 'activation'
        await waitFor(async () => {
            const response = await request('authorization', authorization)
            if (!response.ok) return undefined
            const result: unknown = await response.json()
            assert.deepEqual(result, { allowed: true })
            return true
        })

        stage = 'database'
        assert.equal(process.env.RENTNERPROXY_APP_DATABASE_URL_FILE, databaseUrlFile)
        const url = (await Bun.file(databaseUrlFile).text()).trim()
        const local = new Bun.SQL({ url, connectionTimeout: 2 })
        const foreign = new Bun.SQL({ url, database: 'rentnerproxy', connectionTimeout: 2 })
        try {
            const [database] = await local<{ name: string }[]>`SELECT current_database() AS name`
            assert.equal(database?.name, 'rp_app_20991')
            await assert.rejects(async () => {
                await local`CREATE TABLE app.fixture_forbidden (id bigint)`
            })
            await assert.rejects(async () => {
                await foreign`SELECT current_database()`
            })
        } finally {
            await Promise.allSettled([local.close(), foreign.close()])
        }

        stage = 'notification'
        const notification = {
            category: 'fixture',
            severity: 'info',
            title: 'Fixture',
            message: 'App notification',
        }
        assert.equal((await request('notifications', notification, 'publish-one')).status, 204)
        assert.equal((await request('notifications', notification, 'publish-one')).status, 204)
        assert.equal(
            (await request('notifications', { ...notification, message: 'Changed' }, 'publish-one'))
                .status,
            409,
        )
        const events = await request('events')
        assert.equal(events.headers.get('Content-Type'), 'text/event-stream')
        await events.body?.cancel()
        await Bun.write(progressFile, 'ready')

        stage = 'revocation'
        await waitFor(async () => ((await request('context')).status === 401 ? true : undefined))
        await Bun.write(progressFile, 'revoked')
    } catch {
        await Bun.write(progressFile, 'failed at ' + stage)
        process.exit(1)
    }
}

async function verifyManager() {
    const token = (await Bun.file(controllerTokenFile).text()).trim()
    const control = async (action: string, body: unknown) => {
        const response = await fetch('http://app-runtime/internal/v1/app-generations/' + action, {
            unix: '/run/rentnerproxy/app-api/web.sock',
            signal: AbortSignal.timeout(4_000),
            method: 'POST',
            headers: { Authorization: 'Bearer ' + token, 'Content-Type': 'application/json' },
            body: JSON.stringify(body),
        })
        assert.equal(response.status, 204, 'App manager control rejected ' + action)
    }
    const lease = { identity, leaseExpiresAt: new Date(Date.now() + 120_000).toISOString() }
    await control('register', { ...lease, capabilities: [notifyCapability] })
    await control('grants', {
        identity,
        grants: [
            {
                capability: notifyCapability,
                resourceId: identity.installationId,
                allowService: true,
            },
            {
                capability: { id: 'app.events.subscribe', scope: 'installation' },
                resourceId: identity.installationId,
                allowService: true,
            },
        ],
    })

    const provision = Bun.spawn(
        ['/usr/local/bin/rentnerproxy-provision-app', String(identity.uid), 'database'],
        {
            stdout: 'ignore',
            stderr: 'ignore',
        },
    )
    assert.equal(await provision.exited, 0, 'Could not provision the isolated app')
    const broker = Bun.spawn(['/usr/local/bin/rentnerproxy-controller', '--app-ipc'], {
        stdin: 'pipe',
        stdout: 'pipe',
        stderr: 'ignore',
        env: { RENTNERPROXY_CONTROLLER_TOKEN_FILE: controllerTokenFile },
    })
    const ready = broker.stdout.getReader()
    try {
        await broker.stdin.write(
            JSON.stringify({
                ...identity,
                gid: identity.uid,
                executable: '/usr/local/lib/rentnerproxy-app-runtime-fixture.ts',
                dataDirectory,
                databaseUrlFile,
                leaseSeconds: 60,
                runtimeProfile: 'rentnerproxy-linux-v1',
                appProtocol: '>=1.0.0 <2.0.0',
                platformApi: '>=1.0.0 <2.0.0',
            }) + '\n',
        )
        await broker.stdin.flush()
        const readiness = await ready.read()
        const progress = () =>
            Bun.file(progressFile)
                .text()
                .catch(() => '')
        assert.equal(new TextDecoder().decode(readiness.value), 'ready\n', await progress())
        await control('activate', lease)
        const awaitProgress = (target: string) =>
            waitFor(async () => {
                const current = await progress()
                if (current.startsWith('failed at ')) throw new Error(current)
                return current === target ? true : undefined
            })
        await awaitProgress('ready')
        await control('revoke', { identity })
        await awaitProgress('revoked')
    } finally {
        ready.releaseLock()
        await broker.stdin.end()
        assert.equal(await broker.exited, 0, 'App broker failed')
    }
}

if (process.env.RENTNERPROXY_APP_BOOTSTRAP_FD === '0') {
    await verifyApp(JSON.parse(await Bun.stdin.text()) as Bootstrap)
} else {
    await verifyManager()
}
