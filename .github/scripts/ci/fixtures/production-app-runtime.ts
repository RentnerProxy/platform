#!/usr/local/bin/bun

import assert from 'node:assert/strict'
import { rm, writeFile } from 'node:fs/promises'
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
const providerCapability = { id: 'app.provider.register', scope: 'providerProfiles' }
const providerRegistration = { id: 'fixture-monitor', profile: 'monitoring', version: '1.0.0' }
const identity = {
    appId: 'rentnerproxy.runtime-check',
    installationId: 'production-app-check',
    uid: 20_991,
    generation: 1,
}
const installationDirectory = '/var/lib/rentnerproxy/apps/20991'
const dataDirectory = installationDirectory + '/data'
const databaseUrlFile = dataDirectory + '/database-url'
const progressFile = dataDirectory + '/fixture-progress'
const commandFile = dataDirectory + '/fixture-command'
const controllerTokenFile = '/run/rentnerproxy/controller-token/value'
const managerProgressFile = '/run/rentnerproxy-app-fixture-progress'

async function waitFor<T>(probe: () => Promise<T | undefined>, attempts = 100): Promise<T> {
    for (let attempt = 0; attempt < attempts; attempt += 1) {
        // oxlint-disable-next-line no-await-in-loop -- A failed probe can be retried within the fixture budget.
        const result = await probe()
        if (result !== undefined) return result
        // oxlint-disable-next-line no-await-in-loop -- Pace dependent readiness probes.
        await delay(100)
    }
    throw new Error('App runtime fixture timed out')
}

function isPublishedNotification(frame: string, message: string): boolean {
    const data = frame
        .split(/\r?\n/u)
        .filter((line) => line.startsWith('data:'))
        .map((line) => line.slice(5).replace(/^ /u, ''))
    if (data.length === 0) return false
    const event: unknown = JSON.parse(data.join('\n'))
    return (
        typeof event === 'object' &&
        event !== null &&
        'type' in event &&
        event.type === 'appNotificationPublished' &&
        'payload' in event &&
        typeof event.payload === 'object' &&
        event.payload !== null &&
        'message' in event.payload &&
        event.payload.message === message
    )
}

async function verifyNotificationStream(events: Response, message: string): Promise<void> {
    assert.equal(events.headers.get('Content-Type'), 'text/event-stream')
    const reader = events.body?.getReader()
    assert.ok(reader)
    try {
        const decoder = new TextDecoder()
        let remaining = ''
        let receivedBytes = 0
        for (;;) {
            // oxlint-disable-next-line no-await-in-loop -- Preserve UTF-8 and SSE framing across consecutive reads.
            const chunk = await reader.read()
            if (chunk.done) break
            receivedBytes += chunk.value.byteLength
            assert.ok(receivedBytes <= 65_536)
            remaining += decoder.decode(chunk.value, { stream: true })
            const frames = remaining.split(/\r?\n\r?\n/u)
            remaining = frames.pop() ?? ''
            if (frames.some((frame) => isPublishedNotification(frame, message))) return
        }
        assert.fail('Expected a complete published notification event')
    } finally {
        await reader.cancel()
    }
}

async function verifyApp(bootstrap: Bootstrap): Promise<void> {
    const request = (
        route: string,
        input?: unknown,
        key?: string,
        method = input === undefined ? 'GET' : 'POST',
    ) =>
        fetch('http://app-runtime/platform/v1/' + route, {
            unix: bootstrap.coreSocket,
            signal: AbortSignal.timeout(4_000),
            method,
            headers: {
                Authorization: 'Bearer ' + bootstrap.coreCredential,
                'X-App-Installation': bootstrap.installationId,
                'X-App-Generation': String(bootstrap.generation),
                ...(input !== undefined && { 'Content-Type': 'application/json' }),
                ...(key !== undefined && { 'Idempotency-Key': key }),
            },
            ...(input !== undefined && { body: JSON.stringify(input) }),
        })
    const provider = (id: string) => request('providers/' + id)
    const handoff = (domain: string) => request('legacy-handoffs/' + domain)
    const awaitProviderStatus = (status: number) =>
        waitFor(async () =>
            (await provider(providerRegistration.id)).status === status ? true : undefined,
        )
    let stage = 'preparation'
    try {
        assert.equal(process.getuid?.(), identity.uid)
        const context = await request('context')
        assert.equal(context.status, 200)
        const contextResult: unknown = await context.json()
        assert.deepEqual(contextResult, {
            appId: identity.appId,
            installationId: identity.installationId,
            generation: bootstrap.generation,
            runtimeProfile: 'rentnerproxy-linux-v1',
            versions: { appProtocol: '1.0.0', platformApi: '1.0.0' },
            capabilities: [notifyCapability],
        })
        const authorization = { capability: notifyCapability, resourceId: identity.installationId }
        assert.equal((await request('authorization', authorization)).status, 401)
        // A preparing generation cannot read a provider registration, including its own.
        assert.equal((await provider(providerRegistration.id)).status, 401)

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
                    : Response.json({
                          ready: true,
                          protocolVersion: '1.0.0',
                          providers: [providerRegistration],
                      })
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

        stage = 'provider'
        const live = await provider(providerRegistration.id)
        assert.equal(live.status, 200)
        assert.deepEqual(await live.json(), providerRegistration)
        assert.equal((await provider('fixture-unregistered')).status, 404)

        stage = 'legacy handoff'
        const platformOwned = { domain: providerRegistration.profile, state: 'platform' }
        const status = await handoff(providerRegistration.profile)
        assert.equal(status.status, 200)
        assert.deepEqual(await status.json(), platformOwned)
        // Monitoring registers a source: begin fences built-in monitoring and fixes one export.
        const begin = () =>
            request(
                'legacy-handoffs/' + providerRegistration.profile + '/begin',
                undefined,
                'begin-' + bootstrap.generation,
                'POST',
            )
        const begun = await begin()
        assert.equal(begun.status, 200)
        const exported: unknown = await begun.json()
        assert.ok(typeof exported === 'object' && exported !== null)
        assert.equal('state' in exported && exported.state, 'exported')
        const digest = 'digest' in exported ? exported.digest : undefined
        assert.ok(typeof digest === 'string' && /^[a-f0-9]{64}$/u.test(digest))
        // Even an empty export holds its manifest and end parts.
        assert.ok('partCount' in exported && Number(exported.partCount) >= 2)
        // The status shows the open handoff, and a repeated begin resumes the same export.
        assert.deepEqual(await (await handoff(providerRegistration.profile)).json(), exported)
        assert.deepEqual(await (await begin()).json(), exported)
        const first = await request('legacy-handoffs/' + providerRegistration.profile + '/parts', {
            digest,
            sequence: 0,
        })
        assert.equal(first.status, 200)
        const manifest: unknown = await first.json()
        assert.ok(typeof manifest === 'object' && manifest !== null && 'part' in manifest)
        assert.ok(typeof manifest.part === 'object' && manifest.part !== null)
        assert.equal('kind' in manifest.part && manifest.part.kind, 'manifest')
        assert.equal('format' in manifest.part && manifest.part.format, 'rentnerproxy.monitoring')
        // The app manager's removal check aborts it, as an uninstall would; built-in monitoring
        // is platform-owned again for the rest of the smoke.
        await Bun.write(progressFile, 'handoff-begun-' + bootstrap.generation)
        await awaitCommand('handoff-aborted-' + bootstrap.generation)
        assert.deepEqual(await (await handoff(providerRegistration.profile)).json(), platformOwned)
        // The manifest does not declare dns as a provider profile.
        assert.equal((await handoff('dns')).status, 403)

        if (bootstrap.generation !== 1) {
            await Bun.write(progressFile, 'ready-' + bootstrap.generation)
            stage = 'failure'
            await awaitCommand('crash')
            // Simulate an app crash after activation. Platform must stay reachable.
            process.exit(1)
        }

        stage = 'database'
        assert.equal(process.env.RENTNERPROXY_APP_DATABASE_URL_FILE, databaseUrlFile)
        const url = (await Bun.file(databaseUrlFile).text()).trim()
        const local = new Bun.SQL({ url, connectionTimeout: 2 })
        const foreign = new Bun.SQL({ url, database: 'rentnerproxy', connectionTimeout: 2 })
        try {
            const [database] = await local<{ name: string }[]>`SELECT current_database() AS name`
            assert.equal(database?.name, 'rp_app_20991')
            await assert.rejects(
                async () => {
                    await local`CREATE TABLE app.fixture_forbidden (id bigint)`
                },
                (error: unknown) =>
                    error instanceof Error && 'errno' in error && error.errno === '42501',
            )
            await assert.rejects(
                async () => {
                    await foreign`SELECT current_database()`
                },
                (error: unknown) =>
                    error instanceof Error && 'errno' in error && error.errno === '28000',
            )
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
        await verifyNotificationStream(await request('events'), notification.message)
        await Bun.write(progressFile, 'ready-1')

        stage = 'grant revocation'
        await awaitCommand('revoke-grant')
        await awaitProviderStatus(404)
        // Without the provider grant the installation has no handoff authority either.
        assert.equal((await handoff(providerRegistration.profile)).status, 403)
        await Bun.write(progressFile, 'grant-revoked')

        stage = 'grant restoration'
        await awaitCommand('restore-grant')
        await awaitProviderStatus(200)
        await Bun.write(progressFile, 'grant-restored')
    } catch {
        await Bun.write(progressFile, 'failed at ' + stage)
        process.exit(1)
    }
}

function readProgress(): Promise<string> {
    return Bun.file(progressFile)
        .text()
        .catch(() => '')
}

function awaitProgress(target: string): Promise<boolean> {
    return waitFor(async () => {
        const current = await readProgress()
        if (current.startsWith('failed at ')) throw new Error(current)
        return current === target ? true : undefined
    })
}

function awaitCommand(command: string): Promise<boolean> {
    return waitFor(async () => {
        const current = await Bun.file(commandFile)
            .text()
            .catch(() => '')
        return current === command ? true : undefined
    }, 300)
}

/** An app failure must leave management readiness and the proxy listener available. */
async function verifyPlatformReachable(): Promise<void> {
    const ready = await fetch('http://127.0.0.1:3000/health/ready', {
        signal: AbortSignal.timeout(4_000),
    })
    assert.equal(ready.status, 200)
    assert.deepEqual(await ready.json(), { status: 'ready' })
    const proxy = await fetch('http://127.0.0.1:8080/', {
        redirect: 'manual',
        signal: AbortSignal.timeout(4_000),
    })
    assert.ok(proxy.status >= 200 && proxy.status < 500, 'Proxy listener is unavailable')
}

function setManagerStage(stage: string): Promise<number> {
    return Bun.write(managerProgressFile, stage)
}

async function verifyManager() {
    await setManagerStage('bridge readiness')
    const token = (await Bun.file(controllerTokenFile).text()).trim()
    const controlRequest = (action: string, body: unknown) =>
        fetch('http://app-runtime/internal/v1/app-generations/' + action, {
            unix: '/run/rentnerproxy/app-api/web.sock',
            signal: AbortSignal.timeout(4_000),
            method: 'POST',
            headers: { Authorization: 'Bearer ' + token, 'Content-Type': 'application/json' },
            body: JSON.stringify(body),
        })
    await waitFor(async () => {
        const response = await controlRequest('lease', { identity }).catch(() => null)
        return response?.status === 401 ? true : undefined
    })
    const control = async (action: string, body: unknown) => {
        const response = await controlRequest(action, body)
        assert.equal(response.status, 204, 'App manager control rejected ' + action)
    }
    const generationIdentity = (generation: number) => ({ ...identity, generation })
    /** Return the monitoring handoff the app began to platform, as the removal check does. */
    const abortHandoff = async (generation: number) => {
        await awaitProgress('handoff-begun-' + generation)
        await control('removable', { identity: generationIdentity(generation) })
        await writeFile(commandFile, 'handoff-aborted-' + generation)
    }
    const grants = (generation: number, provider: boolean) => ({
        identity: generationIdentity(generation),
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
            ...(provider
                ? [
                      {
                          capability: providerCapability,
                          resourceId: providerRegistration.profile,
                          allowService: true,
                      },
                  ]
                : []),
        ],
    })
    const register = async (generation: number) => {
        const lease = {
            identity: generationIdentity(generation),
            leaseExpiresAt: new Date(Date.now() + 120_000).toISOString(),
        }
        await control('register', {
            ...lease,
            capabilities: [notifyCapability],
            providerProfiles: [providerRegistration.profile],
        })
        await control('grants', grants(generation, true))
        return lease
    }
    await setManagerStage('registration')
    const lease = await register(1)

    await setManagerStage('provisioning')
    const provision = (storage: 'files' | 'database') =>
        Bun.spawn(['/usr/local/bin/rentnerproxy-provision-app', String(identity.uid), storage], {
            stdout: 'ignore',
            stderr: 'ignore',
        }).exited
    assert.equal(await provision('files'), 0, 'Could not create isolated app paths')
    await writeFile(installationDirectory + '/database-password', '', {
        flag: 'wx',
        mode: 0o600,
    })
    assert.equal(await provision('database'), 0, 'Could not provision the isolated app database')
    const brokers: Bun.Subprocess<'pipe', 'pipe', 'ignore'>[] = []
    const launch = async (generation: number) => {
        const broker = Bun.spawn(['/usr/local/bin/rentnerproxy-controller', '--app-ipc'], {
            stdin: 'pipe',
            stdout: 'pipe',
            stderr: 'ignore',
            env: { RENTNERPROXY_CONTROLLER_TOKEN_FILE: controllerTokenFile },
        })
        brokers.push(broker)
        const ready = broker.stdout.getReader()
        try {
            await broker.stdin.write(
                JSON.stringify({
                    ...generationIdentity(generation),
                    gid: identity.uid,
                    executable: '/usr/local/lib/rentnerproxy-app-runtime-fixture.ts',
                    dataDirectory,
                    databaseUrlFile,
                    runtimeProfile: 'rentnerproxy-linux-v1',
                    appProtocol: '>=1.0.0 <2.0.0',
                    platformApi: '>=1.0.0 <2.0.0',
                    providers: [providerRegistration.profile],
                }) + '\n',
            )
            await broker.stdin.flush()
            const readiness = await ready.read()
            assert.equal(new TextDecoder().decode(readiness.value), 'ready\n', await readProgress())
        } finally {
            ready.releaseLock()
        }
        return broker
    }
    try {
        await setManagerStage('launch')
        const first = await launch(1)
        await setManagerStage('activation')
        await control('activate', lease)
        await setManagerStage('app checks')
        await abortHandoff(1)
        await awaitProgress('ready-1')

        await setManagerStage('grant revocation')
        await control('grants', grants(1, false))
        await writeFile(commandFile, 'revoke-grant')
        await awaitProgress('grant-revoked')
        await setManagerStage('grant restoration')
        await control('grants', grants(1, true))
        await writeFile(commandFile, 'restore-grant')
        await awaitProgress('grant-restored')

        // The app manager fences the running generation before it launches an update.
        await setManagerStage('retirement')
        await control('retire', { identity })
        assert.equal((await controlRequest('lease', { identity })).status, 401)
        assert.equal(await first.exited, 0, 'Lease revocation did not stop the broker')
        const staleProviders = { identity, providers: [providerRegistration] }
        assert.equal((await controlRequest('providers', staleProviders)).status, 409)

        await setManagerStage('update')
        await rm(commandFile, { force: true })
        await rm(progressFile, { force: true })
        const updateLease = await register(2)
        const second = await launch(2)
        await control('activate', updateLease)
        await abortHandoff(2)
        await awaitProgress('ready-2')
        assert.equal((await controlRequest('lease', { identity })).status, 401)
        assert.equal((await controlRequest('providers', staleProviders)).status, 409)

        await setManagerStage('failure')
        await verifyPlatformReachable()
        await writeFile(commandFile, 'crash')
        assert.notEqual(await second.exited, 0, 'The broker did not report the app crash')
        await verifyPlatformReachable()
        await control('retire', { identity: generationIdentity(2) })
        const retired = { identity: generationIdentity(2) }
        assert.equal((await controlRequest('lease', retired)).status, 401)
    } finally {
        await Promise.all(
            brokers.map(async (broker) => {
                await Promise.resolve(broker.stdin.end()).catch(() => undefined)
                await broker.exited
            }),
        )
    }
    await setManagerStage('cleanup')
    const cleanup = Bun.spawn(
        [
            'gosu',
            'postgres',
            'psql',
            '--no-psqlrc',
            '--no-password',
            '--set=ON_ERROR_STOP=1',
            '--set=fixture_id=' + identity.installationId,
            '--host=/var/run/postgresql',
            '--username=postgres',
            '--dbname=rentnerproxy',
        ],
        {
            stdin: new Blob([
                [
                    'BEGIN;',
                    "DELETE FROM rentnerproxy.app_runtime_events WHERE installation_id = :'fixture_id';",
                    "DELETE FROM rentnerproxy.app_runtime_event_retention WHERE installation_id = :'fixture_id';",
                    "DELETE FROM rentnerproxy.app_runtime_messages WHERE installation_id = :'fixture_id';",
                    "DELETE FROM rentnerproxy.app_runtime_grants WHERE installation_id = :'fixture_id';",
                    "DELETE FROM rentnerproxy.app_runtime_generations WHERE installation_id = :'fixture_id';",
                    "DELETE FROM rentnerproxy.app_runtime_installations WHERE id = :'fixture_id';",
                    'COMMIT;',
                    'DROP DATABASE rp_app_20991;',
                    'DROP ROLE rp_app_20991, rp_migrate_20991;',
                    '',
                ].join('\n'),
            ]),
            stdout: 'ignore',
            stderr: 'ignore',
        },
    )
    assert.equal(await cleanup.exited, 0, 'Could not remove isolated database and roles')
    await rm(installationDirectory, { recursive: true })
}

if (process.env.RENTNERPROXY_APP_BOOTSTRAP_FD === '0') {
    await verifyApp(JSON.parse(await Bun.stdin.text()) as Bootstrap)
} else {
    await verifyManager()
}
