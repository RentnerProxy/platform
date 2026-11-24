import { expect, test } from 'bun:test'
import { and, eq, inArray, sql } from 'drizzle-orm'

import { LEGACY_HANDOFF_LIMITS } from '@/config/legacy-handoff.config.ts'
import {
    appRuntimeGenerations,
    appRuntimeGrants,
    appRuntimeInstallations,
    legacyFeatureHandoffParts,
    legacyFeatureHandoffRequests,
    legacyFeatureHandoffs,
} from '@/db/schema.ts'
import { APP_RUNTIME_SUPPORT_CAPABILITIES } from '@/server/AppRuntime/authority-policy.server.ts'
import type { AppRuntimeJsonValue } from '@/server/AppRuntime/Types/authority.types.ts'
import type { LegacyFeatureHandoffSources } from '@/server/LegacyHandoff/Types/legacy-handoff-api.types.ts'
import type {
    LegacyFeatureDomain,
    LegacyFeatureHandoffSource,
} from '@/server/LegacyHandoff/Types/legacy-handoff.types.ts'

const integrationEnabled =
    process.env.RENTNERPROXY_DATABASE_INTEGRATION === '1' && Boolean(process.env.DATABASE_URL)
const integrationTest = integrationEnabled ? test : test.skip

interface Identity {
    readonly appId: string
    readonly installationId: string
    readonly generation: number
    readonly uid: number
}

interface Reply {
    readonly status: number
    readonly body: unknown
}

/** A synthetic built-in feature: its records stay until the committed handoff retires them. */
function featureSource(domain: LegacyFeatureDomain, records: AppRuntimeJsonValue[]) {
    const state = { exports: 0, retirements: 0, records }
    const source: LegacyFeatureHandoffSource = {
        domain,
        inspect: () => Promise.resolve({ configured: true, references: state.records.length }),
        export: async (_transaction, emit) => {
            state.exports += 1
            for (const record of state.records) {
                // oxlint-disable-next-line no-await-in-loop -- Parts are emitted in order.
                await emit(record)
            }
        },
        retire: () => {
            state.retirements += 1
            state.records = []
            return Promise.resolve()
        },
    }
    return { source, state }
}

const leaseExpiresAt = () => new Date(Date.now() + 60_000).toISOString()
const route = (domain: string, suffix = '') => '/platform/v1/legacy-handoffs/' + domain + suffix

const providerGrant = (profile: LegacyFeatureDomain, allowService = true) => ({
    capability: APP_RUNTIME_SUPPORT_CAPABILITIES.provider,
    resourceId: profile,
    allowService,
})

async function createHarness(domains: readonly LegacyFeatureDomain[], encryptionFill: number) {
    const { db } = await import('@/db/index.ts')
    const { createAppRuntimeGateway } = await import('@/server/AppRuntime/gateway.server.ts')
    const { manageAppRuntime } = await import('@/server/AppRuntime/management.server.ts')
    const { executeAppRuntimeCall } = await import('@/server/AppRuntime/services.server.ts')

    // Refuse a shared database instead of taking over another run's handoffs.
    const held = await db
        .select({ domain: legacyFeatureHandoffs.domain })
        .from(legacyFeatureHandoffs)
        .where(inArray(legacyFeatureHandoffs.domain, [...domains]))
    if (held.length > 0)
        throw new Error('Another handoff holds a test domain; use an isolated database.')

    const originalKey = process.env.APP_ENCRYPTION_KEY
    process.env.APP_ENCRYPTION_KEY = Buffer.alloc(32, encryptionFill).toString('base64')
    const token = 'legacy-handoff-api-bridge'
    const shutdown = new AbortController()
    const identities: Identity[] = []
    const uidBase = 20_000 + Math.floor(Math.random() * 39_000)

    const gatewayFor = (sources: LegacyFeatureHandoffSources) =>
        createAppRuntimeGateway(
            token,
            shutdown.signal,
            (call) => executeAppRuntimeCall(call, sources),
            manageAppRuntime,
        )
    const send = async (
        gateway: ReturnType<typeof gatewayFor>,
        target: Identity,
        path: string,
        {
            body,
            key,
            method = body === undefined ? 'GET' : 'POST',
        }: {
            body?: unknown
            key?: string
            method?: 'GET' | 'POST'
        } = {},
    ): Promise<Reply> => {
        const response = await gateway(
            new Request('http://app-api' + path, {
                method,
                headers: {
                    Authorization: 'Bearer ' + token,
                    'X-App-Installation': target.installationId,
                    'X-App-Generation': String(target.generation),
                    'X-RentnerProxy-App-Uid': String(target.uid),
                    'X-RentnerProxy-App-Id': target.appId,
                    ...(key !== undefined && { 'Idempotency-Key': key }),
                    ...(body !== undefined && { 'Content-Type': 'application/json' }),
                },
                ...(body !== undefined && { body: JSON.stringify(body) }),
            }),
        )
        const text = await response.text()
        return { status: response.status, body: text ? (JSON.parse(text) as unknown) : null }
    }

    const handoffApi = (sources: LegacyFeatureHandoffSources) => {
        const gateway = gatewayFor(sources)
        return {
            status: (target: Identity, domain: string) => send(gateway, target, route(domain)),
            begin: (target: Identity, domain: string, key = 'begin-1') =>
                send(gateway, target, route(domain, '/begin'), { key, method: 'POST' }),
            part: (target: Identity, domain: string, sequence: unknown, digest?: string) =>
                send(gateway, target, route(domain, '/parts'), { body: { digest, sequence } }),
            commit: (target: Identity, domain: string, digest: string, key = 'commit-1') =>
                send(gateway, target, route(domain, '/commit'), { body: { digest }, key }),
        }
    }

    /**
     * Serve the gateway on a real socket, as the broker reaches it, and keep every call's outcome
     * so a test can wait until a transaction finished after its client went away.
     */
    const listen = (sources: LegacyFeatureHandoffSources) => {
        const settled: Promise<unknown>[] = []
        const gateway = createAppRuntimeGateway(token, shutdown.signal, (call) => {
            const result = executeAppRuntimeCall(call, sources)
            settled.push(result.catch(() => undefined))
            return result
        })
        const server = Bun.serve({ hostname: '127.0.0.1', port: 0, fetch: gateway })
        const beginOverSocket = async (target: Identity, domain: string, key: string) => {
            const socket = await Bun.connect({
                hostname: '127.0.0.1',
                port: server.port!,
                socket: { data: () => undefined },
            })
            socket.write(
                [
                    `POST ${route(domain, '/begin')} HTTP/1.1`,
                    'Host: app-api',
                    'Authorization: Bearer ' + token,
                    'X-App-Installation: ' + target.installationId,
                    'X-App-Generation: ' + target.generation,
                    'X-RentnerProxy-App-Uid: ' + target.uid,
                    'X-RentnerProxy-App-Id: ' + target.appId,
                    'Idempotency-Key: ' + key,
                    'Content-Length: 0',
                    '',
                    '',
                ].join('\r\n'),
            )
            return socket
        }
        return { server, settled, beginOverSocket }
    }

    const controlGateway = gatewayFor({})
    const control = async (action: string, target: Identity, fields: object = {}) =>
        (
            await send(controlGateway, target, '/internal/v1/app-generations/' + action, {
                body: { identity: target, ...fields },
            })
        ).status

    /** Install one app generation with the given manifest profiles and provider grants. */
    const install = async (
        appId: string,
        providerProfiles: readonly LegacyFeatureDomain[],
        grants: ReturnType<typeof providerGrant>[],
    ) => {
        const identity = {
            appId,
            installationId: crypto.randomUUID(),
            generation: 1,
            uid: uidBase + identities.length,
        }
        identities.push(identity)
        expect(
            await control('register', identity, {
                leaseExpiresAt: leaseExpiresAt(),
                capabilities: [],
                providerProfiles,
            }),
        ).toBe(204)
        expect(await control('grants', identity, { grants })).toBe(204)
        return identity
    }
    const activate = async (identity: Identity) =>
        expect(await control('activate', identity, { leaseExpiresAt: leaseExpiresAt() })).toBe(204)

    const journalRows = () =>
        db
            .select({
                domain: legacyFeatureHandoffs.domain,
                installationId: legacyFeatureHandoffs.installationId,
                state: legacyFeatureHandoffs.state,
            })
            .from(legacyFeatureHandoffs)
            .where(inArray(legacyFeatureHandoffs.domain, [...domains]))
            .orderBy(legacyFeatureHandoffs.domain)
    const partCount = async (domain: LegacyFeatureDomain) =>
        (
            await db
                .select({ sequence: legacyFeatureHandoffParts.sequence })
                .from(legacyFeatureHandoffParts)
                .where(eq(legacyFeatureHandoffParts.domain, domain))
        ).length

    const release = async () => {
        shutdown.abort()
        if (originalKey === undefined) delete process.env.APP_ENCRYPTION_KEY
        else process.env.APP_ENCRYPTION_KEY = originalKey
        const installationIds = identities.map(({ installationId }) => installationId)
        if (installationIds.length === 0) return
        await db.transaction(async (transaction) => {
            const owned = await transaction
                .select({ domain: legacyFeatureHandoffs.domain })
                .from(legacyFeatureHandoffs)
                .where(inArray(legacyFeatureHandoffs.installationId, installationIds))
            const ownedDomains = owned.map(({ domain }) => domain)
            if (ownedDomains.length > 0) {
                await transaction
                    .delete(legacyFeatureHandoffParts)
                    .where(inArray(legacyFeatureHandoffParts.domain, ownedDomains))
                await transaction
                    .delete(legacyFeatureHandoffs)
                    .where(inArray(legacyFeatureHandoffs.domain, ownedDomains))
            }
            await transaction
                .delete(appRuntimeGrants)
                .where(inArray(appRuntimeGrants.installationId, installationIds))
            await transaction
                .delete(appRuntimeGenerations)
                .where(inArray(appRuntimeGenerations.installationId, installationIds))
            await transaction
                .delete(appRuntimeInstallations)
                .where(inArray(appRuntimeInstallations.id, installationIds))
        })
    }

    return { db, handoffApi, listen, control, install, activate, journalRows, partCount, release }
}

integrationTest(
    'only a declared, granted live generation reads, exports and commits a built-in domain',
    async () => {
        const harness = await createHarness(['dns', 'monitoring', 'docker-discovery', 'oidc'], 81)
        const { db, install, activate, control, journalRows, partCount } = harness
        try {
            const dnsRecords: AppRuntimeJsonValue[] = [
                { zone: 'example.test', provider: 'synthetic' },
                { credential: 'legacy-dns-' + crypto.randomUUID() },
                { history: [1, 2, 3] },
            ]
            const dns = featureSource('dns', dnsRecords)
            const discovery = featureSource('docker-discovery', [{ connection: 'local' }])
            const api = harness.handoffApi({
                dns: dns.source,
                'docker-discovery': discovery.source,
            })

            const app = await install(
                'test.handoff-api',
                ['dns', 'monitoring', 'docker-discovery'],
                [
                    providerGrant('dns'),
                    providerGrant('monitoring'),
                    providerGrant('docker-discovery', false),
                ],
            )
            const rival = await install('test.handoff-rival', ['dns'], [providerGrant('dns')])

            // A preparing generation has no handoff authority yet.
            expect((await api.status(app, 'dns')).status).toBe(401)
            await activate(app)
            await activate(rival)

            expect(await api.status(app, 'dns')).toEqual({
                status: 200,
                body: { domain: 'dns', state: 'platform' },
            })
            // The domain must be declared, granted and allowed for the service principal.
            for (const [domain, status] of [
                ['oidc', 403],
                ['crowdsec', 403],
                ['docker-discovery', 403],
                ['proxy-hosts', 400],
            ] as const) {
                // oxlint-disable-next-line no-await-in-loop -- Each refusal is checked alone.
                const reply = await api.status(app, domain)
                expect(reply.status).toBe(status)
            }
            expect((await api.begin(app, 'docker-discovery')).body).toMatchObject({
                code: 'scopeDenied',
            })
            expect(discovery.state.exports).toBe(0)
            expect((await api.status({ ...app, uid: app.uid + 100 }, 'dns')).status).toBe(401)
            const otherDigest = 'b'.repeat(64)
            expect((await api.part(app, 'dns', 1_024, otherDigest)).status).toBe(400)
            expect((await api.part(app, 'dns', -1, otherDigest)).status).toBe(400)
            expect((await api.part(app, 'dns', 0)).status).toBe(400)
            expect((await api.part(app, 'dns', 0, 'not-a-digest')).status).toBe(400)
            expect((await api.commit(app, 'dns', 'not-a-digest')).status).toBe(400)

            // Without a registered source, platform keeps the domain and nothing is fenced.
            expect((await api.status(app, 'monitoring')).body).toEqual({
                domain: 'monitoring',
                state: 'platform',
            })
            expect(await api.begin(app, 'monitoring')).toMatchObject({
                status: 404,
                body: { code: 'notFound' },
            })
            expect((await api.part(app, 'monitoring', 0, otherDigest)).status).toBe(404)
            expect((await api.commit(app, 'monitoring', otherDigest)).status).toBe(404)
            expect(await journalRows()).toEqual([])

            // Nothing is exported yet.
            expect((await api.part(app, 'dns', 0, otherDigest)).status).toBe(404)
            expect((await api.commit(app, 'dns', otherDigest)).status).toBe(404)

            const begun = await api.begin(app, 'dns')
            expect(begun).toMatchObject({
                status: 200,
                body: { domain: 'dns', state: 'exported', partCount: 3 },
            })
            const { digest } = begun.body as { digest: string }
            expect(digest).toMatch(/^[a-f0-9]{64}$/u)
            expect(await api.begin(app, 'dns', 'begin-2')).toEqual(begun)
            expect(dns.state.exports).toBe(1)
            expect((await api.status(app, 'dns')).body).toEqual(begun.body)
            // A key reused for another domain is refused before the journal is touched.
            expect(await api.begin(app, 'monitoring', 'begin-1')).toMatchObject({
                status: 409,
                body: { code: 'idempotencyConflict' },
            })
            expect(await journalRows()).toEqual([
                { domain: 'dns', installationId: app.installationId, state: 'exported' },
            ])

            // Another installation never sees this handoff as a state.
            for (const reply of await Promise.all([
                api.status(rival, 'dns'),
                api.begin(rival, 'dns'),
                api.part(rival, 'dns', 0, digest),
                api.commit(rival, 'dns', digest),
                // A read bound to another export never returns a part of this one.
                api.part(app, 'dns', 0, otherDigest),
            ]))
                expect(reply).toMatchObject({ status: 409, body: { code: 'conflict' } })

            expect(
                await Promise.all(
                    dnsRecords.map((_, sequence) => api.part(app, 'dns', sequence, digest)),
                ),
            ).toEqual(
                dnsRecords.map((part, sequence) => ({ status: 200, body: { sequence, part } })),
            )
            expect((await api.part(app, 'dns', 3, digest)).status).toBe(404)

            // An unreadable part needs a platform repair, not a retry with other input.
            const at = and(
                eq(legacyFeatureHandoffParts.domain, 'dns'),
                eq(legacyFeatureHandoffParts.sequence, 1),
            )
            const [stored] = await db
                .select({ ciphertext: legacyFeatureHandoffParts.ciphertext })
                .from(legacyFeatureHandoffParts)
                .where(at)
            const ciphertext = stored!.ciphertext
            await db
                .update(legacyFeatureHandoffParts)
                .set({ ciphertext: ciphertext.map((byte) => byte ^ 0xff) })
                .where(at)
            expect(await api.part(app, 'dns', 1, digest)).toMatchObject({
                status: 503,
                body: { code: 'unavailable' },
            })
            await db.update(legacyFeatureHandoffParts).set({ ciphertext }).where(at)

            // Commit transfers exactly the exported digest and retires platform state once.
            expect(await api.commit(app, 'dns', otherDigest)).toMatchObject({
                status: 409,
                body: { code: 'conflict' },
            })
            expect(dns.state.retirements).toBe(0)
            const committed = { domain: 'dns', state: 'committed', digest }
            expect(await api.commit(app, 'dns', digest)).toEqual({ status: 200, body: committed })
            expect(await api.commit(app, 'dns', digest, 'commit-2')).toEqual({
                status: 200,
                body: committed,
            })
            // The refused commit above left its key unbound; the accepted one binds it.
            expect(await api.commit(app, 'dns', otherDigest, 'commit-1')).toMatchObject({
                status: 409,
                body: { code: 'idempotencyConflict' },
            })
            expect(dns.state).toMatchObject({ exports: 1, retirements: 1, records: [] })
            expect((await api.status(app, 'dns')).body).toEqual(committed)
            expect((await api.begin(app, 'dns', 'begin-3')).body).toEqual(committed)
            expect((await api.part(app, 'dns', 0, digest)).status).toBe(404)
            expect(await partCount('dns')).toBe(0)
            expect((await api.status(rival, 'dns')).status).toBe(409)

            // A platform version without the source still answers the recorded ownership.
            const unsourced = harness.handoffApi({})
            expect((await unsourced.begin(app, 'dns', 'begin-4')).body).toEqual(committed)
            expect((await unsourced.commit(app, 'dns', digest, 'commit-3')).body).toEqual(committed)
            expect(await unsourced.commit(app, 'dns', otherDigest, 'commit-4')).toMatchObject({
                status: 409,
                body: { code: 'conflict' },
            })
            expect((await unsourced.commit(rival, 'dns', digest)).status).toBe(409)
            expect(dns.state.retirements).toBe(1)

            // A source registered under the wrong domain is a platform fault.
            const misregistered = harness.handoffApi({ monitoring: dns.source })
            expect(await misregistered.status(app, 'monitoring')).toMatchObject({
                status: 503,
                body: { code: 'unavailable' },
            })

            // An update moves the authority to the new generation; ownership stays per installation.
            const next = { ...app, generation: 2 }
            expect(
                await control('register', next, {
                    leaseExpiresAt: leaseExpiresAt(),
                    capabilities: [],
                    providerProfiles: ['dns'],
                }),
            ).toBe(204)
            expect(await control('grants', next, { grants: [providerGrant('dns')] })).toBe(204)
            await activate(next)
            expect((await api.status(app, 'dns')).status).toBe(401)
            expect((await api.status(next, 'dns')).body).toEqual(committed)
            expect((await api.status(next, 'monitoring')).status).toBe(403)
            await db
                .update(appRuntimeGenerations)
                .set({ leaseExpiresAt: new Date(Date.now() - 1_000) })
                .where(eq(appRuntimeGenerations.installationId, next.installationId))
            expect((await api.status(next, 'dns')).status).toBe(401)
        } finally {
            await harness.release()
        }
    },
)

integrationTest(
    'expired authority, bounded keys and a missing source never complete a handoff',
    async () => {
        const harness = await createHarness(['load-balancer'], 82)
        const { db, install, activate, journalRows } = harness
        try {
            const balancer = featureSource('load-balancer', [{ pool: 'web' }])
            const api = harness.handoffApi({ 'load-balancer': balancer.source })
            const unsourced = harness.handoffApi({})
            const app = await install(
                'test.handoff-unsourced',
                ['load-balancer'],
                [providerGrant('load-balancer')],
            )
            await activate(app)
            const setLease = (expiresAt: Date) =>
                db
                    .update(appRuntimeGenerations)
                    .set({ leaseExpiresAt: expiresAt })
                    .where(eq(appRuntimeGenerations.installationId, app.installationId))

            // An export that outlives the caller's lease is rolled back and never answered. The
            // export holds until the deadline passed, so authorization surely ran before it.
            const exportEntered = Promise.withResolvers<'entered'>()
            const releaseExport = Promise.withResolvers<void>()
            const slow = harness.handoffApi({
                'load-balancer': {
                    ...balancer.source,
                    export: async (transaction, emit) => {
                        exportEntered.resolve('entered')
                        await releaseExport.promise
                        await balancer.source.export(transaction, emit)
                    },
                },
            })
            const leaseDeadline = Date.now() + 2_000
            await setLease(new Date(leaseDeadline))
            const expiring = slow.begin(app, 'load-balancer')
            try {
                expect(
                    await Promise.race([exportEntered.promise, expiring.then(() => 'replied')]),
                ).toBe('entered')
                await Bun.sleep(Math.max(0, leaseDeadline - Date.now()) + 50)
            } finally {
                releaseExport.resolve()
            }
            expect(await expiring).toMatchObject({ status: 401, body: { code: 'unauthorized' } })
            expect(balancer.state.exports).toBe(1)
            expect(await journalRows()).toEqual([])
            await setLease(new Date(Date.now() + 60_000))

            // Expired keys and the oldest beyond the per-installation bound are forgotten.
            const { requestKeyRetentionMs, requestKeysPerInstallation } = LEGACY_HANDOFF_LIMITS
            const storedKey = (key: string, createdAt: Date) => ({
                installationId: app.installationId,
                actor: 'service',
                operation: 'begin' as const,
                key,
                fingerprint: 'c'.repeat(64),
                createdAt,
            })
            await db
                .insert(legacyFeatureHandoffRequests)
                .values([
                    storedKey('expired', new Date(Date.now() - requestKeyRetentionMs - 60_000)),
                    ...Array.from({ length: requestKeysPerInstallation }, (_, index) =>
                        storedKey('kept-' + index, new Date(Date.now() - 3_600_000 + index)),
                    ),
                ])
            const keys = async () =>
                (
                    await db
                        .select({ key: legacyFeatureHandoffRequests.key })
                        .from(legacyFeatureHandoffRequests)
                        .where(eq(legacyFeatureHandoffRequests.installationId, app.installationId))
                ).map(({ key }) => key)

            const begun = await api.begin(app, 'load-balancer')
            const remaining = await keys()
            expect(remaining).toHaveLength(requestKeysPerInstallation)
            expect(remaining).toContain('begin-1')
            expect(remaining).not.toContain('expired')
            expect(remaining).not.toContain('kept-0')
            expect(remaining).toContain('kept-1')
            const { digest } = begun.body as { digest: string }
            expect((await unsourced.begin(app, 'load-balancer')).body).toEqual(begun.body)
            expect(await unsourced.commit(app, 'load-balancer', digest)).toMatchObject({
                status: 503,
                body: { code: 'unavailable' },
            })
            expect(balancer.state.retirements).toBe(0)
            expect((await api.commit(app, 'load-balancer', digest)).body).toEqual({
                domain: 'load-balancer',
                state: 'committed',
                digest,
            })
            expect(balancer.state.retirements).toBe(1)
        } finally {
            await harness.release()
        }
    },
)

integrationTest(
    'app removal returns uncommitted domains to platform and keeps committed ownership',
    async () => {
        const harness = await createHarness(['load-balancer', 'oidc'], 83)
        const { db, install, activate, control, journalRows, partCount } = harness
        const { withPlatformOwnedLegacyFeature } =
            await import('@/server/LegacyHandoff/ownership.server.ts')
        try {
            const balancer = featureSource('load-balancer', [{ pool: 'web' }, { pool: 'api' }])
            const oidcRecords: AppRuntimeJsonValue[] = [{ issuer: 'https://id.example.test' }]
            const oidc = featureSource('oidc', oidcRecords)
            const api = harness.handoffApi({
                'load-balancer': balancer.source,
                oidc: oidc.source,
            })
            const leaving = await install(
                'test.handoff-leaving',
                ['load-balancer', 'oidc'],
                [providerGrant('load-balancer'), providerGrant('oidc')],
            )
            const staying = await install('test.handoff-staying', ['oidc'], [providerGrant('oidc')])
            await activate(leaving)
            await activate(staying)

            const balancerExport = await api.begin(leaving, 'load-balancer', 'begin-lb')
            const { digest } = balancerExport.body as { digest: string }
            expect((await api.commit(leaving, 'load-balancer', digest)).status).toBe(200)
            expect((await api.begin(leaving, 'oidc', 'begin-oidc')).body).toMatchObject({
                state: 'exported',
                partCount: 1,
            })
            const platformWrite = () =>
                db.transaction((transaction) =>
                    withPlatformOwnedLegacyFeature(transaction, 'oidc', () =>
                        Promise.resolve('platform wrote'),
                    ),
                )
            expect(await platformWrite()).toEqual({ owned: false })

            // Removing an installation without handoffs leaves other installations' journals alone.
            expect(await control('removable', staying)).toBe(204)
            expect(await journalRows()).toEqual([
                {
                    domain: 'load-balancer',
                    installationId: leaving.installationId,
                    state: 'committed',
                },
                { domain: 'oidc', installationId: leaving.installationId, state: 'exported' },
            ])

            // The removal checks abort the import, so platform resumes its untouched state. The app
            // manager runs the check before and again after it stopped the app's broker; an app
            // that begins again in between is released by the second check.
            const committedOnly = [
                {
                    domain: 'load-balancer',
                    installationId: leaving.installationId,
                    state: 'committed' as const,
                },
            ]
            expect(await control('removable', leaving)).toBe(204)
            expect(await journalRows()).toEqual(committedOnly)
            expect(await platformWrite()).toEqual({ owned: true, value: 'platform wrote' })
            expect((await api.begin(leaving, 'oidc', 'begin-oidc')).body).toMatchObject({
                state: 'exported',
            })
            expect(await control('removable', leaving)).toBe(204)
            expect(await journalRows()).toEqual(committedOnly)
            expect(await partCount('oidc')).toBe(0)
            expect(oidc.state).toMatchObject({ exports: 2, retirements: 0, records: oidcRecords })
            expect(balancer.state.retirements).toBe(1)
            expect(await platformWrite()).toEqual({ owned: true, value: 'platform wrote' })

            // Another official app can now take over the released domain.
            expect((await api.begin(staying, 'oidc')).body).toMatchObject({ state: 'exported' })
            expect(oidc.state.exports).toBe(3)
            expect((await api.status(staying, 'load-balancer')).status).toBe(403)
            expect(await control('removable', staying)).toBe(204)
            expect(await partCount('oidc')).toBe(0)
            expect(await journalRows()).toEqual(committedOnly)

            // Purging the removed app's data drops its request keys; its ownership stays recorded.
            const requestKeys = () =>
                db
                    .select({ key: legacyFeatureHandoffRequests.key })
                    .from(legacyFeatureHandoffRequests)
                    .where(eq(legacyFeatureHandoffRequests.installationId, leaving.installationId))
            expect(await requestKeys()).not.toEqual([])
            expect(await control('revoke', leaving)).toBe(204)
            expect(await control('purge-data', leaving)).toBe(204)
            expect(await requestKeys()).toEqual([])
            expect(await journalRows()).toEqual(committedOnly)
        } finally {
            await harness.release()
        }
    },
)

integrationTest(
    'a begin still in flight when the broker exits leaves no export after the removal check',
    async () => {
        const harness = await createHarness(['load-balancer'], 84)
        const { db, install, activate, journalRows } = harness
        try {
            const balancer = featureSource('load-balancer', [{ pool: 'web' }])
            const app = await install(
                'test.handoff-in-flight',
                ['load-balancer'],
                [providerGrant('load-balancer')],
            )
            await activate(app)
            const { server, settled, beginOverSocket } = harness.listen({
                'load-balancer': balancer.source,
            })
            const checkHeld = Promise.withResolvers<number>()
            const releaseCheck = Promise.withResolvers<void>()
            let check: Promise<unknown> | undefined
            try {
                // The second removal check holds the installation row after the broker stopped.
                check = db.transaction(async (transaction) => {
                    const [session] = await transaction.execute<{ pid: number }>(
                        sql`select pg_backend_pid() as pid`,
                    )
                    await transaction
                        .select({ id: appRuntimeInstallations.id })
                        .from(appRuntimeInstallations)
                        .where(eq(appRuntimeInstallations.id, app.installationId))
                        .for('update')
                    checkHeld.resolve(Number(session!.pid))
                    await releaseCheck.promise
                })
                // A failing lock setup rejects the check before it is held; let it end the test.
                const checkFailed = check.then(() => new Promise<never>(() => undefined))
                // The race or the cleanup below reports the rejection.
                checkFailed.catch(() => undefined)
                const checkPid = await Promise.race([checkHeld.promise, checkFailed])
                const socket = await beginOverSocket(app, 'load-balancer', 'begin-1')
                // Wait until the forwarded begin's session is blocked by exactly this check.
                let blocked = false
                for (let attempt = 0; attempt < 150 && !blocked; attempt += 1) {
                    // oxlint-disable-next-line no-await-in-loop -- Poll the lock graph until the begin waits.
                    const [state] = await db.execute<{ blocked: boolean }>(sql`
                        select exists (
                            select from pg_stat_activity
                            where datname = current_database() and pid <> ${checkPid}
                                and ${checkPid}::int = any(pg_blocking_pids(pid))
                        ) as blocked`)
                    blocked = state?.blocked === true
                    // oxlint-disable-next-line no-await-in-loop -- See above.
                    if (!blocked) await Bun.sleep(20)
                }
                if (!blocked) throw new Error('The begin never waited on the removal check')
                expect(settled).toHaveLength(1)
                // The broker exits, then the check commits and the begin runs its export.
                socket.end()
                await Bun.sleep(100)
                releaseCheck.resolve()
                await check
                await Promise.all(settled)
                expect(settled).toHaveLength(1)
                expect(balancer.state.exports).toBe(1)
                expect(await journalRows()).toEqual([])
            } finally {
                releaseCheck.resolve()
                await check?.catch(() => undefined)
                await server.stop(true)
            }
        } finally {
            await harness.release()
        }
    },
)
