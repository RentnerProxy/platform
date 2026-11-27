import { randomUUID } from 'node:crypto'
import { expect, test } from 'bun:test'
import { and, eq, inArray } from 'drizzle-orm'
import { appRuntimeGenerations, hostDomains, proxyHosts } from '@/db/schema.ts'
import type {
    DomainDiagnosticsControllerInput,
    DomainDiagnosticsResult,
} from '@/lib/RuntimeDiagnostics/Types/domain-diagnostics.types.ts'
import { listAppProxyHosts } from '@/server/AppRuntime/hosts.server.ts'
import type { AppRuntimeIdentity } from '@/server/AppRuntime/Types/authority.types.ts'
import { createAppUpstreamProbes } from '@/server/AppRuntime/upstream-probes.server.ts'
import { getAuthDatabase } from '@/server/Auth/Core/database.server.ts'
import type { DomainDiagnosticsProbeOptions } from '@/server/Controller/Types/domain-diagnostics.types.ts'
import { getDatabaseUrl } from '@/server/env.server.ts'
import { DomainDiagnosticsError } from '@/server/RuntimeDiagnostics/domain-diagnostics.errors.ts'
import {
    allHostsGrant,
    installEventApp,
    monitorHosts,
    readHosts,
    removeEventApps,
} from '@/tests/Helpers/appHostEvents.ts'

const integrationTest =
    process.env.RENTNERPROXY_DATABASE_INTEGRATION === '1' && getDatabaseUrl() !== null
        ? test
        : test.skip

const stage = (status: string, code: string, durationMs = 0, httpStatus: number | null = null) => ({
    status,
    code,
    durationMs,
    addresses: [],
    httpStatus,
})

/** The upstream-only result the core returns for a reachable plain HTTP upstream. */
function reachable(input: DomainDiagnosticsControllerInput): DomainDiagnosticsResult {
    return {
        ...input,
        activeRevision: input.expectedRevision,
        checkedAt: new Date().toISOString(),
        observationPoint: 'appliance',
        publicReachability: 'not_checked',
        stages: {
            configuration: stage('passed', 'configuration_active', 1),
            dns: stage('unknown', 'skipped'),
            upstream: stage('passed', 'upstream_responded', 42, 204),
            tls: stage('not_applicable', 'http_upstream'),
        },
    } as DomainDiagnosticsResult
}

type Call = {
    input: DomainDiagnosticsControllerInput
    options: DomainDiagnosticsProbeOptions | undefined
}

async function createHost(id: string, domains: string[], enabled = true) {
    await getAuthDatabase().transaction(async (transaction) => {
        await transaction.insert(proxyHosts).values({
            id,
            forwardScheme: 'http',
            forwardHost: '172.22.0.5',
            forwardPort: 8080,
            enabled,
        })
        await transaction
            .insert(hostDomains)
            .values(domains.map((domain) => ({ proxyHostId: id, domain })))
    })
}

async function removeHosts(ids: readonly string[]) {
    await getAuthDatabase().delete(proxyHosts).where(inArray(proxyHosts.id, ids))
}

const credentials = (identity: AppRuntimeIdentity) => ({ identity })

integrationTest(
    'a batch probes covered hosts through the app admission and names every other outcome',
    async () => {
        const healthy = randomUUID()
        const disabled = randomUUID()
        const other = randomUUID()
        const busy = randomUUID()
        const limited = randomUUID()
        const failing = randomUUID()
        const removed = randomUUID()
        const ids = [healthy, disabled, other, busy, limited, failing]
        const suffix = healthy.slice(0, 8)
        const domain = (name: string) => `${name}-${suffix}.example.test`
        const apps: AppRuntimeIdentity[] = []
        try {
            await Promise.all([
                createHost(healthy, [domain('a'), domain('b')]),
                createHost(disabled, [domain('off')], false),
                createHost(other, [domain('other')]),
                createHost(busy, [domain('busy')]),
                createHost(limited, [domain('limited')]),
                createHost(failing, [domain('failing')]),
            ])
            const app = await installEventApp([
                allHostsGrant(monitorHosts.id),
                allHostsGrant(readHosts.id),
            ])
            apps.push(app)
            const calls: Call[] = []
            const probe = createAppUpstreamProbes(async (input, _signal, options) => {
                calls.push({ input, options })
                if (input.hostId === busy) throw new DomainDiagnosticsError('busy')
                if (input.hostId === limited) throw new DomainDiagnosticsError('rate_limited')
                if (input.hostId === failing)
                    throw new DomainDiagnosticsError('runtime_unavailable')
                return reachable(input)
            })
            const target = (hostId: string, name: string) => ({ hostId, domain: domain(name) })
            const { results } = await probe(credentials(app), {
                probes: [
                    [healthy, 'b'],
                    [disabled, 'off'],
                    [other, 'a'],
                    [removed, 'gone'],
                    [busy, 'busy'],
                    [limited, 'limited'],
                    [failing, 'failing'],
                ].map(([hostId, name]) => ({
                    hostId: hostId!,
                    domain: domain(name!),
                    timeoutMs: 3_000,
                })),
            })
            const listed = await listAppProxyHosts(credentials(app), { limit: 100 })
            const probeRevision = listed.hosts.find((host) => host.id === healthy)?.probeRevision
            expect(probeRevision).toMatch(/^[a-f0-9]{64}$/u)
            const expected: unknown[] = [
                {
                    outcome: 'probed',
                    ...target(healthy, 'b'),
                    probeRevision,
                    durationMs: 42,
                    httpStatus: 204,
                    failure: null,
                },
                { outcome: 'hostDisabled', ...target(disabled, 'off') },
                { outcome: 'domainNotFound', ...target(other, 'a') },
                { outcome: 'hostRemoved', ...target(removed, 'gone') },
                { outcome: 'busy', ...target(busy, 'busy') },
                { outcome: 'rateLimited', ...target(limited, 'limited') },
                { outcome: 'unavailable', ...target(failing, 'failing') },
            ]
            expect(results as unknown[]).toEqual(expected)
            // Only runnable probes reach the core, each through the chosen domain and the
            // admission of this installation.
            expect(calls.map(({ input }) => [input.hostId, input.domain])).toEqual([
                [healthy, domain('b')],
                [busy, domain('busy')],
                [limited, domain('limited')],
                [failing, domain('failing')],
            ])
            for (const { input, options } of calls) {
                expect(input.hostType).toBe('proxy')
                expect(input.expectedRevision).toMatch(/^sha256:[a-f0-9]{64}$/u)
                expect(options).toEqual({
                    upstreamOnly: true,
                    timeoutMs: 3_000,
                    installationId: app.installationId,
                })
            }
        } finally {
            await removeHosts(ids)
            await removeEventApps(apps)
        }
    },
)

integrationTest(
    'a per-host grant covers only its hosts, and a change during the probe discards the result',
    async () => {
        const [changed, disabledLater, uncovered] = [randomUUID(), randomUUID(), randomUUID()]
        const ids = [changed, disabledLater, uncovered]
        const suffix = changed.slice(0, 8)
        const domain = (name: string) => `${name}-${suffix}.example.test`
        const apps: AppRuntimeIdentity[] = []
        try {
            await createHost(changed, [domain('changed')])
            await createHost(disabledLater, [domain('later')])
            await createHost(uncovered, [domain('uncovered')])
            const app = await installEventApp(
                [changed, disabledLater].map((resourceId) => ({
                    capability: monitorHosts,
                    resourceId,
                    allowService: true,
                })),
            )
            apps.push(app)
            const probed: string[] = []
            const probe = createAppUpstreamProbes(async (input) => {
                probed.push(input.hostId)
                // The host changes while its probe runs, as an edit or toggle would.
                await getAuthDatabase()
                    .update(proxyHosts)
                    .set(input.hostId === changed ? { forwardPort: 9090 } : { enabled: false })
                    .where(eq(proxyHosts.id, input.hostId))
                return reachable(input)
            })
            const probeOf = (hostId: string, name: string, timeoutMs = 1_000) => ({
                hostId,
                domain: domain(name),
                timeoutMs,
            })
            const { results } = await probe(credentials(app), {
                probes: [
                    probeOf(changed, 'changed'),
                    probeOf(disabledLater, 'later'),
                    probeOf(uncovered, 'uncovered'),
                ],
            })
            const expected: unknown[] = [
                { outcome: 'configurationChanged', hostId: changed, domain: domain('changed') },
                { outcome: 'hostDisabled', hostId: disabledLater, domain: domain('later') },
                { outcome: 'scopeDenied', hostId: uncovered, domain: domain('uncovered') },
            ]
            expect(results as unknown[]).toEqual(expected)
            expect(probed.toSorted()).toEqual([changed, disabledLater].toSorted())

            // A batch names each host once, with a deadline the request can still honor.
            await Promise.all(
                [
                    [probeOf(changed, 'changed'), probeOf(changed, 'changed')],
                    [probeOf(changed, 'changed', 8_001)],
                    [probeOf(changed, 'changed', 999)],
                ].map((probes) =>
                    expect(probe(credentials(app), { probes })).rejects.toMatchObject({
                        code: 'invalid_input',
                    }),
                ),
            )
        } finally {
            await removeHosts(ids)
            await removeEventApps(apps)
        }
    },
)

integrationTest('authority that expires while the probes run reports no result', async () => {
    const host = randomUUID()
    const domain = `expiring-${host.slice(0, 8)}.example.test`
    const apps: AppRuntimeIdentity[] = []
    try {
        await createHost(host, [domain])
        const app = await installEventApp([allHostsGrant(monitorHosts.id)])
        apps.push(app)
        const probe = createAppUpstreamProbes(async (input) => {
            // The generation's lease runs out while the core probes the upstream.
            await getAuthDatabase()
                .update(appRuntimeGenerations)
                .set({ leaseExpiresAt: new Date(Date.now() - 1_000) })
                .where(
                    and(
                        eq(appRuntimeGenerations.installationId, app.installationId),
                        eq(appRuntimeGenerations.generation, app.generation),
                    ),
                )
            return reachable(input)
        })
        await expect(
            probe(credentials(app), { probes: [{ hostId: host, domain, timeoutMs: 1_000 }] }),
        ).rejects.toMatchObject({ code: 'unauthorized' })
    } finally {
        await removeHosts([host])
        await removeEventApps(apps)
    }
})
