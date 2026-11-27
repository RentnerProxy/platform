import { randomUUID } from 'node:crypto'
import { expect, test } from 'bun:test'
import { inArray, sql } from 'drizzle-orm'
import {
    appRuntimeGenerations,
    appRuntimeGrants,
    appRuntimeInstallations,
    hostDomains,
    proxyHosts,
} from '@/db/schema.ts'
import { listAppProxyHosts } from '@/server/AppRuntime/hosts.server.ts'
import {
    activateAppRuntimeGenerationInTransaction,
    registerAppRuntimeGenerationInTransaction,
    replaceAppRuntimeGrantsInTransaction,
} from '@/server/AppRuntime/lifecycle.server.ts'
import type {
    AppRuntimeGrant,
    AppRuntimeIdentity,
} from '@/server/AppRuntime/Types/authority.types.ts'
import { getAuthDatabase } from '@/server/Auth/Core/database.server.ts'
import { getDatabaseUrl } from '@/server/env.server.ts'

const integrationTest =
    process.env.RENTNERPROXY_DATABASE_INTEGRATION === '1' && getDatabaseUrl() !== null
        ? test
        : test.skip
const readHosts = { id: 'proxy.hosts.read.v1', scope: 'proxyHosts' }
const probeHosts = { id: 'diagnostics.upstream.probe.v1', scope: 'proxyHosts' }
const allHosts = (id: string): AppRuntimeGrant => ({
    capability: { id, scope: 'allProxyHosts' },
    resourceId: 'all',
    allowService: true,
})

const pool = {
    policy: 'first',
    members: [
        { host: '172.22.0.5', port: 8080 },
        { host: 'backup.internal', port: 9080 },
    ],
    failover: { passive: { failDurationSeconds: 30, maxFails: 3 } },
}

async function createHost(id: string, domains: string[], pooled = false) {
    await getAuthDatabase().transaction(async (transaction) => {
        await transaction.insert(proxyHosts).values({
            id,
            forwardScheme: 'http',
            forwardHost: '172.22.0.5',
            forwardPort: 8080,
            enabled: !pooled,
            // The driver binds an object as a JSON string, so cast it as the platform does.
            ...(pooled && { upstreamPool: sql`${JSON.stringify(pool)}::text::jsonb` }),
        })
        await transaction
            .insert(hostDomains)
            .values(domains.map((domain) => ({ proxyHostId: id, domain })))
    })
}

async function grant(identity: AppRuntimeIdentity, grants: readonly AppRuntimeGrant[]) {
    await getAuthDatabase().transaction((transaction) =>
        replaceAppRuntimeGrantsInTransaction(transaction, identity, grants),
    )
}

integrationTest(
    'an approval for all proxy hosts lists every host with its probe view, also later hosts',
    async () => {
        const db = getAuthDatabase()
        const installationId = randomUUID()
        const identity = { appId: 'fixture.monitor', installationId, generation: 1, uid: 59_976 }
        const credentials = { identity }
        const [early, late, pooled] = [randomUUID(), randomUUID(), randomUUID()]
        const ids: string[] = [early, late, pooled]
        const suffix = installationId.slice(0, 8)
        await createHost(early, [`b-${suffix}.example.test`, `a-${suffix}.example.test`])
        const leaseExpiresAt = new Date(Date.now() + 60_000)
        await db.transaction(async (transaction) => {
            await registerAppRuntimeGenerationInTransaction(transaction, {
                identity,
                leaseExpiresAt,
                capabilities: [readHosts, probeHosts],
            })
            await activateAppRuntimeGenerationInTransaction(transaction, identity, leaseExpiresAt)
        })
        try {
            await grant(identity, [allHosts(readHosts.id), allHosts(probeHosts.id)])
            // Hosts created after the approval are listed too.
            await createHost(late, [`late-${suffix}.example.test`])
            await createHost(pooled, [`pool-${suffix}.example.test`], true)
            const listed = async () =>
                (await listAppProxyHosts(credentials, { limit: 100 })).hosts.filter((host) =>
                    ids.includes(host.id),
                )
            const hosts = await listed()
            expect(hosts.map((host) => host.id)).toEqual([early, late, pooled].toSorted())
            const byId = new Map(hosts.map((host) => [host.id, host]))
            expect(byId.get(early)).toEqual({
                id: early,
                hostname: `a-${suffix}.example.test`,
                revision: expect.stringMatching(/^[a-f0-9]{64}$/u),
                enabled: true,
                domains: [`a-${suffix}.example.test`, `b-${suffix}.example.test`],
                upstream: {
                    scheme: 'http',
                    targets: [{ address: '172.22.0.5', port: 8080 }],
                    pool: null,
                },
                probeRevision: expect.stringMatching(/^[a-f0-9]{64}$/u),
            })
            // A pool lists its members and failover settings, never certificates or policies.
            expect(byId.get(pooled)).toMatchObject({
                enabled: false,
                upstream: {
                    scheme: 'http',
                    targets: [
                        { address: '172.22.0.5', port: 8080 },
                        { address: 'backup.internal', port: 9080 },
                    ],
                    pool: {
                        policy: 'first',
                        failover: { passive: { failDurationSeconds: 30, maxFails: 3 } },
                    },
                },
            })
            expect(Object.keys(byId.get(pooled)!).toSorted()).toEqual([
                'domains',
                'enabled',
                'hostname',
                'id',
                'probeRevision',
                'revision',
                'upstream',
            ])

            // Without it, the app sees only the hosts granted to it.
            await grant(identity, [{ capability: readHosts, resourceId: late, allowService: true }])
            expect((await listed()).map((host) => host.id)).toEqual([late])
            await grant(identity, [allHosts(probeHosts.id)])
            expect(await listed()).toEqual([])

            // The scope never names a host, and never covers managing hosts.
            await expect(
                grant(identity, [{ ...allHosts(readHosts.id), resourceId: early }]),
            ).rejects.toMatchObject({ code: 'invalid_input' })
            await expect(
                grant(identity, [allHosts('proxy.hosts.manage-owned.v1')]),
            ).rejects.toMatchObject({ code: 'invalid_input' })
        } finally {
            await db.transaction(async (transaction) => {
                await transaction.delete(proxyHosts).where(inArray(proxyHosts.id, ids))
                await transaction
                    .delete(appRuntimeGrants)
                    .where(inArray(appRuntimeGrants.installationId, [installationId]))
                await transaction
                    .delete(appRuntimeGenerations)
                    .where(inArray(appRuntimeGenerations.installationId, [installationId]))
                await transaction
                    .delete(appRuntimeInstallations)
                    .where(inArray(appRuntimeInstallations.id, [installationId]))
            })
        }
    },
)
