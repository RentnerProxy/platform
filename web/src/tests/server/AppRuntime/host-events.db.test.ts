import { randomUUID } from 'node:crypto'
import { expect, test } from 'bun:test'
import { replayAppRuntimeEventsInTransaction } from '@/server/AppRuntime/events.server.ts'
import { recordProxyHostEventsInTransaction } from '@/server/AppRuntime/host-events.server.ts'
import { getAuthDatabase } from '@/server/Auth/Core/database.server.ts'
import { getDatabaseUrl } from '@/server/env.server.ts'
import {
    allHostsGrant,
    grantEventApp,
    hostEventsOf,
    installEventApp,
    monitorHosts,
    probeHosts,
    readHosts,
    removeEventApps,
} from '@/tests/Helpers/appHostEvents.ts'

function event(capabilityId: string, type: string, resourceId: string) {
    return { type, capabilityId, scope: 'proxyHosts', resourceId }
}

function grant(capability: typeof probeHosts | typeof monitorHosts, resourceId: string) {
    return { capability, resourceId, allowService: true }
}

const integrationTest =
    process.env.RENTNERPROXY_DATABASE_INTEGRATION === '1' && getDatabaseUrl() !== null
        ? test
        : test.skip

integrationTest(
    'records one event per change and app, and leaves out the app that made the change',
    async () => {
        const [host, other] = [randomUUID(), randomUUID()]
        const acting = await installEventApp([allHostsGrant(readHosts.id)])
        const both = await installEventApp([
            allHostsGrant(probeHosts.id),
            { capability: readHosts, resourceId: host, allowService: true },
        ])
        const probing = await installEventApp([
            { capability: probeHosts, resourceId: other, allowService: true },
        ])
        try {
            await getAuthDatabase().transaction((transaction) =>
                recordProxyHostEventsInTransaction(
                    transaction,
                    [
                        { proxyHostId: host, type: 'proxyHostCreated' },
                        { proxyHostId: other, type: 'proxyHostDisabled' },
                    ],
                    acting.installationId,
                ),
            )
            expect(await hostEventsOf(acting.installationId)).toEqual([])
            // Read wins over probe, and each change is recorded once per app.
            expect(await hostEventsOf(both.installationId)).toEqual([
                event(readHosts.id, 'proxyHostCreated', host),
                event(probeHosts.id, 'proxyHostDisabled', other),
            ])
            expect(await hostEventsOf(probing.installationId)).toEqual([
                event(probeHosts.id, 'proxyHostDisabled', other),
            ])
            // A rolled back change leaves no event.
            await getAuthDatabase()
                .transaction(async (transaction) => {
                    await recordProxyHostEventsInTransaction(transaction, [
                        { proxyHostId: other, type: 'proxyHostRemoved' },
                    ])
                    throw new Error('rollback')
                })
                .catch(() => undefined)
            expect(await hostEventsOf(probing.installationId)).toHaveLength(1)
        } finally {
            await removeEventApps([acting, both, probing])
        }
    },
)

integrationTest(
    'a remaining covering grant still receives events recorded under a revoked one',
    async () => {
        const [host, other] = [randomUUID(), randomUUID()]
        const app = await installEventApp([grant(probeHosts, host), grant(monitorHosts, host)])
        // Event cursors are encrypted with the app encryption key.
        const encryptionKey = process.env.APP_ENCRYPTION_KEY
        process.env.APP_ENCRYPTION_KEY = Buffer.from(new Uint8Array(32).fill(9)).toString('base64')
        try {
            await getAuthDatabase().transaction((transaction) =>
                recordProxyHostEventsInTransaction(transaction, [
                    { proxyHostId: host, type: 'proxyHostUpdated' },
                    { proxyHostId: other, type: 'proxyHostUpdated' },
                ]),
            )
            // The monitoring-class probe records it, ahead of the older probe.
            expect(await hostEventsOf(app.installationId)).toEqual([
                event(monitorHosts.id, 'proxyHostUpdated', host),
            ])
            // Revoking that grant keeps the change for the probe grant that still covers the host,
            // and a grant for another host never receives it.
            await grantEventApp(app, [grant(probeHosts, host)])
            const replay = () =>
                getAuthDatabase().transaction((transaction) =>
                    replayAppRuntimeEventsInTransaction(transaction, { identity: app }),
                )
            expect(
                (await replay()).events.map(({ type, resourceId }) => [type, resourceId]),
            ).toEqual([['proxyHostUpdated', host]])
            await grantEventApp(app, [grant(probeHosts, other)])
            expect((await replay()).events).toEqual([])
        } finally {
            if (encryptionKey === undefined) delete process.env.APP_ENCRYPTION_KEY
            else process.env.APP_ENCRYPTION_KEY = encryptionKey
            await removeEventApps([app])
        }
    },
)
