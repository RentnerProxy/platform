import { randomUUID } from 'node:crypto'
import { expect, test } from 'bun:test'
import { inArray } from 'drizzle-orm'
import { hostDomains, proxyHosts } from '@/db/schema.ts'
import { listCatalogProxyHosts } from '@/server/AppRuntime/catalog/hosts.server.ts'
import { getAuthDatabase } from '@/server/Auth/Core/database.server.ts'
import { getDatabaseUrl } from '@/server/env.server.ts'

const integrationTest =
    process.env.RENTNERPROXY_DATABASE_INTEGRATION === '1' && getDatabaseUrl() !== null
        ? test
        : test.skip

function host(id: string, enabled: boolean) {
    return {
        id,
        forwardScheme: 'http' as const,
        forwardHost: '172.22.0.5',
        forwardPort: 8080,
        enabled,
    }
}

integrationTest('lists the proxy hosts an Owner can approve by their first domain', async () => {
    const [named, disabled, unnamed] = [randomUUID(), randomUUID(), randomUUID()]
    const ids: string[] = [named, disabled, unnamed]
    const suffix = named.slice(0, 8)
    await getAuthDatabase().transaction(async (transaction) => {
        await transaction
            .insert(proxyHosts)
            .values([host(named, true), host(disabled, false), host(unnamed, true)])
        await transaction.insert(hostDomains).values([
            { proxyHostId: named, domain: `zz-${suffix}.example.com` },
            { proxyHostId: named, domain: `aa-${suffix}.example.com` },
            { proxyHostId: disabled, domain: `mm-${suffix}.example.com` },
        ])
    })
    try {
        const listed = (await listCatalogProxyHosts()).filter((row) => ids.includes(row.id))
        // A host without a domain has nothing to show and is not offered.
        expect(listed).toEqual([
            { id: named, hostname: `aa-${suffix}.example.com`, enabled: true },
            { id: disabled, hostname: `mm-${suffix}.example.com`, enabled: false },
        ])
    } finally {
        await getAuthDatabase().delete(proxyHosts).where(inArray(proxyHosts.id, ids))
    }
})
