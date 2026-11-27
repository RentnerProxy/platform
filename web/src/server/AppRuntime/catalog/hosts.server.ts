import '@tanstack/react-start/server-only'

import { asc, sql } from 'drizzle-orm'
import { hostDomains, proxyHosts } from '@/db/schema.ts'
import type { CatalogProxyHost } from '@/lib/AppCatalog/grantApproval.ts'
import { getAuthDatabase } from '@/server/Auth/Core/database.server.ts'

/** The most proxy hosts the approval dialog lists; it filters them locally. */
export const CATALOG_PROXY_HOST_LIMIT = 1_000

/**
 * The platform proxy hosts an Owner can approve for an app, named by their first domain. Only
 * the Owner-guarded catalog server function calls this.
 */
export async function listCatalogProxyHosts(): Promise<CatalogProxyHost[]> {
    const hostname = sql<string>`(select d.domain from ${hostDomains} d
        where d.proxy_host_id = "proxy_hosts"."id" order by d.domain limit 1)`
    return getAuthDatabase()
        .select({ id: proxyHosts.id, hostname, enabled: proxyHosts.enabled })
        .from(proxyHosts)
        .where(
            sql`exists (select 1 from ${hostDomains} d where d.proxy_host_id = "proxy_hosts"."id")`,
        )
        .orderBy(asc(hostname), asc(proxyHosts.id))
        .limit(CATALOG_PROXY_HOST_LIMIT)
}
