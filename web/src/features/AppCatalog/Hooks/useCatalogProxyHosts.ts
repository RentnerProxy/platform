import { useQuery } from '@tanstack/react-query'
import type { CatalogProxyHost } from '@/lib/AppCatalog/grantApproval.ts'
import { getAppCatalogProxyHostsHandler } from '../middleware.ts'

/** The proxy hosts an Owner can approve for apps, loaded only while `enabled`. */
export default function useCatalogProxyHosts(enabled: boolean) {
    const query = useQuery({
        queryKey: ['app-catalog', 'proxy-hosts'],
        queryFn: async ({ signal }): Promise<CatalogProxyHost[]> => {
            const hosts = await getAppCatalogProxyHostsHandler({ signal })
            if (hosts === 'forbidden') throw new Error('forbidden')
            return hosts
        },
        enabled,
        retry: false,
        staleTime: 30_000,
    })
    return {
        hosts: query.data,
        hostnames: new Map((query.data ?? []).map((host) => [host.id, host.hostname])),
        isLoading: enabled && query.isPending,
        isError: query.isError,
    }
}
