import { createServerFn, createServerOnlyFn } from '@tanstack/react-start'
import { getRequest, setResponseHeader } from '@tanstack/react-start/server'
import type { CatalogSnapshot } from '@/lib/AppCatalog/contract.ts'
import type { CatalogProxyHost } from '@/lib/AppCatalog/grantApproval.ts'
import { requireOwnerSessionService } from '@/server/Auth/Access/authorization.service.ts'
import { listCatalogProxyHosts } from '@/server/AppRuntime/catalog/hosts.server.ts'
import {
    handleCatalogInstall,
    handleCatalogLifecycle,
} from '@/server/AppRuntime/catalog/http.server.ts'
import { nativeAppCatalog } from '@/server/AppRuntime/catalog/transport.server.ts'
import { appUiEnabled, appUiSignal } from '@/server/AppRuntime/ui/transport.server.ts'

export const getAppCatalogHandler = createServerFn({ method: 'GET' }).handler(
    async (): Promise<CatalogSnapshot | 'forbidden' | null> => {
        setResponseHeader('Cache-Control', 'private, no-store')
        try {
            await requireOwnerSessionService()
        } catch {
            return 'forbidden'
        }
        try {
            if (appUiEnabled()) return await nativeAppCatalog(appUiSignal(getRequest()))
        } catch {
            return null
        }
        return null
    },
)

/** The proxy hosts an Owner can approve for an app that requests access to selected hosts. */
export const getAppCatalogProxyHostsHandler = createServerFn({ method: 'GET' }).handler(
    async (): Promise<CatalogProxyHost[] | 'forbidden'> => {
        setResponseHeader('Cache-Control', 'private, no-store')
        try {
            await requireOwnerSessionService()
        } catch {
            return 'forbidden'
        }
        return listCatalogProxyHosts()
    },
)

export const installAppCatalogHandler = createServerOnlyFn(handleCatalogInstall)
export const manageAppCatalogHandler = createServerOnlyFn(handleCatalogLifecycle)
