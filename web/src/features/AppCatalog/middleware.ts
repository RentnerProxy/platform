import { createServerFn, createServerOnlyFn } from '@tanstack/react-start'
import { getRequest, setResponseHeader } from '@tanstack/react-start/server'
import type { CatalogSnapshot } from '@/lib/AppCatalog/contract.ts'
import { unavailableCatalog } from '@/lib/AppCatalog/installProgress.ts'
import { requireOwnerSessionService } from '@/server/Auth/Access/authorization.service.ts'
import { handleCatalogInstall } from '@/server/AppRuntime/catalog/http.server.ts'
import { nativeAppCatalog } from '@/server/AppRuntime/catalog/transport.server.ts'
import { appUiEnabled, appUiSignal } from '@/server/AppRuntime/ui/transport.server.ts'

export const getAppCatalogHandler = createServerFn({ method: 'GET' }).handler(
    async (): Promise<CatalogSnapshot> => {
        setResponseHeader('Cache-Control', 'private, no-store')
        try {
            await requireOwnerSessionService()
            if (appUiEnabled()) return await nativeAppCatalog(appUiSignal(getRequest()))
        } catch {
            return unavailableCatalog
        }
        return unavailableCatalog
    },
)

export const installAppCatalogHandler = createServerOnlyFn(handleCatalogInstall)
