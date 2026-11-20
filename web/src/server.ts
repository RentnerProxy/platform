import { createStartHandler, defaultStreamHandler } from '@tanstack/react-start/server'
import { createServerEntry } from '@tanstack/react-start/server-entry'

import { APP_UI_PREFIX } from '@/lib/AppUi/paths.ts'
import { withRequestAbortHandling } from '@/server/request-abort.server.ts'
import {
    startRestoreMaintenanceWatcher,
    withRestoreMaintenanceFence,
} from '@/server/Backups/restore-maintenance.server.ts'

const serverEntry = createServerEntry({
    fetch: createStartHandler(defaultStreamHandler),
})

startRestoreMaintenanceWatcher()

const fetch = withRequestAbortHandling(serverEntry.fetch)
const fencedFetch: typeof fetch = (request, options) =>
    withRestoreMaintenanceFence(request, async () => {
        const url = new URL(request.url)
        if (url.pathname.startsWith(APP_UI_PREFIX)) {
            const { serveAppUiHttp } = await import('@/server/AppRuntime/ui/http.server.ts')
            return serveAppUiHttp(request, url)
        }
        return fetch(request, options)
    })

export default {
    // Abort handling rewrites the Request, so Start must create its error context afterwards.
    fetch: fencedFetch,
}
