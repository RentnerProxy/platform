import { createServerFn } from '@tanstack/react-start'
import { getRequest, setResponseHeader } from '@tanstack/react-start/server'

import { PERMISSIONS } from '@/config/permissions.config.ts'
import { APP_VERSION } from '@/lib/ApplicationVersion/version.ts'
import { appUiSignal } from '@/server/AppRuntime/ui/transport.server.ts'
import {
    requireOwnerSessionService,
    requirePermissionService,
} from '@/server/Auth/Access/authorization.service.ts'
import { getAvailableUpdateService } from '@/server/Updates/releases.service.ts'
import { getUpgradePreviewService } from '@/server/Updates/upgrade-preview.service.ts'
import type { ApplicationUpgradePreview } from './Types/application-update.types.ts'

export const getApplicationUpdateHandler = createServerFn({ method: 'GET' }).handler(async () => {
    await requirePermissionService(PERMISSIONS.APP_ACCESS)
    return getAvailableUpdateService(APP_VERSION)
})

/** Installed apps and built-in feature state are owner information, like the app catalog. */
export const getApplicationUpgradePreviewHandler = createServerFn({ method: 'GET' }).handler(
    async (): Promise<ApplicationUpgradePreview> => {
        setResponseHeader('Cache-Control', 'private, no-store')
        try {
            await requireOwnerSessionService()
        } catch {
            return { status: 'forbidden' }
        }
        return getUpgradePreviewService(APP_VERSION, appUiSignal(getRequest()))
    },
)
