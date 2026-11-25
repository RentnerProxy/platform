import { useQuery } from '@tanstack/react-query'

import { getApplicationUpgradePreviewHandler } from '../middleware.ts'
import type { ApplicationUpdate } from '../Types/application-update.types.ts'
import type { ApplicationUpgradePreviewQuery } from '../Types/application-update-dialog.types.ts'

/** Check local apps and features only while the dialog shows a target with verified requirements. */
export default function useApplicationUpgradePreviewQuery(
    latest: ApplicationUpdate | null | undefined,
    open: boolean,
): ApplicationUpgradePreviewQuery {
    const enabled = open && latest?.appRequirements.status === 'verified'
    const query = useQuery({
        queryKey: ['application-upgrade-preview', latest?.tag ?? null],
        queryFn: () => getApplicationUpgradePreviewHandler(),
        enabled,
        staleTime: 0,
        gcTime: 0,
        retry: false,
    })
    if (!enabled) return { preview: undefined, loading: false }
    return {
        preview: query.isError ? { status: 'unavailable' } : query.data,
        loading: query.isPending,
    }
}
