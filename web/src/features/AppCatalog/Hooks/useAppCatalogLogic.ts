import { toast } from '@rentnerkev/toasts'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useEffect, useRef } from 'react'
import { useAppUi } from '@/features/AppUi/AppUiProvider.tsx'
import {
    APP_CATALOG_INSTALL_PATH,
    catalogInstallSchema,
    sameCatalogRelease,
    type CatalogSelector,
    type CatalogSnapshot,
} from '@/lib/AppCatalog/contract.ts'
import useTranslationStore from '@/shared/Language/Hooks/useTranslationStore.ts'
import { getAppCatalogHandler } from '../middleware.ts'

const installErrors = {
    400: 'invalid',
    401: 'forbidden',
    403: 'forbidden',
    409: 'conflict',
    413: 'invalid',
    429: 'rateLimited',
} as const

class CatalogRequestError extends Error {
    constructor(readonly code: (typeof installErrors)[keyof typeof installErrors]) {
        super(code)
    }
}

function isKnownInstallError(status: number): status is keyof typeof installErrors {
    return Object.hasOwn(installErrors, status)
}

async function installRelease(input: CatalogSelector) {
    const { appId, version, archiveSha256 } = input
    const response = await fetch(APP_CATALOG_INSTALL_PATH, {
        method: 'POST',
        credentials: 'same-origin',
        cache: 'no-store',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ appId, version, archiveSha256 }),
    })
    if (isKnownInstallError(response.status)) {
        throw new CatalogRequestError(installErrors[response.status])
    }
    if (!response.ok) throw new Error('Catalog installation is unavailable.')
    const value: unknown = await response.json()
    const result = catalogInstallSchema.parse(value)
    if (!sameCatalogRelease(result, input)) throw new Error('Unexpected catalog selection.')
    return result
}

export default function useAppCatalogLogic() {
    const { t } = useTranslationStore()
    const inventory = useAppUi()
    const queryClient = useQueryClient()
    const queryKey = ['app-catalog', inventory?.sessionId ?? null] as const
    const query = useQuery({
        queryKey,
        queryFn: ({ signal }) => getAppCatalogHandler({ signal }),
        retry: false,
        refetchInterval: ({ state }) => {
            if (state.data?.install?.status === 'installing') return 2_000
            if (state.data?.state === 'loading') return 5_000
            return false
        },
    })
    const mutation = useMutation({
        mutationFn: installRelease,
        onSuccess: async (install) => {
            await queryClient.cancelQueries({ queryKey })
            queryClient.setQueryData<CatalogSnapshot>(queryKey, (current) =>
                current ? { ...current, install } : current,
            )
            await queryClient.invalidateQueries({ queryKey })
        },
        onError: (error) => {
            const code = error instanceof CatalogRequestError ? error.code : 'unavailable'
            toast.error(t(`appCatalog.errors.${code}`), { title: t('toast.titles.error') })
            void queryClient.invalidateQueries({ queryKey }).catch(() => {})
        },
    })

    const snapshot = query.isError ? undefined : query.data
    const install = snapshot?.install
    const isInstalling = mutation.isPending || install?.status === 'installing'
    const status = snapshot?.state ?? (query.isPending ? 'loading' : 'unavailable')
    const refreshAppUi = inventory?.refresh
    const installedAppId = install?.status === 'installed' ? install.installationId : undefined
    const refreshedInstall = useRef<string | undefined>(undefined)
    useEffect(() => {
        if (!installedAppId || !refreshAppUi || refreshedInstall.current === installedAppId) return
        refreshedInstall.current = installedAppId
        void refreshAppUi().catch(() => {})
    }, [installedAppId, refreshAppUi])

    const installed = new Map(inventory?.apps.map((app) => [app.appId, app.installationId]))
    const entries = (snapshot?.entries ?? []).map((entry) => {
        const isSelected = !!install && sameCatalogRelease(install, entry)
        const installationId = installed.get(entry.appId)
        const isInstalled = !!installationId || (isSelected && install.status === 'installed')
        const isRetry = isSelected && install.status === 'failed'
        return {
            entry,
            installationId,
            isInstalled,
            isRetry,
            canInstall:
                !isInstalled &&
                !isInstalling &&
                status === 'ready' &&
                entry.availability === 'available',
        }
    })
    const showInstalled =
        !!installedAppId &&
        !entries.some(({ entry, isInstalled }) => entry.appId === install?.appId && isInstalled)

    return {
        state: {
            status,
            entries,
            isInstalling,
            isRefreshing: query.isFetching,
            failure: install?.status === 'failed' ? (install.error ?? 'installFailed') : null,
            showInstalled,
        },
        handler: {
            handleInstall: mutation.mutate,
            handleRefresh: () => {
                void query.refetch().catch(() => {})
            },
        },
    }
}
