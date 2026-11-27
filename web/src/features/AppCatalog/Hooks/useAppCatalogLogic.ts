import { toast } from '@rentnerkev/toasts'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useEffect, useRef, useState } from 'react'
import { useAppUi } from '@/features/AppUi/AppUiProvider.tsx'
import {
    isPackageSourceOutage,
    sameCatalogLifecycle,
    sameCatalogRelease,
    type CatalogEntry,
    type CatalogGrant,
    type CatalogLifecycleInput,
    type CatalogLifecycle,
    type CatalogRelease,
} from '@/lib/AppCatalog/contract.ts'
import { revokeGrantRequest } from '@/lib/AppCatalog/grantApproval.ts'
import {
    catalogBlockedRelease,
    catalogInstallationActions,
} from '@/lib/AppCatalog/installationActions.ts'
import { keepCatalogProgress, type CatalogQueryResult } from '@/lib/AppCatalog/installProgress.ts'
import {
    catalogRequestError,
    installCatalogRelease,
    manageCatalogInstallation,
} from '@/lib/AppCatalog/requests.ts'
import useTranslationStore from '@/shared/Language/Hooks/useTranslationStore.ts'
import type {
    CatalogApprovalRequest,
    CatalogConfirmation,
    CatalogInstallationView,
} from '../Types/app-catalog.types.ts'
import { getAppCatalogHandler } from '../middleware.ts'

export default function useAppCatalogLogic() {
    const { t } = useTranslationStore()
    const inventory = useAppUi()
    const queryClient = useQueryClient()
    const [confirmation, setConfirmation] = useState<CatalogConfirmation | null>(null)
    const [approval, setApproval] = useState<CatalogApprovalRequest | null>(null)
    const [previousReceipt, setPreviousReceipt] = useState<CatalogLifecycle | null>(null)
    const queryKey = ['app-catalog', inventory?.sessionId ?? null] as const
    const query = useQuery({
        queryKey,
        queryFn: async ({ signal }) => {
            const current = await getAppCatalogHandler({ signal }).catch(() => null)
            signal.throwIfAborted()
            if (current === 'forbidden') return keepCatalogProgress(undefined, null, Date.now())
            return keepCatalogProgress(
                queryClient.getQueryData<CatalogQueryResult>(queryKey),
                current,
                Date.now(),
            )
        },
        retry: false,
        refetchInterval: ({ state }) => {
            if (
                state.data?.install?.status === 'installing' ||
                state.data?.lifecycle?.status === 'pending'
            )
                return 2_000
            if (state.data?.state === 'loading') return 5_000
            return false
        },
    })
    const installMutation = useMutation({
        mutationFn: installCatalogRelease,
        onSuccess: async (install) => {
            await queryClient.cancelQueries({ queryKey })
            queryClient.setQueryData<CatalogQueryResult>(
                queryKey,
                (current) => current && { ...current, install },
            )
            await queryClient.invalidateQueries({ queryKey })
        },
        onError: (error) => {
            toast.error(t(`appCatalog.errors.${catalogRequestError(error)}`), {
                title: t('toast.titles.error'),
            })
            void queryClient.invalidateQueries({ queryKey }).catch(() => {})
        },
    })
    const lifecycleMutation = useMutation({
        mutationFn: manageCatalogInstallation,
        onMutate: () => {
            setPreviousReceipt(
                queryClient.getQueryData<CatalogQueryResult>(queryKey)?.lifecycle ?? null,
            )
        },
        onSuccess: async (lifecycle) => {
            await queryClient.cancelQueries({ queryKey })
            queryClient.setQueryData<CatalogQueryResult>(
                queryKey,
                (current) => current && { ...current, lifecycle },
            )
            await queryClient.invalidateQueries({ queryKey })
        },
        onError: () => queryClient.invalidateQueries({ queryKey }),
    })

    const snapshot = query.data
    const install = snapshot?.install
    const lifecycle = snapshot?.lifecycle
    const pendingAction = lifecycleMutation.isPending
        ? lifecycleMutation.variables
        : lifecycle?.status === 'pending'
          ? lifecycle
          : undefined
    const isInstalling = installMutation.isPending || install?.status === 'installing'
    const status = snapshot?.state ?? (query.isPending ? 'loading' : 'unavailable')
    const canManage = snapshot?.isConnected === true && !isInstalling && !pendingAction
    const refreshAppUi = inventory?.refresh
    const refreshedInstall = useRef<typeof install>(undefined)
    useEffect(() => {
        if (
            install?.status !== 'installed' ||
            !refreshAppUi ||
            refreshedInstall.current === install
        )
            return
        refreshedInstall.current = install
        void refreshAppUi().catch(() => {})
    }, [install, refreshAppUi])

    const refreshedLifecycle = useRef<typeof lifecycle>(undefined)
    useEffect(() => {
        if (!lifecycle || lifecycle.status === 'pending') {
            refreshedLifecycle.current = undefined
            return
        }
        if (refreshedLifecycle.current === lifecycle) return
        refreshedLifecycle.current = lifecycle
        void refreshAppUi?.().catch(() => {})
    }, [lifecycle, refreshAppUi])

    // Without a reachable source, only packages already in the local store can be installed.
    const sourceUnreachable =
        status === 'stale' ||
        status === 'unavailable' ||
        (install?.status === 'failed' && isPackageSourceOutage(install.error)) ||
        (lifecycle?.status === 'failed' && isPackageSourceOutage(lifecycle.error))
    const catalogEntries = snapshot?.entries ?? []
    const catalogNames = new Map(catalogEntries.map((entry) => [entry.appId, entry]))
    const availableReleases = new Map<string, CatalogRelease>(
        catalogEntries
            .filter((entry) => entry.availability === 'available')
            .map(({ appId, version, archiveSha256 }) => [appId, { version, archiveSha256 }]),
    )
    const accessibleApps = new Map(inventory?.apps.map((app) => [app.installationId, app]))
    const installedAppIds = new Set(snapshot?.installations.map((row) => row.appId))
    const installations: CatalogInstallationView[] = (snapshot?.installations ?? []).map(
        (installation) => {
            const declaredApp = catalogNames.get(installation.appId)
            const app = accessibleApps.get(installation.installationId)
            const { update } = installation
            const cachedUpdate =
                update !== null &&
                catalogEntries.some(
                    (entry) =>
                        entry.cached &&
                        sameCatalogRelease(entry, { appId: installation.appId, ...update }),
                )
            return {
                installation,
                name: installation.name ?? declaredApp?.name ?? app?.name ?? installation.appId,
                publisher: declaredApp?.publisher,
                canOpen: installation.state === 'running' && app?.appId === installation.appId,
                actions: catalogInstallationActions(
                    installation,
                    status === 'ready',
                    availableReleases.get(installation.appId),
                ),
                blockedRelease: catalogBlockedRelease(installation, catalogEntries),
                updateRequiresSource:
                    update !== null && status === 'ready' && sourceUnreachable && !cachedUpdate,
            }
        },
    )
    const entries = catalogEntries
        .filter((entry) => !installedAppIds.has(entry.appId))
        .map((entry) => {
            return {
                entry,
                isRetry: install?.status === 'failed' && sameCatalogRelease(install, entry),
                canInstall: canManage && status === 'ready' && entry.availability === 'available',
                requiresSource:
                    sourceUnreachable && entry.availability === 'available' && !entry.cached,
            }
        })
    const retained = installations.filter(
        ({ installation }) => installation.state === 'removed' || installation.state === 'purging',
    )
    const installed = installations.filter(
        ({ installation }) => installation.state !== 'removed' && installation.state !== 'purging',
    )
    const unconfirmed =
        lifecycleMutation.isError &&
        (!lifecycle ||
            lifecycle === previousReceipt ||
            !sameCatalogLifecycle(lifecycle, lifecycleMutation.variables))
    const reportedAction = pendingAction ?? (unconfirmed ? lifecycleMutation.variables : lifecycle)
    const operationName = installations.find(
        ({ installation }) => installation.installationId === reportedAction?.installationId,
    )?.name

    function listedEntry(appId: string, target: CatalogRelease | undefined) {
        return target
            ? catalogEntries.find(
                  (entry) =>
                      entry.availability === 'available' &&
                      sameCatalogRelease(entry, { appId, ...target }),
              )
            : undefined
    }

    function handleInstall(entry: CatalogEntry) {
        if (!canManage) return
        if (entry.grants.length === 0) {
            installMutation.mutate(entry)
            return
        }
        const { appId, version, archiveSha256 } = entry
        setApproval({
            kind: 'install',
            name: entry.name,
            version,
            requested: entry.grants,
            permissionKeys: entry.permissionKeys,
            previous: null,
            submit: (grants) =>
                installMutation.mutate({ appId, version, archiveSha256, approval: grants }),
        })
    }

    function handleAction(
        { name, installation }: CatalogInstallationView,
        request: CatalogLifecycleInput,
    ) {
        if (!canManage) return
        if (
            request.action === 'uninstall' ||
            request.action === 'purge' ||
            request.action === 'rollback'
        ) {
            setConfirmation({ name, request })
            return
        }
        // An update that requests more than the current approval, and every reinstall of a
        // release with grants, starts only after the Owner approves its access.
        const reviewed =
            (request.action === 'update' && installation.updateRequiresApproval) ||
            request.action === 'reinstall'
        const entry = reviewed ? listedEntry(installation.appId, request.target) : undefined
        if (request.action === 'update' && installation.updateRequiresApproval && !entry) return
        if (entry && entry.grants.length > 0) {
            setApproval({
                kind: request.action === 'update' ? 'update' : 'reinstall',
                name,
                version: entry.version,
                requested: entry.grants,
                permissionKeys: entry.permissionKeys,
                previous: installation.grants,
                submit: (grants) => lifecycleMutation.mutate({ ...request, approval: grants }),
            })
            return
        }
        lifecycleMutation.mutate(request)
    }

    function handleRevoke(
        { name, installation }: CatalogInstallationView,
        grant: CatalogGrant,
        label: string,
    ) {
        if (!canManage) return
        setConfirmation({ name, request: revokeGrantRequest(installation, grant), grant: label })
    }

    return {
        state: {
            status,
            entries,
            installed,
            retained,
            isInstalling,
            isRefreshing: query.isFetching,
            isLoading: query.isPending,
            isConnected: snapshot?.isConnected === true,
            canManage,
            confirmation,
            // The Owner's approval starts the operation only while the catalog can manage apps.
            approval: approval && {
                ...approval,
                submit: (grants: Parameters<CatalogApprovalRequest['submit']>[0]) => {
                    setApproval(null)
                    if (canManage) approval.submit(grants)
                },
            },
            installFailure:
                install?.status === 'failed' ? (install.error ?? 'installFailed') : null,
            operation: reportedAction?.action,
            operationName,
            operationStatus: pendingAction ? 'pending' : unconfirmed ? 'failed' : lifecycle?.status,
            operationError: pendingAction
                ? undefined
                : unconfirmed
                  ? catalogRequestError(lifecycleMutation.error)
                  : lifecycle?.status === 'failed'
                    ? lifecycle.error
                    : undefined,
        },
        handler: {
            handleInstall,
            handleAction,
            handleRevoke,
            handleApprovalChange: (open: boolean) => {
                if (!open) setApproval(null)
            },
            handleConfirm: () => {
                if (!canManage || !confirmation) return
                setConfirmation(null)
                lifecycleMutation.mutate(confirmation.request)
            },
            handleConfirmationChange: (open: boolean) => {
                if (!open) setConfirmation(null)
            },
            handleRefresh: () => {
                void query.refetch().catch(() => {})
            },
        },
    }
}
