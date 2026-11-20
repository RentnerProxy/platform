import { useQuery } from '@tanstack/react-query'
import {
    createContext,
    useCallback,
    useContext,
    useMemo,
    useRef,
    useState,
    type ReactNode,
} from 'react'

import type { AuthenticatedUser } from '@/lib/Auth/Types/auth.types.ts'
import type { AppUiSlot, AppUiSummary } from '@/lib/AppUi/contract.ts'
import type { UserThemeMode } from '@/config/Types/theme-config.types.ts'
import { PERMISSIONS } from '@/config/permissions.config.ts'
import useTranslationStore from '@/shared/Language/Hooks/useTranslationStore.ts'
import { Modal } from '@/shared/Modal/index.tsx'
import { ModalActionButton, ModalCancelButton } from '@/shared/Modal/Components/ModalActions.tsx'
import { listAppUisHandler } from './middleware.ts'

type DialogOutcome = 'confirmed' | 'cancelled'

type AppDialog = {
    appName: string
    dialogId: string
    mount: string
    settle: (outcome: DialogOutcome) => void
}

type AppUiContext = {
    apps: AppUiSummary[]
    isPending: boolean
    sessionId: string | null
    theme: UserThemeMode
    refresh: () => Promise<AppUiSummary[]>
    openDialog: (dialog: AppDialog) => void
    cancelDialog: (mount: string) => void
}

const appUiContext = createContext<AppUiContext | null>(null)

export function useAppUi() {
    return useContext(appUiContext)
}

export function useAppUiSlot(slot: AppUiSlot) {
    return useAppUi()?.apps.filter((app) => app.slots.includes(slot)) ?? []
}

export default function AppUiProvider({
    children,
    user,
    sessionId,
    theme,
    active,
}: {
    children: ReactNode
    user: AuthenticatedUser
    sessionId: string | null
    theme: UserThemeMode
    active: boolean
}) {
    const { t } = useTranslationStore()
    const enabled =
        active && sessionId !== null && user.permissions.includes(PERMISSIONS.APP_ACCESS)
    const inventory = useQuery({
        queryKey: [
            'app-ui',
            user.id,
            sessionId,
            user.roles.toSorted(),
            user.permissions.toSorted(),
        ],
        queryFn: ({ signal }) =>
            sessionId ? listAppUisHandler({ data: { sessionId }, signal }) : [],
        enabled,
        retry: false,
        staleTime: 0,
        refetchOnWindowFocus: true,
        refetchInterval: 30_000,
    })
    const busy = useRef<AppDialog | null>(null)
    const [dialog, setDialog] = useState<AppDialog | null>(null)

    const settle = useCallback((outcome: DialogOutcome) => {
        const current = busy.current
        busy.current = null
        setDialog(null)
        current?.settle(outcome)
    }, [])
    const { data, isError, isPending, refetch } = inventory
    const context = useMemo<AppUiContext>(
        () => ({
            apps: enabled && !isError ? (data ?? []) : [],
            isPending: enabled && isPending,
            sessionId,
            theme,
            refresh: async () => {
                if (!enabled) return []
                const current = await refetch()
                return current.isSuccess ? current.data : []
            },
            openDialog: (request) => {
                if (busy.current) {
                    request.settle('cancelled')
                    return
                }
                busy.current = request
                setDialog(request)
            },
            cancelDialog: (mount) => {
                if (busy.current?.mount === mount) settle('cancelled')
            },
        }),
        [data, enabled, isError, isPending, refetch, sessionId, settle, theme],
    )

    return (
        <appUiContext.Provider value={context}>
            {children}
            <Modal
                open={dialog !== null}
                onOpenChange={(open) => {
                    if (!open) settle('cancelled')
                }}
                title={t('appUi.confirmTitle')}
                description={
                    dialog
                        ? t('appUi.confirmDescription', {
                              name: dialog.appName,
                              dialog: dialog.dialogId,
                          })
                        : ''
                }
                size="sm"
                footer={
                    <>
                        <ModalCancelButton onClick={() => settle('cancelled')} />
                        <ModalActionButton onClick={() => settle('confirmed')}>
                            {t('common.confirm')}
                        </ModalActionButton>
                    </>
                }
            />
        </appUiContext.Provider>
    )
}
