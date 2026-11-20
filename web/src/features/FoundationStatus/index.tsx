import useTranslationStore from '@/shared/Language/Hooks/useTranslationStore.ts'
import ContentState from '@/shared/Management/ContentState.tsx'
import PageAlert from '@/shared/PageAlerts/PageAlert.tsx'
import PageHeader from '@/shared/Management/PageHeader.tsx'
import AppUiFrame from '@/features/AppUi/AppUiFrame.tsx'
import { useAppUiSlot } from '@/features/AppUi/AppUiProvider.tsx'
import FoundationStatus from './Components/FoundationStatus/index.tsx'
import CrowdSecOverview from './Components/CrowdSecOverview/index.tsx'
import useFoundationStatusLogic from './Hooks/useFoundationStatusLogic.ts'

export default function FoundationStatusPage({
    permissions,
}: {
    readonly permissions: readonly string[]
}) {
    const { t } = useTranslationStore()
    const { state } = useFoundationStatusLogic(permissions)
    const widgets = useAppUiSlot('dashboardWidget')

    return (
        <>
            <PageHeader
                eyebrow={t('shell.controlPlane')}
                title={t('shell.overview')}
                description={t('foundation.description')}
            />
            {state.isPending ? (
                <ContentState
                    busy
                    title={t('foundation.loading.title')}
                    description={t('foundation.loading.description')}
                />
            ) : state.isError || !state.data ? (
                <PageAlert
                    severity="error"
                    title={t('foundation.error.title')}
                    description={t('foundation.error.description')}
                />
            ) : (
                <FoundationStatus health={state.data} liveStatus={state.liveStatus} compact />
            )}
            <CrowdSecOverview enabled={state.canViewCrowdSec} />
            {widgets.length > 0 ? (
                <div className="mt-6 grid gap-4 lg:grid-cols-2">
                    {widgets.map((app) => (
                        <section
                            key={app.installationId}
                            className="min-w-0 rounded-2xl border border-border bg-surface p-4"
                        >
                            <h2 className="mb-3 text-lg font-bold text-ink">{app.name}</h2>
                            <AppUiFrame app={app} slot="dashboardWidget" />
                        </section>
                    ))}
                </div>
            ) : null}
        </>
    )
}
