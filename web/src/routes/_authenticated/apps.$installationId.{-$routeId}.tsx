import { createFileRoute } from '@tanstack/react-router'

import { PERMISSIONS } from '@/config/permissions.config.ts'
import AppUiFrame from '@/features/AppUi/AppUiFrame.tsx'
import { useAppUi } from '@/features/AppUi/AppUiProvider.tsx'
import { requirePermissionRoute } from '@/features/Auth/route-guards.ts'
import { appUiDefaultRoute } from '@/lib/AppUi/bridge.ts'
import useTranslationStore from '@/shared/Language/Hooks/useTranslationStore.ts'

export const Route = createFileRoute('/_authenticated/apps/$installationId/{-$routeId}')({
    beforeLoad: requirePermissionRoute(PERMISSIONS.APP_ACCESS),
    validateSearch: (search): { slot?: 'search' } =>
        search.slot === 'search' ? { slot: 'search' } : {},
    component: ApplicationRoute,
})

function ApplicationRoute() {
    const inventory = useAppUi()
    const { t } = useTranslationStore()
    const { installationId, routeId } = Route.useParams()
    const search = Route.useSearch()
    const navigate = Route.useNavigate()
    const app = inventory?.apps.find((candidate) => candidate.installationId === installationId)

    if (inventory?.isPending) return <output>{t('appUi.loading')}</output>
    if (!app) return <output>{t('appUi.unavailable')}</output>

    const activeRoute = routeId ?? appUiDefaultRoute(app)

    if (
        !app.routes.includes(activeRoute) ||
        (search.slot === 'search' && !app.slots.includes('search'))
    ) {
        return <output>{t('appUi.unavailable')}</output>
    }
    const slot = search.slot ?? (app.slots.includes('navigation') ? 'navigation' : undefined)

    return (
        <section>
            <h1 className="mb-6 font-display text-4xl text-ink">{app.name}</h1>
            <AppUiFrame
                app={app}
                slot={slot}
                route={activeRoute}
                onNavigate={(route) => {
                    if (route === activeRoute) return
                    void navigate({
                        to: '/apps/$installationId/{-$routeId}',
                        params: { installationId, routeId: route },
                        search,
                    }).catch(() => {})
                }}
            />
        </section>
    )
}
