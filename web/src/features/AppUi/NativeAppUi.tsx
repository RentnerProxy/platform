import type { AppUiSummary } from '@/lib/AppUi/contract.ts'
import { nativeText } from '@/lib/AppUi/native-presentation.ts'
import { buttonClassName } from '@/shared/Buttons/buttonStyles.ts'
import useTranslationStore from '@/shared/Language/Hooks/useTranslationStore.ts'
import PageHeader from '@/shared/Management/PageHeader.tsx'
import NativeAppForm from './Components/NativeAppForm.tsx'
import NativeAppTable from './Components/NativeAppTable.tsx'
import { useNativeAppUiLogic, type NativeAppSession } from './Hooks/useNativeAppUiLogic.ts'

export default function NativeAppUi({
    app,
    route,
    onNavigate,
}: {
    app: AppUiSummary
    route: string
    onNavigate: (route: string) => void
}) {
    const { t, locale } = useTranslationStore()
    const { state, handler } = useNativeAppUiLogic(app)
    const { source, scope } = state
    const activePage = source.data?.presentation.pages.find((page) => page.route === route)
    const session: NativeAppSession | undefined = source.data && {
        scope,
        handler,
        operations: source.data.operations,
    }

    return (
        <section>
            <PageHeader
                eyebrow={t('appUi.apps')}
                title={app.name}
                description={
                    activePage?.description ? nativeText(activePage.description, locale) : ''
                }
            />
            {source.isPending ? (
                <output className="text-sm text-muted">{t('appUi.loading')}</output>
            ) : !source.data || !activePage || !session ? (
                <div className="flex flex-wrap items-center gap-3">
                    <output className="text-sm text-muted">{t('appUi.unavailable')}</output>
                    <button
                        type="button"
                        className={buttonClassName('secondary')}
                        onClick={() => void source.refetch()}
                    >
                        {t('common.retry')}
                    </button>
                </div>
            ) : (
                <>
                    <nav aria-label={app.name} className="mb-6 flex flex-wrap gap-2">
                        {source.data.presentation.pages.map((page) => (
                            <button
                                key={page.route}
                                type="button"
                                aria-current={page.route === route ? 'page' : undefined}
                                className={buttonClassName(
                                    page.route === route ? 'primary' : 'ghost',
                                )}
                                onClick={() => onNavigate(page.route)}
                            >
                                {nativeText(page.label, locale)}
                            </button>
                        ))}
                    </nav>
                    <div key={JSON.stringify(scope)}>
                        {source.data.presentation.pages.map((page) => (
                            <div key={page.route} hidden={page.route !== route}>
                                {page.kind === 'form' ? (
                                    <NativeAppForm
                                        page={page}
                                        session={session}
                                        appName={app.name}
                                        active={page.route === route}
                                    />
                                ) : (
                                    <NativeAppTable
                                        page={page}
                                        session={session}
                                        active={page.route === route}
                                    />
                                )}
                            </div>
                        ))}
                    </div>
                </>
            )}
        </section>
    )
}
