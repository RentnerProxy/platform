import { Link } from '@tanstack/react-router'
import { Download, RefreshCw } from 'lucide-react'
import { buttonClassName } from '@/shared/Buttons/buttonStyles.ts'
import useTranslationStore from '@/shared/Language/Hooks/useTranslationStore.ts'
import PageHeader from '@/shared/Management/PageHeader.tsx'
import useAppCatalogLogic from './Hooks/useAppCatalogLogic.ts'

export default function AppCatalogPage() {
    const { t } = useTranslationStore()
    const { state, handler } = useAppCatalogLogic()

    return (
        <section>
            <PageHeader
                eyebrow={t('appUi.apps')}
                title={t('appCatalog.title')}
                description={t('appCatalog.description')}
                action={
                    <button
                        type="button"
                        className={buttonClassName('secondary')}
                        disabled={state.isRefreshing}
                        onClick={handler.handleRefresh}
                    >
                        <RefreshCw className="size-4" aria-hidden="true" />
                        {t('appCatalog.refresh')}
                    </button>
                }
            />
            <div aria-live="polite" className="space-y-2">
                {state.status !== 'ready' ? (
                    <p className="text-sm text-muted">{t(`appCatalog.status.${state.status}`)}</p>
                ) : state.entries.length === 0 ? (
                    <p className="text-sm text-muted">{t('appCatalog.empty')}</p>
                ) : null}
                {state.isInstalling ? (
                    <p className="text-sm font-semibold text-ink">{t('appCatalog.installing')}</p>
                ) : null}
                {state.failure ? (
                    <p className="text-sm text-danger-text">
                        {t(`appCatalog.errors.${state.failure}`)}
                    </p>
                ) : null}
                {state.showInstalled ? (
                    <p className="text-sm text-ink">{t('appCatalog.installed')}</p>
                ) : null}
            </div>
            {state.entries.length > 0 ? (
                <ul className="mt-5 grid gap-4 lg:grid-cols-2">
                    {state.entries.map(
                        ({ entry, installationId, isInstalled, isRetry, canInstall }) => (
                            <li
                                key={`${entry.appId}@${entry.version}`}
                                className="flex min-w-0 flex-col gap-4 rounded-2xl border border-border bg-surface-subtle p-5"
                            >
                                <div className="min-w-0">
                                    <h2 className="font-display text-2xl wrap-anywhere text-ink">
                                        {entry.name}
                                    </h2>
                                    <p className="mt-1 text-sm wrap-anywhere text-muted">
                                        {t('appCatalog.release', {
                                            publisher: entry.publisher,
                                            version: entry.version,
                                        })}
                                    </p>
                                </div>
                                <p className="text-sm wrap-anywhere text-ink-soft">
                                    {entry.summary}
                                </p>
                                <div className="mt-auto flex flex-wrap items-center gap-3">
                                    {isInstalled ? (
                                        <>
                                            {installationId ? (
                                                <Link
                                                    to="/apps/$installationId/{-$routeId}"
                                                    params={{ installationId, routeId: undefined }}
                                                    search={{}}
                                                    className={buttonClassName('secondary')}
                                                    onClick={() => handler.handleOpen(entry.appId)}
                                                >
                                                    {t('appCatalog.open')}
                                                </Link>
                                            ) : null}
                                            <span className="text-sm text-muted">
                                                {t('appCatalog.installed')}
                                            </span>
                                        </>
                                    ) : entry.availability === 'available' ? (
                                        <button
                                            type="button"
                                            className={buttonClassName('primary')}
                                            disabled={!canInstall}
                                            onClick={() => handler.handleInstall(entry)}
                                        >
                                            <Download className="size-4" aria-hidden="true" />
                                            {t(isRetry ? 'appCatalog.retry' : 'appCatalog.install')}
                                        </button>
                                    ) : (
                                        <p className="text-sm text-muted">
                                            {t(`appCatalog.availability.${entry.availability}`)}
                                        </p>
                                    )}
                                </div>
                            </li>
                        ),
                    )}
                </ul>
            ) : null}
        </section>
    )
}
