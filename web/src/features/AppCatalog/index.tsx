import { CheckCircle2, CircleAlert, Download, LoaderCircle, RefreshCw } from 'lucide-react'
import { buttonClassName } from '@/shared/Buttons/buttonStyles.ts'
import useTranslationStore from '@/shared/Language/Hooks/useTranslationStore.ts'
import PageHeader from '@/shared/Management/PageHeader.tsx'
import { ConfirmDialog } from '@/shared/Modal/Components/ConfirmDialog.tsx'
import InstalledAppCard from './Components/InstalledAppCard.tsx'
import useAppCatalogLogic from './Hooks/useAppCatalogLogic.ts'

export default function AppCatalogPage() {
    const { t } = useTranslationStore()
    const { state, handler } = useAppCatalogLogic()
    const { confirmation, operation, operationStatus } = state

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

            <div aria-live="polite">
                {operation && operationStatus ? (
                    <div className="mb-5 flex items-start gap-3 rounded-2xl border border-border bg-surface-subtle p-4 text-sm">
                        {operationStatus === 'pending' ? (
                            <LoaderCircle
                                className="mt-0.5 size-4 shrink-0 text-accent-ring motion-safe:animate-spin"
                                aria-hidden="true"
                            />
                        ) : operationStatus === 'succeeded' ? (
                            <CheckCircle2
                                className="mt-0.5 size-4 shrink-0 text-success-text"
                                aria-hidden="true"
                            />
                        ) : (
                            <CircleAlert
                                className="mt-0.5 size-4 shrink-0 text-danger-text"
                                aria-hidden="true"
                            />
                        )}
                        <div className="min-w-0 space-y-1">
                            <p className="font-semibold text-ink">
                                {operationStatus === 'failed'
                                    ? t('appCatalog.management.failed')
                                    : t(`appCatalog.management.${operationStatus}.${operation}`)}
                            </p>
                            {state.operationName ? (
                                <p className="wrap-anywhere text-muted">{state.operationName}</p>
                            ) : null}
                            {state.operationError ? (
                                <p className="text-danger-text">
                                    {t(`appCatalog.management.errors.${state.operationError}`)}
                                </p>
                            ) : null}
                        </div>
                    </div>
                ) : null}
                {state.isInstalling ? (
                    <p className="mb-5 flex items-center gap-2 rounded-xl border border-border bg-surface-subtle p-4 text-sm font-semibold text-ink">
                        <LoaderCircle
                            className="size-4 shrink-0 text-accent-ring motion-safe:animate-spin"
                            aria-hidden="true"
                        />
                        {t('appCatalog.installing')}
                    </p>
                ) : null}
                {state.installFailure ? (
                    <p className="mb-5 rounded-xl border border-danger-text/20 bg-danger-bg p-4 text-sm text-danger-text">
                        {t(`appCatalog.errors.${state.installFailure}`)}
                    </p>
                ) : null}
            </div>

            <section aria-labelledby="installed-apps-title" className="space-y-3">
                <h2 id="installed-apps-title" className="font-display text-2xl text-ink">
                    {t('appCatalog.management.installed')}
                </h2>
                <div aria-live="polite">
                    {state.isLoading ? (
                        <p className="text-sm text-muted">{t('appCatalog.management.loading')}</p>
                    ) : !state.isConnected ? (
                        <p className="text-sm text-warning-text">
                            {t('appCatalog.management.unavailable')}
                        </p>
                    ) : state.installed.length === 0 ? (
                        <p className="text-sm text-muted">{t('appCatalog.management.empty')}</p>
                    ) : null}
                </div>
                {state.installed.length > 0 ? (
                    <ul className="grid gap-3">
                        {state.installed.map((app) => (
                            <InstalledAppCard
                                key={app.installation.installationId}
                                app={app}
                                canManage={state.canManage}
                                onAction={handler.handleAction}
                            />
                        ))}
                    </ul>
                ) : null}
            </section>

            {state.retained.length > 0 ? (
                <section aria-labelledby="retained-apps-title" className="mt-8 space-y-3">
                    <h2 id="retained-apps-title" className="font-display text-2xl text-ink">
                        {t('appCatalog.management.retained')}
                    </h2>
                    <ul className="grid gap-3">
                        {state.retained.map((app) => (
                            <InstalledAppCard
                                key={app.installation.installationId}
                                app={app}
                                canManage={state.canManage}
                                onAction={handler.handleAction}
                            />
                        ))}
                    </ul>
                </section>
            ) : null}

            <section
                aria-labelledby="available-apps-title"
                className="mt-8 space-y-3 border-t border-border pt-6"
            >
                <h2 id="available-apps-title" className="font-display text-2xl text-ink">
                    {t('appCatalog.management.discover')}
                </h2>
                <div aria-live="polite">
                    {state.status !== 'ready' ? (
                        <p className="text-sm text-muted">
                            {t(`appCatalog.status.${state.status}`)}
                        </p>
                    ) : state.entries.length === 0 ? (
                        <p className="text-sm text-muted">{t('appCatalog.empty')}</p>
                    ) : null}
                </div>
                {state.entries.length > 0 ? (
                    <ul className="grid gap-4 lg:grid-cols-2">
                        {state.entries.map(({ entry, isRetry, canInstall }) => (
                            <li
                                key={`${entry.appId}@${entry.version}`}
                                className="flex min-w-0 flex-col gap-4 rounded-2xl border border-border bg-surface-subtle p-5"
                            >
                                <div className="min-w-0">
                                    <h3 className="text-lg font-bold wrap-anywhere text-ink">
                                        {entry.name}
                                    </h3>
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
                                <div className="mt-auto">
                                    {entry.availability === 'available' ? (
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
                        ))}
                    </ul>
                ) : null}
            </section>

            <ConfirmDialog
                open={confirmation !== null}
                onOpenChange={handler.handleConfirmationChange}
                title={
                    confirmation
                        ? t(`appCatalog.management.actions.${confirmation.request.action}`)
                        : ''
                }
                description={
                    confirmation
                        ? t(`appCatalog.management.confirm.${confirmation.request.action}`, {
                              name: confirmation.name,
                              version: confirmation.request.target?.version,
                          })
                        : ''
                }
                confirmLabel={
                    confirmation
                        ? t(`appCatalog.management.actions.${confirmation.request.action}`)
                        : ''
                }
                destructive={confirmation?.request.action !== 'rollback'}
                onConfirm={handler.handleConfirm}
            />
        </section>
    )
}
