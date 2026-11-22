import { Link } from '@tanstack/react-router'
import { ArrowUp, ExternalLink, Package } from 'lucide-react'

import type { CatalogLifecycleInput } from '@/lib/AppCatalog/contract.ts'
import { buttonClassName } from '@/shared/Buttons/buttonStyles.ts'
import useTranslationStore from '@/shared/Language/Hooks/useTranslationStore.ts'
import type { CatalogInstallationView } from '../Types/app-catalog.types.ts'

const statusColors = {
    running: 'bg-success-bg text-success-text',
    disabled: 'bg-surface-raised text-muted',
    recoveryRequired: 'bg-warning-text/10 text-warning-text',
    removing: 'bg-warning-text/10 text-warning-text',
    removed: 'bg-surface-raised text-muted',
    purging: 'bg-warning-text/10 text-warning-text',
} as const

export default function InstalledAppCard({
    app,
    canManage,
    onAction,
}: {
    app: CatalogInstallationView
    canManage: boolean
    onAction: (app: CatalogInstallationView, request: CatalogLifecycleInput) => void
}) {
    const { t } = useTranslationStore()
    const { installation, name, publisher, canOpen, actions } = app

    return (
        <li className="flex flex-wrap items-center justify-between gap-x-6 gap-y-4 rounded-2xl border border-border bg-surface-subtle p-4 sm:p-5">
            <div className="flex min-w-0 items-start gap-3">
                <span className="grid size-11 shrink-0 place-items-center rounded-xl border border-border bg-surface-raised text-muted">
                    <Package className="size-5" aria-hidden="true" />
                </span>
                <div className="min-w-0">
                    <div className="flex flex-wrap items-center gap-x-2 gap-y-1">
                        <h3 className="text-base font-bold wrap-anywhere text-ink">{name}</h3>
                        <span
                            className={`rounded-full px-2.5 py-1 text-xs font-semibold ${statusColors[installation.state]}`}
                        >
                            {t(`appCatalog.management.states.${installation.state}`)}
                        </span>
                    </div>
                    <p className="mt-1 text-sm wrap-anywhere text-muted">
                        {publisher
                            ? t('appCatalog.release', { publisher, version: installation.version })
                            : t('appCatalog.management.version', { version: installation.version })}
                    </p>
                </div>
            </div>
            <div className="flex flex-wrap items-center gap-2">
                {canOpen ? (
                    <Link
                        to="/apps/$installationId/{-$routeId}"
                        params={{ installationId: installation.installationId, routeId: undefined }}
                        search={{}}
                        className={buttonClassName('secondary')}
                    >
                        <ExternalLink className="size-4" aria-hidden="true" />
                        {t('appCatalog.open')}
                    </Link>
                ) : null}
                {actions.map((request) => (
                    <button
                        key={request.action}
                        type="button"
                        className={buttonClassName(
                            request.action === 'update' ||
                                request.action === 'recover' ||
                                request.action === 'reinstall'
                                ? 'primary'
                                : request.action === 'purge'
                                  ? 'danger'
                                  : 'secondary',
                        )}
                        disabled={!canManage}
                        onClick={() => onAction(app, request)}
                    >
                        {request.action === 'update' ? (
                            <ArrowUp className="size-4" aria-hidden="true" />
                        ) : null}
                        {request.target &&
                        (request.action === 'update' || request.action === 'reinstall')
                            ? t(
                                  request.action === 'update'
                                      ? 'appCatalog.management.updateTo'
                                      : 'appCatalog.management.reinstall',
                                  { version: request.target.version },
                              )
                            : t(`appCatalog.management.actions.${request.action}`)}
                    </button>
                ))}
            </div>
        </li>
    )
}
