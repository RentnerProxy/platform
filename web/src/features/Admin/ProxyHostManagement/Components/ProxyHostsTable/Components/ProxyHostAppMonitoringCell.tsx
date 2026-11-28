import { createContext, useContext } from 'react'
import { TriangleExclamationPoint } from 'lucide-react'
import HostAvailabilityBadge from '@/features/Admin/HostMonitoring/Components/HostAvailabilityBadge.tsx'
import useTranslationStore from '@/shared/Language/Hooks/useTranslationStore.ts'
import type {
    HostMonitoringAppRows,
    ProxyHostAppMonitoringCellProps,
} from '../../../Types/host-monitoring-overview.types.ts'

export const ProxyHostAppMonitoringContext = createContext<HostMonitoringAppRows | undefined>(
    undefined,
)

const linkClassName =
    'grid cursor-pointer gap-1.5 rounded-lg text-left focus-visible:outline-2 focus-visible:outline-offset-4 focus-visible:outline-accent-ring'

/** The monitoring app's state of one host; it links to the app's tab of that host. */
export default function ProxyHostAppMonitoringCell({
    host,
    onOpenApp,
}: ProxyHostAppMonitoringCellProps) {
    const { t } = useTranslationStore()
    const monitoring = useContext(ProxyHostAppMonitoringContext)
    const view = monitoring?.rows.get(host.id)
    const state = view?.state ?? 'loading'
    const installationId = monitoring?.installationId ?? null
    const content = (
        <>
            {state === 'unavailable' ? (
                <output
                    title={t('admin.hostMonitoring.appUnavailableHint')}
                    className="inline-flex w-fit items-center gap-1.5 rounded-full border border-border bg-surface-raised px-2 py-1 text-xs font-bold text-muted"
                >
                    <TriangleExclamationPoint aria-hidden="true" className="size-3.5" />
                    {t('admin.hostMonitoring.appUnavailable')}
                </output>
            ) : state === 'noData' ? (
                <span className="text-xs text-muted">{t('admin.hostMonitoring.appNoData')}</span>
            ) : (
                <HostAvailabilityBadge availability={state} />
            )}
            {view?.observedAt ? (
                <time dateTime={view.observedAt} className="text-xs text-muted">
                    {new Date(view.observedAt).toLocaleString()}
                </time>
            ) : null}
            {view?.latency ? (
                <span className="font-mono text-xs text-ink-soft">{view.latency}</span>
            ) : null}
        </>
    )
    if (!onOpenApp || installationId === null || state === 'unavailable' || state === 'loading')
        return <div className="grid gap-1.5">{content}</div>
    return (
        <button
            type="button"
            className={linkClassName}
            onClick={() => onOpenApp(host, installationId)}
        >
            <span className="sr-only">
                {t('admin.hostMonitoring.appOpen', { name: host.domains[0] ?? host.forwardHost })}
            </span>
            {content}
        </button>
    )
}
