import { useMemo } from 'react'
import { useQuery } from '@tanstack/react-query'
import { HOST_MONITORING_APP } from '@/config/host-monitoring.config.ts'
import { getHostMonitoringAppSummary } from '@/lib/HostMonitoring/hostMonitoringClient.ts'
import { hostMonitoringQueryKeys } from '@/lib/HostMonitoring/hostMonitoringCache.ts'
import type { ProxyHostSummary } from '@/lib/Admin/ProxyHostManagement/Types/proxy-hosts.types.ts'
import useTranslationStore from '@/shared/Language/Hooks/useTranslationStore.ts'
import type {
    HostMonitoringAppRows,
    ProxyHostAppMonitoringRow,
} from '../Types/host-monitoring-overview.types.ts'

/**
 * The monitoring app's state per host, loaded apart from the host list, so the table renders
 * first. It asks only while an app owns monitoring; any failure marks the whole column unavailable.
 */
export default function useHostMonitoringAppSummaries(
    hosts: readonly ProxyHostSummary[],
    enabled: boolean,
): HostMonitoringAppRows {
    const { locale } = useTranslationStore()
    const ids = useMemo(() => hosts.map((host) => host.id).toSorted(), [hosts])
    const active = enabled && ids.length > 0
    const query = useQuery({
        queryKey: hostMonitoringQueryKeys.appSummary(ids),
        queryFn: ({ signal }) => getHostMonitoringAppSummary(ids, signal),
        enabled: active,
        // The server caches the app's answer for about the same time.
        staleTime: HOST_MONITORING_APP.pollIntervalMs / 2,
        refetchInterval: active ? HOST_MONITORING_APP.pollIntervalMs : false,
        refetchIntervalInBackground: false,
        refetchOnWindowFocus: true,
        retry: false,
    })
    const formatter = useMemo(
        () => new Intl.DateTimeFormat(locale, { dateStyle: 'short', timeStyle: 'medium' }),
        [locale],
    )
    const durationFormatter = useMemo(
        () =>
            new Intl.NumberFormat(locale, {
                style: 'unit',
                unit: 'millisecond',
                unitDisplay: 'short',
            }),
        [locale],
    )
    return useMemo(() => {
        if (!active) return { rows: new Map(), installationId: null }
        // A failed refetch keeps old data in the query; it never counts as current.
        const answer = query.isError ? undefined : query.data
        const installationId = answer?.status === 'available' ? answer.installationId : null
        const reported = new Map(
            answer?.status === 'available' ? answer.hosts.map((row) => [row.proxyHostId, row]) : [],
        )
        return {
            installationId,
            rows: new Map(
                ids.map((id): [string, ProxyHostAppMonitoringRow] => {
                    const empty = { latency: null, observedAt: null, observedAtLabel: null }
                    if (query.isPending) return [id, { state: 'loading', ...empty }]
                    if (answer?.status !== 'available')
                        return [id, { state: 'unavailable', ...empty }]
                    const row = reported.get(id)
                    if (!row) return [id, { state: 'noData', ...empty }]
                    return [
                        id,
                        {
                            state: row.state,
                            latency:
                                row.latencyMs === null
                                    ? null
                                    : durationFormatter.format(row.latencyMs),
                            observedAt: row.observedAt,
                            observedAtLabel:
                                row.observedAt === null
                                    ? null
                                    : formatter.format(new Date(row.observedAt)),
                        },
                    ]
                }),
            ),
        }
    }, [active, durationFormatter, formatter, ids, query.data, query.isError, query.isPending])
}
