import { useMemo, useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { HOST_MONITORING_UI } from '@/config/host-monitoring-ui.config.ts'
import {
    getHostMonitoringSummary,
    HostMonitoringClientError,
} from '@/lib/HostMonitoring/hostMonitoringClient.ts'
import { hostMonitoringQueryKeys } from '@/lib/HostMonitoring/hostMonitoringCache.ts'
import type { ProxyHostSummary } from '@/lib/Admin/ProxyHostManagement/Types/proxy-hosts.types.ts'
import useTranslationStore from '@/shared/Language/Hooks/useTranslationStore.ts'
import type {
    HostMonitoringSummaries,
    ProxyHostMonitoringRow,
} from '../Types/host-monitoring-overview.types.ts'

const isHandedOff = (error: unknown) =>
    error instanceof HostMonitoringClientError && error.code === 'handed_off'

/** Rows per host, and whether an app took monitoring over so the built-in controls step aside. */
export default function useHostMonitoringSummaries(
    hosts: readonly ProxyHostSummary[],
    enabled: boolean,
): HostMonitoringSummaries {
    const { t, locale } = useTranslationStore()
    const ids = useMemo(() => hosts.map((host) => host.id).toSorted(), [hosts])
    // The handoff outlives the query of one host page: a new page asks once, but neither polls nor
    // shows the built-in column again until a summary reports built-in monitoring, as after an abort.
    const [retiredAt, setRetiredAt] = useState<number | null>(null)
    const retired = retiredAt !== null
    const query = useQuery({
        queryKey: hostMonitoringQueryKeys.summary(ids),
        queryFn: ({ signal }) => getHostMonitoringSummary(ids, signal),
        enabled: enabled && ids.length > 0,
        staleTime: 5_000,
        // A handoff to an app is final: stop asking for built-in summaries once it is reported.
        refetchInterval: (current) =>
            enabled && ids.length > 0 && !retired && !isHandedOff(current.state.error)
                ? HOST_MONITORING_UI.pollIntervalMs
                : false,
        refetchIntervalInBackground: false,
        refetchOnWindowFocus: true,
        refetchOnReconnect: true,
        retry: (count, error) =>
            count < 1 &&
            !(
                error instanceof HostMonitoringClientError &&
                (error.code === 'authentication_required' ||
                    error.code === 'permission_denied' ||
                    error.code === 'handed_off')
            ),
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
    const reported = isHandedOff(query.error)
    // Only a summary fetched after the handoff report proves built-in monitoring, not cached data.
    if (reported && !retired) setRetiredAt(query.errorUpdatedAt)
    else if (retired && query.isSuccess && query.dataUpdatedAt > retiredAt) setRetiredAt(null)
    const handedOff = enabled && (retired || reported)
    const rows = useMemo(() => {
        const policies = new Map(
            enabled && !query.isError
                ? query.data?.summaries.map((row) => [row.proxyHostId, row.policy] as const)
                : [],
        )
        return new Map(
            hosts.map((host): [string, ProxyHostMonitoringRow] => {
                if (!enabled || query.isError || (!query.isPending && !policies.has(host.id)))
                    return [
                        host.id,
                        {
                            availability: 'unavailable',
                            checkedAt: null,
                            checkedAtIso: null,
                            duration: null,
                        },
                    ]
                const policy = policies.get(host.id)
                return [
                    host.id,
                    {
                        availability: query.isPending
                            ? 'loading'
                            : (policy?.availability ?? 'disabled'),
                        checkedAt: policy?.lastCheckedAt
                            ? t('admin.hostMonitoring.checkedAtValue', {
                                  time: formatter.format(policy.lastCheckedAt),
                              })
                            : null,
                        checkedAtIso: policy?.lastCheckedAt?.toISOString() ?? null,
                        duration:
                            policy?.lastDurationMs === null || policy?.lastDurationMs === undefined
                                ? null
                                : durationFormatter.format(policy.lastDurationMs),
                    },
                ]
            }),
        )
    }, [
        durationFormatter,
        enabled,
        formatter,
        hosts,
        query.data,
        query.isError,
        query.isPending,
        t,
    ])
    return useMemo(() => ({ rows, handedOff }), [rows, handedOff])
}
