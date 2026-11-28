import type { ProxyHostSummary } from '@/lib/Admin/ProxyHostManagement/Types/proxy-hosts.types.ts'
import type { HostMonitoringAppState } from '@/lib/HostMonitoring/Types/host-monitoring-app.types.ts'
import type { HostAvailability } from '@/lib/HostMonitoring/Types/host-monitoring-presentation.types.ts'

export interface ProxyHostMonitoringRow {
    readonly availability: HostAvailability
    readonly checkedAt: string | null
    readonly checkedAtIso: string | null
    readonly duration: string | null
}

export interface HostMonitoringSummaries {
    readonly rows: ReadonlyMap<string, ProxyHostMonitoringRow>
    /** An app owns monitoring, so the table hides the built-in column and action. */
    readonly handedOff: boolean
}

export interface ProxyHostAppMonitoringRow {
    readonly state: HostMonitoringAppState | 'loading' | 'unavailable' | 'noData'
    readonly latency: string | null
    readonly observedAt: string | null
}

export interface HostMonitoringAppRows {
    readonly rows: ReadonlyMap<string, ProxyHostAppMonitoringRow>
    /** The app that owns monitoring, once it answered; the cell links to its host tab. */
    readonly installationId: string | null
}

export interface ProxyHostAppMonitoringCellProps {
    readonly host: ProxyHostSummary
    readonly onOpenApp?: ((host: ProxyHostSummary, installationId: string) => void) | undefined
}

export interface ProxyHostMonitoringCellProps {
    readonly host: ProxyHostSummary
    readonly onMonitoring: (host: ProxyHostSummary) => void
}
