export interface DomainDiagnosticsProbeOptions {
    upstreamOnly?: boolean
    /** Marks an app probe admitted by its own per-installation budget; requires upstreamOnly. */
    installationId?: string
    timeoutMs?: number
}
