import type { DomainDiagnosticsResult } from '@/lib/RuntimeDiagnostics/Types/domain-diagnostics.types.ts'
import type {
    AppUpstreamProbeFailure,
    AppUpstreamProbeOutcome,
    AppUpstreamProbeTarget,
} from './Types/upstream-probes.types.ts'

/**
 * The probe result an app classifies like built-in host monitoring: the HTTP status, the upstream
 * duration and the first stage that prevented a usable response, checked in monitoring's order.
 */
export function upstreamProbeOutcome(
    target: Pick<AppUpstreamProbeTarget, 'hostId' | 'domain'>,
    probeRevision: string,
    stages: DomainDiagnosticsResult['stages'],
): AppUpstreamProbeOutcome {
    const { configuration, upstream, tls } = stages
    let failure: AppUpstreamProbeFailure | null = null
    if (configuration.code !== 'configuration_active')
        failure = { stage: 'configuration', code: configuration.code }
    else if (tls.code === 'tls_failed') failure = { stage: 'tls', code: tls.code }
    else if (upstream.httpStatus === null) failure = { stage: 'upstream', code: upstream.code }
    return {
        outcome: 'probed',
        hostId: target.hostId,
        domain: target.domain,
        probeRevision,
        durationMs: upstream.durationMs,
        httpStatus: upstream.httpStatus,
        failure,
    }
}
