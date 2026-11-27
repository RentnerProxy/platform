import { randomUUID } from 'node:crypto'
import { describe, expect, test } from 'bun:test'
import { classifyHostMonitoringOutcome } from '@/lib/HostMonitoring/state.ts'
import { domainDiagnosticsResultSchema } from '@/lib/RuntimeDiagnostics/domainDiagnostics.ts'
import { upstreamProbeOutcome } from '@/server/AppRuntime/upstream-probe-outcome.ts'
import type { AppUpstreamProbeOutcome } from '@/server/AppRuntime/Types/upstream-probes.types.ts'
import fixtures from '../../fixtures/app-contracts/upstream-probe-fixtures.json'

const expectedRevision = 'sha256:' + 'a'.repeat(64)
const unreachable = new Set(['upstream_unreachable', 'upstream_timeout', 'upstream_dns_failed'])

type Fixture = (typeof fixtures.cases)[number]
type Stages = Parameters<typeof upstreamProbeOutcome>[2]

/** The upstream-only result the core returns for the fixture's stages. */
function diagnosticsResult(stages: Stages) {
    const active = stages.configuration.code === 'configuration_active'
    return domainDiagnosticsResultSchema.parse({
        hostType: 'proxy',
        hostId: randomUUID(),
        domain: 'app.example.net',
        expectedRevision,
        activeRevision: active ? expectedRevision : null,
        checkedAt: new Date().toISOString(),
        observationPoint: 'appliance',
        publicReachability: 'not_checked',
        stages,
    })
}

const unknown = (code: string) => ({ status: 'unknown', code, durationMs: null, httpStatus: null })

/** An app classifies a probe result as the contract describes built-in monitoring. */
function appClassification(result: AppUpstreamProbeOutcome, expectedStatus: number): unknown {
    if (result.outcome === 'busy') return unknown('busy')
    if (result.outcome === 'unavailable') return unknown('runtime_unavailable')
    if (result.outcome !== 'probed') return null
    const { failure, httpStatus, durationMs } = result
    if (failure?.stage === 'configuration') return unknown(failure.code)
    if (failure?.stage === 'tls')
        return { status: 'unhealthy', code: 'tls_failed', durationMs, httpStatus: null }
    if (failure === null && httpStatus !== null) {
        const accepted =
            httpStatus === expectedStatus ||
            (expectedStatus === 200 && httpStatus >= 200 && httpStatus < 400)
        return {
            status: accepted ? 'healthy' : 'unhealthy',
            code: accepted ? 'expected_status' : 'unexpected_status',
            durationMs,
            httpStatus,
        }
    }
    if (failure?.stage === 'upstream' && unreachable.has(failure.code))
        return { status: 'unhealthy', code: failure.code, durationMs, httpStatus: null }
    return unknown('invalid_response')
}

const probed = fixtures.cases.filter(
    (fixture): fixture is Fixture & { diagnostics: { stages: Stages } } =>
        fixture.diagnostics !== null && 'stages' in fixture.diagnostics,
)

describe('monitoring-class upstream probe results', () => {
    test('the shared fixtures cover every result the platform derives from stages', () => {
        expect(probed.length).toBeGreaterThanOrEqual(15)
    })

    for (const fixture of probed) {
        test(fixture.title, () => {
            const diagnostics = diagnosticsResult(fixture.diagnostics.stages)
            const { hostId, domain, probeRevision } = fixture.result as {
                hostId: string
                domain: string
                probeRevision: string
            }
            const result = upstreamProbeOutcome({ hostId, domain }, probeRevision, diagnostics.stages)
            expect(result).toEqual(fixture.result as AppUpstreamProbeOutcome)
            // Built-in monitoring and an app that reads only the probe result agree exactly.
            const monitoring: unknown = classifyHostMonitoringOutcome(
                diagnostics,
                fixture.expectedStatus,
            )
            expect(monitoring).toEqual(fixture.monitoring)
            expect(appClassification(result, fixture.expectedStatus)).toEqual(monitoring)
        })
    }

    for (const fixture of fixtures.cases.filter((item) => !probed.includes(item as never))) {
        test(fixture.title, () => {
            const result = fixture.result as AppUpstreamProbeOutcome
            expect(appClassification(result, fixture.expectedStatus)).toEqual(fixture.monitoring)
        })
    }
})
