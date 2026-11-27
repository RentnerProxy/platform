import { describe, expect, test } from 'bun:test'
import type { ProxyHostSummary } from '@/lib/Admin/ProxyHostManagement/Types/proxy-hosts.types.ts'
import { proxyHostChange } from '@/server/AppRuntime/host-events.server.ts'

const host: ProxyHostSummary = {
    id: '2f9c4b1e-6a3d-4e8f-9b7c-0d1e2f3a4b5c',
    domains: ['app.example.test'],
    enabled: true,
    certificateId: null,
    forceHttps: false,
    verifyUpstreamTls: true,
    upstreamTlsServerName: null,
    trustedCaId: null,
    accessPolicyId: null,
    forwardHost: '172.22.0.5',
    forwardPort: 8080,
    forwardScheme: 'http',
    createdAt: new Date('2026-11-01T00:00:00Z'),
    updatedAt: new Date('2026-11-01T00:00:00Z'),
}

describe('proxy host change events', () => {
    test('a save without a change records nothing, not even a new timestamp', () => {
        expect(proxyHostChange(host, { ...host, updatedAt: new Date() })).toBeNull()
    })

    test('an enabled transition alone is reported as such', () => {
        expect(proxyHostChange(host, { ...host, enabled: false })).toBe('proxyHostDisabled')
        expect(proxyHostChange({ ...host, enabled: false }, host)).toBe('proxyHostEnabled')
    })

    test('any other change is one update, also together with an enabled transition', () => {
        for (const change of [
            { domains: ['app.example.test', 'www.example.test'] },
            { forwardPort: 8081 },
            { certificateId: '8a7b6c5d-4e3f-4a1b-9c8d-7e6f5a4b3c2d', enabled: false },
            { accessPolicyId: '8a7b6c5d-4e3f-4a1b-9c8d-7e6f5a4b3c2d' },
        ])
            expect(proxyHostChange(host, { ...host, ...change })).toBe('proxyHostUpdated')
    })
})
