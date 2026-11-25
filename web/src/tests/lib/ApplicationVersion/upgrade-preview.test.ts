import { describe, expect, test } from 'bun:test'

import type { UpgradePreviewApp } from '@/features/ApplicationVersion/Types/application-update.types.ts'
import type {
    BuiltInFeatureDomain,
    BuiltInFeatureTransition,
} from '@/lib/ApplicationVersion/Types/app-requirements.types.ts'
import { appProviderProfiles } from '@/lib/AppUi/identifiers.ts'
import {
    evaluateUpgradePreview,
    type LocalBuiltInFeature,
} from '@/lib/ApplicationVersion/upgradePreview.ts'

function plan(retired: Partial<Record<BuiltInFeatureDomain, readonly string[]>> = {}) {
    return appProviderProfiles.map((domain): BuiltInFeatureTransition => ({
        domain,
        status: retired[domain] ? 'retired' : 'built-in',
        apps: retired[domain] ?? [],
    }))
}

function app(overrides: Partial<UpgradePreviewApp> = {}): UpgradePreviewApp {
    return {
        installationId: 'app-monitoring',
        appId: 'rentnerproxy.monitoring',
        version: '1.2.0',
        state: 'running',
        providers: ['monitoring'],
        target: 'compatible',
        ...overrides,
    }
}

const platformOwned = (
    domain: BuiltInFeatureDomain,
    inspection?: LocalBuiltInFeature['inspection'],
): LocalBuiltInFeature => ({
    domain,
    ownership: { owner: 'platform' },
    ...(inspection ? { inspection } : {}),
})

describe('upgrade preview evaluation', () => {
    test('a target that keeps every feature built in and runs every app is ready', () => {
        const preview = evaluateUpgradePreview(
            plan(),
            [platformOwned('monitoring', { configured: true, references: 4 })],
            [app()],
        )
        expect(preview.status).toBe('ready')
        expect(preview.issues).toEqual([])
        expect(preview.features[0]).toEqual({
            domain: 'monitoring',
            target: 'built-in',
            apps: [],
            owner: 'platform',
            configured: true,
            references: 4,
            providers: ['rentnerproxy.monitoring'],
        })
        expect(preview.features[1]).toMatchObject({
            domain: 'docker-discovery',
            configured: null,
            references: null,
            providers: [],
        })
    })

    test('an installed app the target would not run blocks the update', () => {
        const preview = evaluateUpgradePreview(
            plan(),
            [],
            [
                app(),
                app({ installationId: 'app-dns', appId: 'example.dns', target: 'incompatible' }),
            ],
        )
        expect(preview.status).toBe('blocked')
        expect(preview.issues).toEqual([
            {
                kind: 'app-incompatible',
                installationId: 'app-dns',
                appId: 'example.dns',
                version: '1.2.0',
            },
        ])
    })

    test('unknown or unavailable app checks leave the preview incomplete, not ready', () => {
        expect(evaluateUpgradePreview(plan(), [], [app({ target: 'unknown' })]).status).toBe(
            'incomplete',
        )
        const unavailable = evaluateUpgradePreview(plan(), [], null)
        expect(unavailable.status).toBe('incomplete')
        expect(unavailable.apps).toBeNull()
        expect(unavailable.features.every(({ providers }) => providers === null)).toBe(true)
    })

    test('a retired feature without an installed providing app blocks the update', () => {
        const target = plan({ monitoring: ['rentnerproxy.monitoring'] })
        for (const local of [
            [],
            [platformOwned('monitoring', { configured: true, references: 0 })],
        ])
            expect(evaluateUpgradePreview(target, local, []).issues).toEqual([
                {
                    kind: 'feature-retired-without-app',
                    domain: 'monitoring',
                    apps: ['rentnerproxy.monitoring'],
                },
            ])
        // An incompatible provider does not count, and is reported itself.
        const incompatible = evaluateUpgradePreview(target, [], [app({ target: 'incompatible' })])
        expect(incompatible.issues.map(({ kind }) => kind)).toEqual([
            'app-incompatible',
            'feature-retired-without-app',
        ])
    })

    test('a retired feature still held by platform needs a completed handoff', () => {
        const target = plan({ monitoring: ['rentnerproxy.monitoring'] })
        for (const local of [
            [],
            [platformOwned('monitoring', { configured: false, references: 2 })],
            [
                {
                    domain: 'monitoring',
                    ownership: { owner: 'handoff' },
                } satisfies LocalBuiltInFeature,
            ],
        ]) {
            const preview = evaluateUpgradePreview(target, local, [app({ state: 'disabled' })])
            expect(preview.status).toBe('blocked')
            expect(preview.issues).toEqual([
                { kind: 'feature-handoff-pending', domain: 'monitoring' },
            ])
        }
    })

    test('a retired feature an app took over, or that holds nothing, does not block', () => {
        const target = plan({ monitoring: ['rentnerproxy.monitoring'] })
        expect(
            evaluateUpgradePreview(
                target,
                [{ domain: 'monitoring', ownership: { owner: 'app' } }],
                [app()],
            ).status,
        ).toBe('ready')
        expect(
            evaluateUpgradePreview(
                target,
                [platformOwned('monitoring', { configured: false, references: 0 })],
                [],
            ).status,
        ).toBe('ready')
    })

    test('a retired feature cannot be judged while installed apps are unknown', () => {
        const preview = evaluateUpgradePreview(plan({ dns: ['rentnerproxy.dns'] }), [], null)
        expect(preview.status).toBe('incomplete')
        expect(preview.issues).toEqual([])
    })
})
