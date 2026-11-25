import { describe, expect, mock, test } from 'bun:test'

import type {
    ApplicationUpdate,
    ApplicationUpdateResult,
} from '@/features/ApplicationVersion/Types/application-update.types.ts'
import { BUILT_IN_FEATURE_TRANSITIONS } from '@/config/app-requirements.config.ts'
import type { UpgradePreviewDependencies } from '@/server/Updates/Types/upgrade-preview.types.ts'

// The default dependencies open the database; every test injects its own.
void mock.module('@/server/Auth/Core/database.server.ts', () => ({
    getAuthDatabase: () => {
        throw new Error('The preview test must inject its dependencies')
    },
}))
const { getUpgradePreviewService } = await import('@/server/Updates/upgrade-preview.service.ts')

const environment = {
    runtimeProfile: 'rentnerproxy-linux-v1',
    platformApi: '1.1.0',
    appProtocol: '1.0.0',
    uiBridge: '1.0.0',
    engineCapabilities: [],
}

function update(appRequirements: ApplicationUpdate['appRequirements']): ApplicationUpdateResult {
    return {
        status: 'available',
        checkedAt: null,
        currentChannel: 'beta',
        latest: {
            version: '1.0.0-beta.5',
            tag: 'v1.0.0-beta.5',
            channel: 'beta',
            url: 'https://github.com/RentnerProxy/platform/releases/tag/v1.0.0-beta.5',
            notes: null,
            image: { status: 'verified', reference: null, digest: null, platform: 'linux/amd64' },
            compatibility: { status: 'supported', minimumVersion: null, intermediateVersion: null },
            appRequirements,
        },
    }
}

function dependencies(
    overrides: Partial<UpgradePreviewDependencies> = {},
): UpgradePreviewDependencies {
    return {
        update: mock(async () =>
            update({ status: 'verified', environment, features: BUILT_IN_FEATURE_TRANSITIONS }),
        ),
        inspectFeatures: mock(async () => []),
        checkTarget: mock(async () => []),
        ...overrides,
    }
}

describe('upgrade preview service', () => {
    test('checks installed apps only against the verified target environment', async () => {
        const checkTarget = mock(async () => [
            {
                installationId: 'app-a',
                appId: 'example.alpha',
                version: '2.0.0',
                state: 'running' as const,
                providers: [],
                target: 'incompatible' as const,
            },
        ])
        const signal = new AbortController().signal
        const deps = dependencies({ checkTarget })
        const preview = await getUpgradePreviewService(
            '1.0.0-beta.4',
            'v1.0.0-beta.5',
            signal,
            deps,
        )
        expect(deps.update).toHaveBeenCalledWith('1.0.0-beta.4')
        expect(checkTarget).toHaveBeenCalledWith(environment, signal)
        expect(preview).toMatchObject({
            status: 'blocked',
            issues: [{ kind: 'app-incompatible', installationId: 'app-a' }],
        })
    })

    test.each(['pending', 'invalid', 'unavailable'] as const)(
        'never checks local state for %s target requirements',
        async (status) => {
            const deps = dependencies({
                update: mock(async () => update({ status, environment: null, features: [] })),
            })
            expect(
                await getUpgradePreviewService(
                    '1.0.0-beta.4',
                    'v1.0.0-beta.5',
                    AbortSignal.timeout(1_000),
                    deps,
                ),
            ).toEqual({ status: 'unavailable' })
            expect(deps.inspectFeatures).not.toHaveBeenCalled()
            expect(deps.checkTarget).not.toHaveBeenCalled()
        },
    )

    test('reports no preview without an available target', async () => {
        const deps = dependencies({
            update: mock(async () => ({
                status: 'current' as const,
                checkedAt: null,
                currentChannel: 'beta' as const,
                latest: null,
            })),
        })
        expect(
            await getUpgradePreviewService(
                '1.0.0-beta.4',
                'v1.0.0-beta.5',
                AbortSignal.timeout(1_000),
                deps,
            ),
        ).toEqual({ status: 'unavailable' })
    })

    test('never previews another release than the one the dialog shows', async () => {
        const deps = dependencies()
        expect(
            await getUpgradePreviewService(
                '1.0.0-beta.4',
                'v1.0.0-beta.6',
                AbortSignal.timeout(1_000),
                deps,
            ),
        ).toEqual({ status: 'unavailable' })
        expect(deps.inspectFeatures).not.toHaveBeenCalled()
        expect(deps.checkTarget).not.toHaveBeenCalled()
    })

    test('a failed feature inspection hides the preview, a failed app check marks it incomplete', async () => {
        expect(
            await getUpgradePreviewService(
                '1.0.0-beta.4',
                'v1.0.0-beta.5',
                AbortSignal.timeout(1_000),
                dependencies({
                    inspectFeatures: mock(async () => {
                        throw new Error('database unavailable')
                    }),
                }),
            ),
        ).toEqual({ status: 'unavailable' })
        expect(
            await getUpgradePreviewService(
                '1.0.0-beta.4',
                'v1.0.0-beta.5',
                AbortSignal.timeout(1_000),
                dependencies({
                    checkTarget: mock(async () => {
                        throw new Error('app manager unavailable')
                    }),
                }),
            ),
        ).toMatchObject({ status: 'incomplete', apps: null, issues: [] })
    })
})
