import { readFile } from 'node:fs/promises'
import { resolve } from 'node:path'

import { describe, expect, test } from 'bun:test'

import {
    buildReleaseAppRequirements,
    serializeReleaseAppRequirements,
} from '../../../../../.github/scripts/release/generate-release-app-requirements.ts'
import { buildReleaseReadiness } from '../../../../../.github/scripts/release/generate-release-readiness.ts'
import type { ReleaseReadinessInput } from '../../../../../.github/scripts/release/Types/release-readiness.types.ts'
import {
    APP_REQUIREMENTS_ASSET,
    APP_REQUIREMENTS_MAX_BYTES,
    APP_RUNTIME_ENVIRONMENT,
    BUILT_IN_FEATURE_TRANSITIONS,
    BUNDLED_INSTALLER_CONFIG,
} from '@/config/app-requirements.config.ts'
import { appProviderProfiles } from '@/lib/AppUi/identifiers.ts'
import {
    parseReleaseAppRequirements,
    releaseAppRequirementsSchema,
} from '@/server/Updates/app-requirements.ts'

const root = resolve(import.meta.dir, '../../../../..')

function input(overrides: Partial<ReleaseReadinessInput> = {}): ReleaseReadinessInput {
    return {
        repository: 'RentnerProxy/platform',
        releaseId: '257',
        tag: 'v1.0.0-beta.4',
        channel: 'beta',
        prerelease: 'true',
        publishedAt: '2026-11-25T12:34:56Z',
        revision: 'a'.repeat(40),
        image: 'ghcr.io/rentnerproxy/platform',
        digest: 'sha256:' + 'b'.repeat(64),
        platforms: 'linux/amd64,linux/arm64',
        ...overrides,
    }
}

const bundledInstaller = async (): Promise<unknown> =>
    JSON.parse(await readFile(resolve(root, BUNDLED_INSTALLER_CONFIG), 'utf8'))

describe('release app requirements generation', () => {
    test('describes this release from its pinned sources and passes the reader', async () => {
        const installer = await bundledInstaller()
        const requirements = buildReleaseAppRequirements(input(), installer)
        expect(requirements).toEqual({
            schemaVersion: 1,
            releaseId: 257,
            tag: 'v1.0.0-beta.4',
            channel: 'beta',
            publishedAt: '2026-11-25T12:34:56Z',
            revision: 'a'.repeat(40),
            environment: {
                ...APP_RUNTIME_ENVIRONMENT,
                engineCapabilities: (installer as { engineCapabilities: string[] })
                    .engineCapabilities,
            },
            features: [...BUILT_IN_FEATURE_TRANSITIONS],
        })
        const serialized = serializeReleaseAppRequirements(requirements)
        expect(Buffer.byteLength(serialized)).toBeLessThanOrEqual(APP_REQUIREMENTS_MAX_BYTES)
        const readiness = buildReleaseReadiness(input())
        expect(
            parseReleaseAppRequirements(
                JSON.parse(serialized),
                {
                    id: 257,
                    tag: 'v1.0.0-beta.4',
                    channel: 'beta',
                    publishedAt: '2026-11-25T12:34:56Z',
                },
                readiness,
            ),
        ).toEqual(requirements)
    })

    test('lists every provider profile once, in order', () => {
        expect(BUILT_IN_FEATURE_TRANSITIONS.map(({ domain }) => domain)).toEqual([
            ...appProviderProfiles,
        ])
    })

    test.each([
        { repository: 'attacker/platform' },
        { image: 'ghcr.io/attacker/platform' },
        { releaseId: '0' },
        { tag: 'v1.0.0-rc.1' },
        { channel: 'stable' },
        { revision: 'A'.repeat(40) },
        { digest: 'sha256:short' },
    ])('refuses unbound release metadata %j', async (overrides) => {
        expect(() => buildReleaseAppRequirements(input(overrides), {})).toThrow()
        const installer = await bundledInstaller()
        expect(() => buildReleaseAppRequirements(input(overrides), installer)).toThrow()
    })

    test.each([
        {},
        { engineCapabilities: 'caddy.crowdsec.v1' },
        { engineCapabilities: ['Caddy.crowdsec.v1'] },
        { engineCapabilities: ['caddy.crowdsec.v1', 'caddy.crowdsec.v1'] },
        { engineCapabilities: ['caddy'] },
    ])('refuses an installer configuration its readers would reject: %j', (installer) => {
        expect(() => buildReleaseAppRequirements(input(), installer)).toThrow()
    })

    test('the reader refuses retired features without an app and unordered domains', () => {
        const valid = buildReleaseAppRequirements(input(), { engineCapabilities: [] })
        const [first, ...rest] = valid.features
        for (const features of [
            [{ ...first!, status: 'retired', apps: [] }, ...rest],
            [...rest, first!],
            [first!, first!, ...rest.slice(1)],
            [{ ...first!, apps: ['rentnerproxy.monitoring', 'rentnerproxy.monitoring'] }, ...rest],
        ]) {
            expect(releaseAppRequirementsSchema.safeParse({ ...valid, features }).success).toBe(
                false,
            )
        }
        expect(
            releaseAppRequirementsSchema.safeParse({
                ...valid,
                features: [
                    { ...first!, status: 'retired', apps: ['rentnerproxy.monitoring'] },
                    ...rest,
                ],
            }).success,
        ).toBe(true)
    })

    test('keeps the published environment in step with the Rust core and web runtime', async () => {
        const core = await readFile(resolve(root, 'core/src/app_install.rs'), 'utf8')
        expect(core).toContain(
            `pub(crate) const RUNTIME_PROFILE: &str = "${APP_RUNTIME_ENVIRONMENT.runtimeProfile}";`,
        )
        expect(core).toContain(
            `pub(crate) const PROTOCOL_VERSION: &str = "${APP_RUNTIME_ENVIRONMENT.platformApi}";`,
        )
        expect(APP_RUNTIME_ENVIRONMENT.appProtocol).toBe(APP_RUNTIME_ENVIRONMENT.platformApi)
        expect(APP_RUNTIME_ENVIRONMENT.uiBridge).toBe(APP_RUNTIME_ENVIRONMENT.platformApi)
        const authority = await readFile(
            resolve(root, 'web/src/server/AppRuntime/authority.server.ts'),
            'utf8',
        )
        expect(authority).toContain(
            `const appRuntimeProfile = '${APP_RUNTIME_ENVIRONMENT.runtimeProfile}'`,
        )
        expect(authority).toContain(
            `const appRuntimeVersion = '${APP_RUNTIME_ENVIRONMENT.platformApi}'`,
        )
        const dockerfile = await readFile(resolve(root, 'docker/production/Dockerfile'), 'utf8')
        expect(dockerfile).toContain(
            'COPY docker/production/apps/catalog/ /usr/share/rentnerproxy/app-catalog/',
        )
        expect(BUNDLED_INSTALLER_CONFIG).toBe('docker/production/apps/catalog/installer.json')
    })
})

const script = (name: string) => readFile(resolve(root, '.github/scripts/release', name), 'utf8')

test('publishes app requirements with readiness, pins their sources and clears them on rebuild', async () => {
    const readiness = await script('publish-release-readiness.sh')
    const generateReadiness = readiness.indexOf(
        'bun --no-env-file "$script_directory/generate-release-readiness.ts"',
    )
    const generateRequirements = readiness.indexOf(
        'bun --no-env-file "$script_directory/generate-release-app-requirements.ts"',
    )
    const validateOnly = readiness.indexOf('--validate-only ]]; then exit 0; fi')
    const upload = readiness.indexOf('gh release upload')
    expect(generateRequirements).toBeGreaterThan(generateReadiness)
    expect(validateOnly).toBeGreaterThan(generateRequirements)
    expect(upload).toBeGreaterThan(validateOnly)
    // Readers that see readiness must already find the requirements: two sequential uploads.
    const readinessUpload = readiness.indexOf('gh release upload', upload + 1)
    expect(readiness.slice(upload, readinessUpload)).toContain(APP_REQUIREMENTS_ASSET)
    expect(readiness.slice(upload, readinessUpload)).not.toContain('rentnerproxy-update.json')
    expect(readiness.slice(readinessUpload)).toContain('rentnerproxy-update.json')
    expect(readiness.slice(readinessUpload)).not.toContain(APP_REQUIREMENTS_ASSET)
    expect(await script('publish-building-release.sh')).toContain(`'${APP_REQUIREMENTS_ASSET}'`)
    const policy = await script('verify-compatibility-policy-source.ts')
    expect(policy).toContain("'web/src/config/app-requirements.config.ts'")
    expect(policy).toContain(`'${BUNDLED_INSTALLER_CONFIG}'`)
})
