import '@tanstack/react-start/server-only'

import {
    catalogInstallSchema,
    catalogLifecycleSchema,
    catalogSnapshotSchema,
    catalogTargetCheckSchema,
    sameCatalogLifecycle,
    sameCatalogRelease,
    type CatalogLifecycleInput,
    type CatalogSelector,
} from '@/lib/AppCatalog/contract.ts'
import type { AppRuntimeEnvironment } from '@/lib/ApplicationVersion/Types/app-requirements.types.ts'
import { nativeAppRuntimeJson, uiProblems } from '../ui/transport.server.ts'

export function nativeAppCatalog(signal: AbortSignal) {
    return nativeAppRuntimeJson(
        catalogSnapshotSchema,
        '/v1/catalog',
        signal,
        undefined,
        12 * 1024 * 1024,
    )
}

/** Ask the Rust app manager whether a target platform release would run each installed app. */
export function nativeCatalogTargetCheck(environment: AppRuntimeEnvironment, signal: AbortSignal) {
    return nativeAppRuntimeJson(
        catalogTargetCheckSchema,
        '/v1/catalog/target-check',
        signal,
        {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(environment),
        },
        256 * 1024,
    )
}

export async function nativeCatalogLifecycle(input: CatalogLifecycleInput, signal: AbortSignal) {
    const result = await nativeAppRuntimeJson(
        catalogLifecycleSchema,
        '/v1/catalog/lifecycle',
        signal,
        {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(input),
        },
        1_024,
    )
    if (result.status !== 'pending' || !sameCatalogLifecycle(result, input))
        throw uiProblems.unavailable
    return result
}

export async function nativeCatalogInstall(input: CatalogSelector, signal: AbortSignal) {
    const result = await nativeAppRuntimeJson(
        catalogInstallSchema,
        '/v1/catalog/install',
        signal,
        {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(input),
        },
        1_024,
    )
    if (!sameCatalogRelease(result, input)) throw uiProblems.unavailable
    return result
}
