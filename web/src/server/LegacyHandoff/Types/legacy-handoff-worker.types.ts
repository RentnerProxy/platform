import type { BackgroundWorkerId } from '@/server/Foundation/Types/worker-observability.types.ts'
import type { LegacyFeatureDomain, LegacyFeatureOwner } from './legacy-handoff.types.ts'

/** The part of a built-in worker a gate drives; a stopped worker must accept a later start. */
export interface LegacyFeatureGatedWorker {
    start(): void
    stop(): Promise<void>
}

export interface LegacyFeatureWorkerGateOptions {
    /** Reports `handed_off` while the gate holds the worker and `idle` once it resumes. */
    readonly id?: BackgroundWorkerId
    readonly readOwner?: (domain: LegacyFeatureDomain) => Promise<LegacyFeatureOwner['owner']>
    readonly subscribe?: (domain: LegacyFeatureDomain, listener: () => void) => () => void
    readonly schedule?: (callback: () => void, delayMs: number) => () => void
    readonly pollMs?: number
}
