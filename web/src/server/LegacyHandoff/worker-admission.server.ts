import '@tanstack/react-start/server-only'

import { LEGACY_HANDOFF_LIMITS } from '@/config/legacy-handoff.config.ts'
import { runDetachedTask } from '@/lib/Async/runDetachedTask.ts'
import { getAuthDatabase } from '@/server/Auth/Core/database.server.ts'
import { workerObservability } from '@/server/Foundation/worker-observability.ts'
import { subscribeToLegacyFeatureOwnership } from './ownership-signal.server.ts'
import { readLegacyFeatureOwnerInTransaction } from './ownership.server.ts'
import type {
    LegacyFeatureGatedWorker,
    LegacyFeatureWorkerGateOptions,
} from './Types/legacy-handoff-worker.types.ts'
import type { LegacyFeatureDomain, LegacyFeatureOwner } from './Types/legacy-handoff.types.ts'

export async function readLegacyFeatureOwner(
    domain: LegacyFeatureDomain,
): Promise<LegacyFeatureOwner['owner']> {
    const ownership = await getAuthDatabase().transaction((transaction) =>
        readLegacyFeatureOwnerInTransaction(transaction, domain),
    )
    return ownership.owner
}

/**
 * Admit a built-in worker only while platform owns its domain. Once an app holds the domain, a
 * restart or a downgrade to any image with this check never starts a second productive copy.
 */
export async function isLegacyFeaturePlatformOwned(domain: LegacyFeatureDomain): Promise<boolean> {
    return (await readLegacyFeatureOwner(domain)) === 'platform'
}

/**
 * Whether an app committed the domain. Only a committed handoff ends a built-in worker for good: a
 * gated worker started during an open handoff stays held and resumes if the handoff is aborted.
 */
export async function isLegacyFeatureAppOwned(domain: LegacyFeatureDomain): Promise<boolean> {
    return (await readLegacyFeatureOwner(domain)) === 'app'
}

function scheduleTimer(callback: () => void, delayMs: number): () => void {
    const timer = setTimeout(callback, delayMs)
    timer.unref()
    return () => clearTimeout(timer)
}

/**
 * Run a built-in worker only while platform owns its domain, without a restart in between. A begun
 * handoff stops the worker and keeps it stopped; an abort starts it again with its untouched state;
 * a commit ends the gate. Ownership is re-read on every signal of the domain (a handoff request in
 * this process, or a writer the fence turned away) and, while the worker is held, on a slow poll
 * that also catches handoffs aborted by another process. The fence on every writer stays the
 * guarantee: the gate only keeps a worker from doing work the fence would discard.
 */
export function createLegacyFeatureWorkerGate(
    domain: LegacyFeatureDomain,
    worker: LegacyFeatureGatedWorker,
    options: LegacyFeatureWorkerGateOptions = {},
) {
    const readOwner = options.readOwner ?? readLegacyFeatureOwner
    const subscribe = options.subscribe ?? subscribeToLegacyFeatureOwnership
    const schedule = options.schedule ?? scheduleTimer
    const pollMs = options.pollMs ?? LEGACY_HANDOFF_LIMITS.workerOwnershipPollMs
    let active = false
    let running = false
    // A failed drain leaves the worker stopping; it must settle before the worker may start again.
    let unsettledStop = false
    let reconciling: Promise<void> | null = null
    let dirty = false
    let cancelPoll: (() => void) | null = null
    let unsubscribe: (() => void) | null = null

    const state = (value: 'idle' | 'handed_off') => {
        if (options.id) workerObservability.state(options.id, value)
    }
    const stopPolling = () => {
        cancelPoll?.()
        cancelPoll = null
    }
    // Reconcile settles every failure itself; the detached run only owns an unexpected one.
    const reconcileDetached = () =>
        runDetachedTask(
            () => reconcile(),
            () => console.error('[legacy-handoff] Worker gate failed'),
        )
    const poll = () => {
        if (!active || cancelPoll) return
        cancelPoll = schedule(() => {
            cancelPoll = null
            reconcileDetached()
        }, pollMs)
    }
    const stopWorker = async () => {
        running = false
        unsettledStop = true
        await worker.stop()
        unsettledStop = false
    }

    async function apply(): Promise<void> {
        const owner = await readOwner(domain)
        if (!active) return
        if (owner === 'platform') {
            stopPolling()
            if (running) return
            if (unsettledStop) {
                await stopWorker()
                // A handoff may have begun during the drain, also in another process: read again.
                return apply()
            }
            // Only a start that returned counts; a throwing one is retried on the poll.
            worker.start()
            running = true
            state('idle')
            return
        }
        if (running || unsettledStop) await stopWorker()
        state('handed_off')
        if (owner === 'app') {
            // A committed handoff is final; nothing could hand the domain back to platform.
            stopPolling()
            unsubscribe?.()
            unsubscribe = null
            return
        }
        poll()
    }

    /** Apply ownership one change at a time; a signal during a run schedules exactly one more. */
    function reconcile(): Promise<void> {
        if (reconciling) {
            dirty = true
            return reconciling
        }
        reconciling = (async () => {
            for (;;) {
                dirty = false
                try {
                    // oxlint-disable-next-line no-await-in-loop -- Ownership changes apply in order.
                    await apply()
                } catch {
                    // An unreadable journal or a failed drain keeps the current state until the poll.
                    stopPolling()
                    poll()
                }
                // A signal or a stop may have arrived while apply() waited.
                if (!dirty || !active) return
            }
        })().finally(() => {
            reconciling = null
            // A signal between the last pass and this cleanup found the old run and set `dirty`.
            if (dirty && active) reconcileDetached()
        })
        return reconciling
    }

    return {
        start(): Promise<void> {
            if (active) return reconciling ?? Promise.resolve()
            active = true
            unsubscribe = subscribe(domain, reconcileDetached)
            return reconcile()
        },
        /** Drain the worker on every stop, also a held one, so shutdown settles all it owns. */
        async stop(): Promise<void> {
            active = false
            unsubscribe?.()
            unsubscribe = null
            stopPolling()
            await reconciling
            await stopWorker()
        },
    }
}
