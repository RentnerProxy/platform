export type WorkerLifecycle = {
    start: (signal?: AbortSignal) => void | Promise<unknown>
    stop: () => Promise<void>
}

export interface WorkerLifecycleOptions {
    maxAttempts?: number
    retryDelayMs?: number
    startupTimeoutMs?: number
    drainTimeoutMs?: number
    classifyFailure?: (error: unknown) => 'retryable' | 'terminal'
    /**
     * Decide right before the first start whether platform may run this worker at all. A false
     * result leaves the loaded worker unstarted in `handed_off`; a rejection retries like a failed load.
     */
    admit?: () => Promise<boolean>
}

/** A deadline bounds shutdown waiting, while drained retains ownership of the actual execution. */
export class WorkerDrainTimeoutError extends Error {
    constructor(readonly drained: Promise<void>) {
        super('worker_drain_timeout')
        this.name = 'WorkerDrainTimeoutError'
        // The checkpoint caller may leave while execution still owns a resource.
        void drained.catch(() => undefined)
    }
}
