import { expect, test } from 'bun:test'

import { workerObservability } from '@/server/Foundation/worker-observability.ts'
import {
    signalLegacyFeatureOwnership,
    subscribeToLegacyFeatureOwnership,
} from '@/server/LegacyHandoff/ownership-signal.server.ts'
import { createLegacyFeatureWorkerGate } from '@/server/LegacyHandoff/worker-admission.server.ts'
import type { LegacyFeatureOwner } from '@/server/LegacyHandoff/Types/legacy-handoff.types.ts'

type Owner = LegacyFeatureOwner['owner']

/** A gate around a recording worker, with the journal, signals and poll timer in the test's hand. */
function harness(
    initial: Owner | Error,
    stop: () => Promise<void> = async () => undefined,
    start: () => void = () => undefined,
) {
    let owner: Owner | Error = initial
    const events: string[] = []
    const listeners = new Set<() => void>()
    const timers: { callback: () => void; delayMs: number }[] = []
    let reads = 0
    const gate = createLegacyFeatureWorkerGate(
        'monitoring',
        {
            start: () => {
                start()
                events.push('start')
            },
            stop: async () => {
                events.push('stop')
                await stop()
            },
        },
        {
            id: 'host_monitoring',
            pollMs: 1_000,
            readOwner: async () => {
                reads += 1
                if (owner instanceof Error) throw owner
                return owner
            },
            subscribe: (_domain, listener) => {
                listeners.add(listener)
                return () => listeners.delete(listener)
            },
            schedule: (callback, delayMs) => {
                const timer = { callback, delayMs }
                timers.push(timer)
                return () => timers.splice(timers.indexOf(timer), 1)
            },
        },
    )
    return {
        gate,
        events,
        listeners,
        timers,
        reads: () => reads,
        set: (next: Owner | Error) => {
            owner = next
        },
        signal: async () => {
            for (const listener of listeners) listener()
            // Let the coalesced reconcile settle.
            await Bun.sleep(1)
        },
        tick: async () => {
            const timer = timers.shift()
            timer?.callback()
            await Bun.sleep(1)
        },
    }
}

const state = () =>
    workerObservability.snapshot().workers.find(({ id }) => id === 'host_monitoring')?.state

test('the gate runs the worker while platform owns the domain and follows a handoff without a restart', async () => {
    const run = harness('platform')
    await run.gate.start()
    expect(run.events).toEqual(['start'])
    expect(state()).toBe('idle')
    // Running workers need no poll: a fenced writer or the handoff request signals the domain.
    expect(run.timers).toEqual([])

    run.set('handoff')
    await run.signal()
    expect(run.events).toEqual(['start', 'stop'])
    expect(state()).toBe('handed_off')
    // A held worker polls, so an abort made by another process resumes it.
    expect(run.timers.map(({ delayMs }) => delayMs)).toEqual([1_000])
    await run.tick()
    expect(run.events).toEqual(['start', 'stop'])

    run.set('platform')
    await run.tick()
    expect(run.events).toEqual(['start', 'stop', 'start'])
    expect(state()).toBe('idle')
    expect(run.timers).toEqual([])

    run.set('handoff')
    await run.signal()
    run.set('app')
    await run.signal()
    // A commit is final: the gate stops listening and polling, and never starts the worker again.
    expect(run.events).toEqual(['start', 'stop', 'start', 'stop'])
    expect(run.listeners.size).toBe(0)
    expect(run.timers).toEqual([])
    run.set('platform')
    await run.signal()
    expect(run.events).toEqual(['start', 'stop', 'start', 'stop'])

    await run.gate.stop()
    expect(run.events.at(-1)).toBe('stop')
})

test('a worker started during an open handoff stays held until the handoff is aborted', async () => {
    const run = harness('handoff')
    await run.gate.start()
    expect(run.events).toEqual([])
    expect(state()).toBe('handed_off')
    run.set('platform')
    await run.signal()
    expect(run.events).toEqual(['start'])
    await run.gate.stop()
    expect(run.events).toEqual(['start', 'stop'])
    expect(run.listeners.size).toBe(0)
})

test('an unreadable journal keeps the current state and retries on the poll', async () => {
    const run = harness(new Error('database unavailable'))
    await run.gate.start()
    expect(run.events).toEqual([])
    expect(run.timers).toHaveLength(1)
    run.set('platform')
    await run.tick()
    expect(run.events).toEqual(['start'])
    run.set(new Error('database unavailable'))
    await run.signal()
    // The worker keeps running: only a read that shows another owner stops it.
    expect(run.events).toEqual(['start'])
    await run.gate.stop()
})

test('a failed drain is settled before the worker may start again', async () => {
    let failing = true
    const run = harness('platform', async () => {
        if (failing) throw new Error('drain timeout')
    })
    await run.gate.start()
    run.set('handoff')
    await run.signal()
    expect(run.events).toEqual(['start', 'stop'])
    expect(run.timers).toHaveLength(1)
    failing = false
    run.set('platform')
    await run.tick()
    expect(run.events).toEqual(['start', 'stop', 'stop', 'start'])
    await run.gate.stop()
})

test('a worker start that throws is retried on the poll', async () => {
    let failing = true
    const run = harness('platform', undefined, () => {
        if (failing) throw new Error('start failed')
    })
    await run.gate.start()
    expect(run.events).toEqual([])
    expect(run.timers).toHaveLength(1)
    failing = false
    await run.tick()
    expect(run.events).toEqual(['start'])
    // A started worker is not started twice.
    await run.signal()
    expect(run.events).toEqual(['start'])
    await run.gate.stop()
})

test('a handoff begun during a retried drain keeps the worker stopped', async () => {
    let failing = true
    let drained: PromiseWithResolvers<void> | undefined
    const run = harness('platform', async () => {
        if (failing) throw new Error('drain timeout')
        await drained?.promise
    })
    await run.gate.start()
    run.set('handoff')
    await run.signal()
    failing = false
    drained = Promise.withResolvers()
    run.set('platform')
    await run.tick()
    expect(run.events).toEqual(['start', 'stop', 'stop'])
    // Another process begins a handoff while the drain runs; this process gets no signal.
    run.set('handoff')
    drained.resolve()
    await Bun.sleep(1)
    expect(run.events).toEqual(['start', 'stop', 'stop'])
    expect(run.timers).toHaveLength(1)
    await run.gate.stop()
})

test('a signal while a reconcile finishes still reaches the worker', async () => {
    // Land the signal at every point between the last ownership read and the reconcile cleanup.
    for (let offset = 0; offset < 12; offset += 1) {
        const run = harness('platform')
        // oxlint-disable-next-line no-await-in-loop -- Each offset runs its own gate.
        await run.gate.start()
        for (const listener of run.listeners) listener()
        for (let hop = 0; hop < offset; hop += 1)
            // oxlint-disable-next-line no-await-in-loop -- Advance one microtask at a time.
            await Promise.resolve()
        run.set('handoff')
        for (const listener of run.listeners) listener()
        // oxlint-disable-next-line no-await-in-loop -- Let every reconcile settle.
        await Bun.sleep(2)
        expect(run.events).toEqual(['start', 'stop'])
        // oxlint-disable-next-line no-await-in-loop -- See above.
        await run.gate.stop()
    }
})

test('signals during a reconcile coalesce into one more ownership read', async () => {
    const run = harness('platform')
    const started = run.gate.start()
    for (const listener of run.listeners) {
        listener()
        listener()
        listener()
    }
    await started
    await Bun.sleep(1)
    expect(run.reads()).toBe(2)
    expect(run.events).toEqual(['start'])
    // A second start of a running gate changes nothing.
    await run.gate.start()
    expect(run.reads()).toBe(2)
    await run.gate.stop()
})

test('ownership signals reach only the listeners of their domain and survive a failing one', () => {
    const calls: string[] = []
    const stopFailing = subscribeToLegacyFeatureOwnership('monitoring', () => {
        throw new Error('listener failed')
    })
    const stopMonitoring = subscribeToLegacyFeatureOwnership('monitoring', () =>
        calls.push('monitoring'),
    )
    const stopDns = subscribeToLegacyFeatureOwnership('dns', () => calls.push('dns'))
    signalLegacyFeatureOwnership(['monitoring'])
    expect(calls).toEqual(['monitoring'])
    signalLegacyFeatureOwnership()
    expect(calls).toEqual(['monitoring', 'monitoring', 'dns'])
    stopFailing()
    stopMonitoring()
    stopDns()
    signalLegacyFeatureOwnership()
    expect(calls).toEqual(['monitoring', 'monitoring', 'dns'])
})
