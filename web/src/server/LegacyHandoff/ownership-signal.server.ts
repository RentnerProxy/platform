import '@tanstack/react-start/server-only'

import { appProviderProfiles } from '@/server/AppRuntime/contract.ts'
import type { LegacyFeatureDomain } from './Types/legacy-handoff.types.ts'

const listeners = new Map<LegacyFeatureDomain, Set<() => void>>()

/**
 * Follow a domain's ownership in this process. A signal carries no state: the listener re-reads the
 * journal, so a signal that arrives early, late or twice never decides ownership by itself.
 */
export function subscribeToLegacyFeatureOwnership(
    domain: LegacyFeatureDomain,
    listener: () => void,
): () => void {
    const domainListeners = listeners.get(domain) ?? new Set()
    domainListeners.add(listener)
    listeners.set(domain, domainListeners)
    return () => {
        domainListeners.delete(listener)
    }
}

/**
 * Ask the domains' listeners to re-read ownership. Call it after the transaction that began,
 * committed or aborted a handoff has ended, or when the fence turned a platform writer away.
 */
export function signalLegacyFeatureOwnership(
    domains: readonly LegacyFeatureDomain[] = appProviderProfiles,
): void {
    for (const domain of domains) {
        for (const listener of listeners.get(domain) ?? []) {
            try {
                listener()
            } catch {
                // A failing listener must not keep the others or the signalling writer from running.
            }
        }
    }
}
