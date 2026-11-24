import '@tanstack/react-start/server-only'

import type { LegacyFeatureHandoffSources } from './Types/legacy-handoff-api.types.ts'

/**
 * Built-in features register their handoff source here once their extraction lands. Until then a
 * domain may still hold platform state that nothing can export, so `begin` refuses it.
 */
export const legacyFeatureHandoffSources: LegacyFeatureHandoffSources = Object.freeze({})
