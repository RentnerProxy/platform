export const LEGACY_HANDOFF_LIMITS = {
    // Each part must later fit into one App API response with room for its envelope.
    partBytes: 262_144,
    maximumParts: 1_024,
    // Two-key advisory locks: this class plus the domain's position in the profile list.
    advisoryLockClass: 7_421_917,
} as const

export const LEGACY_HANDOFF_DIGEST_LABEL = 'rentnerproxy-legacy-feature-handoff-v1'
