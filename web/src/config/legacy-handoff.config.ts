export const LEGACY_HANDOFF_LIMITS = {
    // Each part must later fit into one App API response with room for its envelope.
    partBytes: 262_144,
    maximumParts: 1_024,
    // Two-key advisory locks: this class plus the domain's position in the profile list.
    advisoryLockClass: 7_421_917,
    // Begin and commit are idempotent through the journal, so a forgotten key only loses the
    // conflict check for its reuse. These bounds keep an app from growing the key record.
    requestKeyRetentionMs: 30 * 24 * 60 * 60 * 1_000,
    requestKeysPerInstallation: 1_024,
    // A paused built-in worker re-reads its domain this often, so an abort made by another process
    // resumes it without a restart. A committed handoff ends the polling for good.
    workerOwnershipPollMs: 15_000,
} as const

export const LEGACY_HANDOFF_DIGEST_LABEL = 'rentnerproxy-legacy-feature-handoff-v1'
