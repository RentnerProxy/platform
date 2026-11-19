export const BACKUP_RUNTIME_POLICY = {
    // Allow 18 seconds for app retirement and 25 seconds for consumers and state services.
    applianceStopGraceSeconds: 50,
    maximumArtifactBytes: 8 * 1024 ** 3,
    diskReserveBytes: 2 * 1024 ** 3,
    capacityCheckBytes: 16 * 1024 ** 2,
    capacityCheckIntervalMs: 1_000,
    operationTimeoutMs: 4 * 60 * 60 * 1_000,
    captureTimeoutMs: 2 * 60 * 60 * 1_000,
    databaseTimeoutMs: 2 * 60 * 60 * 1_000,
    // Outer owners allow the operation to stop and publish its durable result.
    supervisorTimeoutSeconds: 4 * 60 * 60 + 5 * 60,
    agentTimeoutMs: (4 * 60 * 60 + 10 * 60) * 1_000,
} as const
