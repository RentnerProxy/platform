export const HOST_MONITORING_LIMITS = {
    maxPolicies: 1_000,
    maxActiveClaims: 64,
    workerConcurrency: 64,
    claimBatchSize: 16,
    persistenceBatchSize: 16,
    persistenceDelayMs: 25,
    pollIntervalMs: 250,
    idlePollMaximumMs: 30_000,
    leaseMs: 45_000,
    transactionTimeoutMs: 2_000,
    // A global ceiling, not a minimum history promise: 1,000 policies receive at most 100 samples each after fair pruning.
    maxObservations: 100_000,
    maxIncidents: 10_000,
    historyLimit: 100,
    inputLimitBytes: 4_096,
    retentionSweepMs: 60_000,
    retentionDeleteLimit: 4_096,
    retentionPolicyPageSize: 8,
    advisoryLockId: 7_421_916,
} as const

/**
 * The monitoring legacy handoff export. `Types/host-monitoring-handoff.types.ts` documents the
 * format; a new column or kind needs a new version.
 */
export const HOST_MONITORING_HANDOFF = {
    format: 'rentnerproxy.monitoring',
    version: 1,
    // Rows fetched per cursor read. Parts are cut by bytes, so this bounds memory, not the format.
    fetchRows: 8_192,
    columns: {
        policies: [
            'id',
            'proxyHostId',
            'domain',
            'enabled',
            'intervalSeconds',
            'timeoutMs',
            'expectedStatus',
            'failureThreshold',
            'recoveryThreshold',
            'retentionDays',
            'sampleLimit',
            'incidentLimit',
            'version',
            'state',
            'failureCount',
            'recoveryCount',
            'failureStartedAt',
            'recoveryStartedAt',
            'lastCheckedAt',
            'lastOutcome',
            'lastCode',
            'lastDurationMs',
            'lastHttpStatus',
            'nextCheckAt',
            'createdAt',
            'updatedAt',
        ],
        observations: [
            'id',
            'policyId',
            'policyVersion',
            'checkedAt',
            'status',
            'code',
            'durationMs',
            'httpStatus',
        ],
        incidents: [
            'id',
            'policyId',
            'startedAt',
            'detectedAt',
            'recoveryStartedAt',
            'recoveredAt',
            'failureCode',
            'recoveryCode',
            'closedReason',
            'closedAt',
        ],
    },
} as const

export const HOST_MONITORING_DEFAULTS = {
    enabled: false,
    intervalSeconds: 60,
    timeoutMs: 3_000,
    expectedStatus: 200,
    failureThreshold: 3,
    recoveryThreshold: 2,
    // Time/count settings are upper bounds; the global fair-share budget may retain fewer samples.
    retentionDays: 7,
    sampleLimit: 1_440,
    incidentLimit: 100,
} as const

export const HOST_MONITORING_WRITE_RATE_LIMIT = {
    limit: 20,
    windowMs: 60_000,
    scope: 'host-monitoring-policy',
} as const

export const HOST_MONITORING_OUTCOME_CODES = [
    'expected_status',
    'unexpected_status',
    'upstream_unreachable',
    'upstream_timeout',
    'upstream_dns_failed',
    'tls_failed',
    'configuration_stale',
    'configuration_changed',
    'host_not_active',
    'runtime_unavailable',
    'busy',
    'invalid_response',
] as const
