import type {
    AppIncidentResolution,
    NotificationCategory,
    NotificationChannelPolicy,
    NotificationDeliveryError,
    NotificationPayload,
    NotificationSeverity,
    HostAvailabilityNotification,
} from '@/lib/Notifications/Types/notifications.types.ts'

export interface NotificationEngineConfiguration {
    readonly enabled: boolean
    readonly pausedAfterRestore: boolean
    readonly channels: readonly (NotificationChannelPolicy & {
        readonly ownerUserId?: string | undefined
    })[]
}

export interface NotificationDispatch {
    readonly channelId: string
    readonly ownerUserId: string | null
    readonly kind: NotificationChannelPolicy['kind']
    readonly category: NotificationCategory
    readonly at: number
}

type NotificationDeliveryStatus = 'pending' | 'inflight' | 'succeeded' | 'failed' | 'cancelled'
type NotificationAdmissionStatus = 'pending' | 'succeeded' | 'failed'

interface NotificationIncidentChannel {
    channelId: string
    channelRevision: number
    failure: NotificationAdmissionStatus
    recovery: NotificationAdmissionStatus | null
    /** The severity of the latest delivered failure notice of an app incident; a rise notifies again. */
    severity?: NotificationSeverity | undefined
    /** A failure notice reached the channel, so it is owed a recovery even after a failed escalation. */
    notified?: true | undefined
}

export interface NotificationIncident {
    id: string
    category: NotificationCategory
    resourceId: string
    severity: NotificationSeverity
    startedAt: number
    observedAt: number
    evidence: string
    failures: number
    code?: 'certificate_renewal_manual_dns_required' | undefined
    recoveredAt: number | null
    recoveryEvidence: string | null
    channels: NotificationIncidentChannel[]
    host?: HostAvailabilityNotificationContext | undefined
    app?: AppIncidentContext | undefined
    /**
     * A built-in host outage the monitoring handoff commit froze: it admits no new outage notice,
     * while the notices it admitted before and their recoveries stay deliverable.
     */
    frozen?: true | undefined
    /** An app incident that took a frozen built-in host outage over, keyed by its incident ID. */
    continuation?: true | undefined
}

/** What an app asserted about one of its incidents, as the platform keeps it. */
export interface AppIncidentContext {
    installationId: string
    appId: string
    appName?: string | undefined
    categoryId: string
    categoryName: string
    key: string
    title: string
    message: string
    resource: { type: 'proxyHost'; proxyHostId: string } | null
    /** Set when the platform closed the incident because the app could no longer assert it. */
    resolution?: AppIncidentResolution | undefined
}

interface HostAvailabilityNotificationContext extends HostAvailabilityNotification {
    readonly policyId: string
    readonly policyVersion: string
    readonly contextProof: string
    readonly contextRevision: string
    readonly subscriptions?:
        | readonly {
              readonly channelId: string
              readonly channelRevision: number
          }[]
        | undefined
}

export interface HostAvailabilityNotificationTransition {
    readonly kind: 'outage' | 'recovery'
    readonly incidentId: string
    readonly proxyHostId: string
    readonly startedAt: number
    readonly occurredAt: number
    readonly failures: number
    readonly host: HostAvailabilityNotificationContext
}

export interface NotificationQueuedDelivery {
    id: string
    channelId: string
    channelRevision: number
    payload: NotificationPayload
    status: NotificationDeliveryStatus
    attempts: number
    backupAvailableAt?: number | undefined
    createdAt: number
    updatedAt: number
    nextAttemptAt: number
    leaseToken: string | null
    leaseExpiresAt: number | null
    error: NotificationDeliveryError | null
    dispatch?: NotificationDispatch | undefined
}

export interface NotificationState {
    version: 1
    proxyApplyPending: { desiredRevision: string; since: number; observedAt: number } | null
    incidents: NotificationIncident[]
    deliveries: NotificationQueuedDelivery[]
    deferredCount: number
    saturationCount: number
    dispatches?: NotificationDispatch[] | undefined
}

export interface NotificationClaimedDelivery {
    id: string
    channelId: string
    channelRevision: number
    payload: NotificationPayload
    leaseToken: string
}
