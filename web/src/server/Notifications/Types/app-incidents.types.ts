import type { NotificationSeverity } from '@/lib/Notifications/Types/notifications.types.ts'
import type { AppIncidentContext, NotificationState } from './notification-state.types.ts'

/** The installation and key by which an app names one of its incidents. */
export interface AppIncidentSubject {
    readonly installationId: string
    readonly key: string
}

export type AppIncidentChange =
    | {
          readonly kind: 'open'
          readonly severity: NotificationSeverity
          readonly app: AppIncidentContext
      }
    | { readonly kind: 'resolve'; readonly subject: AppIncidentSubject }

export interface AppIncidentOutcome {
    readonly state: NotificationState
    /** `unchanged` repeats the state the platform already keeps; the limits refuse a new incident. */
    readonly result: 'applied' | 'unchanged' | 'limit' | 'saturated'
}

/** What the app tables say about the installations and hosts of open app incidents. */
export interface AppIncidentFacts {
    readonly active: ReadonlySet<string>
    readonly grants: readonly {
        readonly installationId: string
        readonly capabilityId: string
        readonly scope: string
        readonly resourceId: string
    }[]
    /** The app's own host ID by installation and platform host ID. */
    readonly owned: ReadonlyMap<string, string>
    /** The first domain of each platform host that still exists. */
    readonly hostnames: ReadonlyMap<string, string | null>
}
