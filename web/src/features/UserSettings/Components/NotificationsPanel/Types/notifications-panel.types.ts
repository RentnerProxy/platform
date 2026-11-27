import type { AuthenticatedUser } from '@/lib/Auth/Types/auth.types.ts'
import type {
    AppIncidentCategoryGroup,
    NotificationConfiguration,
    NotificationCategory,
    PersonalNotificationSettings,
    NotificationStatus,
} from '@/lib/Notifications/Types/notifications.types.ts'
import type { z } from 'zod'
import type { updatePersonalNotificationConfigurationSchema } from '@/lib/Notifications/validation.ts'

export type Channel = NotificationConfiguration['channels'][number]
export type ChannelInput = z.infer<
    typeof updatePersonalNotificationConfigurationSchema
>['channels'][number]
export interface NotificationsPanelProps {
    user: AuthenticatedUser
    active: boolean
}
export interface ChannelEditorState {
    channel: Channel | null
    revision: number
    channels: readonly Channel[]
}
export interface ChannelEditorProps {
    editor: ChannelEditorState
    settings: PersonalNotificationSettings
    /** The app categories a channel can subscribe to; undefined until they are loaded. */
    appCategories?: readonly AppIncidentCategoryGroup[] | undefined
    email: string
    pending: boolean
    onClose: () => void
    onSave: (channel: ChannelInput, editor: ChannelEditorState) => Promise<boolean>
}
export interface DeliveryTableProps {
    status: NotificationStatus
    channels: readonly Channel[]
}
export type DeliveryRow = NotificationStatus['deliveries'][number] & {
    channelName: string
    incidentState: string
}
export interface ChannelFormValues {
    name: string
    kind: 'email' | 'webhook'
    enabled: boolean
    events: NotificationCategory[]
    minimumSeverity: 'warning' | 'error' | 'critical'
    thresholdSeconds: string
    recovery: boolean
    appCategories: string[]
    replaceDestination: boolean
    recipients: string
    url: string
    token: string
    cidrs: string
}
export interface AppCategoryOptionsProps {
    groups: readonly AppIncidentCategoryGroup[]
    selected: readonly string[]
    /** Subscriptions of apps that are no longer available, listed so they can be cleared. */
    unavailable: readonly string[]
    disabled: boolean
    onToggle: (key: string, checked: boolean) => void
}
