import { z } from 'zod'
import {
    APP_INCIDENT_LIMITS,
    NOTIFICATION_CATEGORIES,
    NOTIFICATION_LIMITS,
    NOTIFICATION_SEVERITIES,
} from '@/config/notifications.config.ts'
import { HOST_MONITORING_OUTCOME_CODES } from '@/config/host-monitoring.config.ts'
import { appIdSchema, appRecordId } from '@/lib/AppUi/identifiers.ts'

export const hostAvailabilityNotificationSchema = z.strictObject({
    domain: z
        .string()
        .min(1)
        .max(253)
        .regex(/^[a-z0-9.-]+$/u),
    failureCode: z.enum(HOST_MONITORING_OUTCOME_CODES),
    detectedAt: z.iso.datetime(),
    recoveryStartedAt: z.iso.datetime().nullable(),
    managementPath: z.literal('/proxy-hosts'),
    managementUrl: z.url().max(2_048).optional(),
})

/** A qualified app incident category: `appId/categoryId`. */
const appIncidentCategoryKeySchema = z.string().refine((value) => {
    const separator = value.indexOf('/')
    return (
        separator > 0 &&
        appIdSchema.safeParse(value.slice(0, separator)).success &&
        appRecordId.safeParse(value.slice(separator + 1)).success
    )
})

/**
 * One line of plain text, counted in code points like the App API contract: no control,
 * surrogate, format, line or paragraph separator characters.
 */
export const appIncidentName = (maximum: number) =>
    z.string().regex(new RegExp(`^[^\\p{Cc}\\p{Cs}\\p{Cf}\\p{Zl}\\p{Zp}]{1,${maximum}}$`, 'u'))
/** A link-like run, found after lowercasing only ASCII letters, as both contract SDKs do. */
const linkLike = /(?:[a-z][a-z0-9+.-]*:\/\/|www\.|mailto:)/u
const isLinkLike = (value: string) =>
    linkLike.test(value.replace(/[A-Z]/gu, (letter) => letter.toLowerCase()))

/** App text renders as plain text on one line and without links, exactly as the contract admits it. */
export const appIncidentText = (maximum: number) =>
    appIncidentName(maximum).refine((value) => !isLinkLike(value))

export const appIncidentNotificationSchema = z.strictObject({
    appName: z.string().min(1).max(97),
    // The manifest admits category names by the plain line rule alone.
    categoryName: appIncidentName(APP_INCIDENT_LIMITS.title),
    title: appIncidentText(APP_INCIDENT_LIMITS.title),
    message: appIncidentText(APP_INCIDENT_LIMITS.message),
    resource: z
        .strictObject({
            type: z.literal('proxyHost'),
            hostname: z
                .string()
                .min(1)
                .max(253)
                .regex(/^[a-z0-9.-]+$/u)
                .optional(),
        })
        .optional(),
    resolution: z.enum(['appStopped', 'grantRevoked', 'resourceUnavailable']).optional(),
})

const notificationIdSchema = z.uuid().regex(/^[a-f0-9-]+$/u)
export const notificationRevisionSchema = z.number().int().min(0).max(4_294_967_295)
export const notificationPolicySchema = z.strictObject({
    id: notificationIdSchema,
    name: z
        .string()
        .trim()
        .min(1)
        .max(80)
        .regex(/^[^\p{Cc}\p{Cf}]+$/u),
    kind: z.enum(['email', 'webhook']),
    enabled: z.boolean(),
    events: z
        .array(z.enum(NOTIFICATION_CATEGORIES))
        .min(1)
        .max(NOTIFICATION_CATEGORIES.length)
        .refine((events) => new Set(events).size === events.length),
    minimumSeverity: z.enum(NOTIFICATION_SEVERITIES),
    thresholdSeconds: z.number().int().min(0).max(86_400),
    recovery: z.boolean(),
    appCategories: z
        .array(appIncidentCategoryKeySchema)
        .max(APP_INCIDENT_LIMITS.channelCategories)
        .refine((keys) => new Set(keys).size === keys.length)
        .optional(),
})

export const notificationDestinationSchema = z.discriminatedUnion('kind', [
    z.strictObject({
        kind: z.literal('email'),
        recipients: z
            .array(z.email().max(254))
            .min(1)
            .max(16)
            .refine(
                (recipients) =>
                    new Set(recipients.map((email) => email.toLowerCase())).size ===
                    recipients.length,
            ),
    }),
    z.strictObject({
        kind: z.literal('webhook'),
        url: z.string().min(1).max(2_048),
        authorizationToken: z
            .string()
            .regex(/^[\x21-\x7e]{1,2048}$/u)
            .nullable(),
        allowedPrivateCidrs: z.array(z.string().min(3).max(64)).max(16),
    }),
])

export const updateNotificationConfigurationSchema = z
    .strictObject({
        expectedRevision: notificationRevisionSchema,
        enabled: z.boolean(),
        channels: z
            .array(
                notificationPolicySchema
                    .extend({
                        destination: notificationDestinationSchema.optional(),
                    })
                    .superRefine((channel, context) => {
                        if (channel.destination && channel.destination.kind !== channel.kind)
                            context.addIssue({
                                code: 'custom',
                                message: 'Destination kind must match channel',
                            })
                    }),
            )
            .max(NOTIFICATION_LIMITS.channels),
    })
    .superRefine((configuration, context) => {
        if (
            new Set(configuration.channels.map((channel) => channel.id)).size !==
            configuration.channels.length
        )
            context.addIssue({ code: 'custom', message: 'Duplicate channel' })
    })

export const updatePersonalNotificationConfigurationSchema = z
    .strictObject({
        expectedRevision: notificationRevisionSchema,
        channels: updateNotificationConfigurationSchema.shape.channels,
        resumeDelivery: z.boolean().optional(),
    })
    .refine(
        (configuration) =>
            new Set(configuration.channels.map((channel) => channel.id)).size ===
            configuration.channels.length,
        'Duplicate channel',
    )

export const testPersonalNotificationChannelSchema = z.strictObject({
    expectedRevision: notificationRevisionSchema,
    channelId: notificationIdSchema,
})
