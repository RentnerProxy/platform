import { z } from 'zod'
import { LEGACY_HANDOFF_LIMITS } from '@/config/legacy-handoff.config.ts'
import { appProviderProfileSchema, appRecordId } from '@/lib/AppUi/identifiers.ts'

export {
    appIdSchema,
    appProviderProfiles,
    appProviderProfileSchema,
    appProviderProfilesSchema,
    appRecordId,
} from '@/lib/AppUi/identifiers.ts'

// Platform's request schemas follow the Marketplace App API v1 contract.
export const appRpcLimits = {
    jsonBytes: 1_048_576,
    jsonDepth: 64,
    requestMs: 10_000,
} as const

export const appGenerationSchema = z.number().int().min(1).max(Number.MAX_SAFE_INTEGER)
export const appUidSchema = z.number().int().min(20_000).max(59_999)
export const appCursorSchema = z.string().regex(/^[A-Za-z0-9_-]{1,256}$/u)
export const appDelegationSchema = z.string().regex(/^[A-Za-z0-9_-]{16,256}$/u)

export const appCapabilitySchema = z.discriminatedUnion('id', [
    z.strictObject({ id: z.literal('proxy.hosts.read.v1'), scope: z.literal('proxyHosts') }),
    z.strictObject({
        id: z.literal('proxy.hosts.manage-owned.v1'),
        scope: z.literal('ownedProxyHosts'),
    }),
    z.strictObject({
        id: z.literal('diagnostics.upstream.probe.v1'),
        scope: z.literal('proxyHosts'),
    }),
    z.strictObject({ id: z.literal('notifications.publish.v1'), scope: z.literal('installation') }),
    z.strictObject({
        id: z.literal('docker.inventory.observe.v1'),
        scope: z.literal('dockerConnections'),
    }),
    z.strictObject({ id: z.literal('dns.challenge.manage.v1'), scope: z.literal('dnsZones') }),
    z.strictObject({
        id: z.literal('engine.contributions.submit.v1'),
        scope: z.literal('ownedEngineResources'),
    }),
    z.strictObject({
        id: z.literal('identity.provider.register.v1'),
        scope: z.literal('identityProviders'),
    }),
    z.strictObject({ id: z.literal('access.logs.read.v1'), scope: z.literal('proxyHosts') }),
    z.strictObject({
        id: z.literal('security.enforcement.contribute.v1'),
        scope: z.literal('ownedEngineResources'),
    }),
])

export const appProviderRegistrationSchema = z.strictObject({
    id: appRecordId,
    profile: appProviderProfileSchema,
    version: z.literal('1.0.0'),
})
export const appProviderRegistrationsSchema = z
    .array(appProviderRegistrationSchema)
    .min(1)
    .max(32)
    .refine((providers) => new Set(providers.map(({ id }) => id)).size === providers.length)

const hostname = z
    .string()
    .max(253)
    .regex(/^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/u)

export const appAuthorizationRequest = z.strictObject({
    capability: appCapabilitySchema,
    resourceId: appRecordId,
})
export const appProxyHostQuery = z.strictObject({
    limit: z.number().int().min(1).max(100),
    cursor: appCursorSchema.optional(),
})
export const appProxyHostChange = z.discriminatedUnion('action', [
    z.strictObject({
        action: z.literal('upsert'),
        hostId: appRecordId,
        expectedRevision: appRecordId.nullable(),
        hostname,
        upstream: z.strictObject({
            scheme: z.enum(['http', 'https']),
            address: z.union([z.ipv4(), z.ipv6(), hostname]),
            port: z.number().int().min(1).max(65_535),
        }),
    }),
    z.strictObject({
        action: z.literal('remove'),
        hostId: appRecordId,
        expectedRevision: appRecordId,
    }),
])
export const appUpstreamProbe = z.strictObject({
    hostId: appRecordId,
    timeoutMs: z.number().int().min(1).max(10_000),
})
export const appNotification = z.strictObject({
    category: appRecordId,
    severity: z.enum(['info', 'warning', 'error']),
    title: z.string().regex(/^[^\p{Cc}\p{Cs}]{1,80}$/u),
    message: z.string().regex(/^[^\p{Cc}\p{Cs}]{1,400}$/u),
})
const appLegacyHandoffDigest = z.string().regex(/^[a-f0-9]{64}$/u)
export const appLegacyHandoffPartRequest = z.strictObject({
    digest: appLegacyHandoffDigest,
    sequence: z
        .number()
        .int()
        .min(0)
        .max(LEGACY_HANDOFF_LIMITS.maximumParts - 1),
})
export const appLegacyHandoffCommit = z.strictObject({ digest: appLegacyHandoffDigest })
export const appAuditEvent = z.strictObject({
    action: appRecordId,
    outcome: z.enum(['succeeded', 'rejected', 'failed']),
    resourceId: appRecordId.optional(),
})

export type AppNotificationInput = z.infer<typeof appNotification>
export type AppAuditEventInput = z.infer<typeof appAuditEvent>

/** Bound decoded JSON before validating the v1 shapes or using any member. */
export function isAppWireJson(value: unknown, depth = 0): boolean {
    if (value === null || typeof value === 'boolean') return true
    if (typeof value === 'number') return Math.abs(value) <= Number.MAX_SAFE_INTEGER
    if (typeof value === 'string') return !/\p{Cs}/u.test(value)
    if (typeof value !== 'object' || depth >= appRpcLimits.jsonDepth) return false
    if (Array.isArray(value)) {
        return value.every((item: unknown) => isAppWireJson(item, depth + 1))
    }
    return Object.entries(value).every(
        ([key, member]) => !/\p{Cs}/u.test(key) && isAppWireJson(member, depth + 1),
    )
}
