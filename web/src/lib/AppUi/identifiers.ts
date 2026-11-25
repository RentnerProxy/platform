import { z } from 'zod'

export const appRecordId = z.string().regex(/^[a-z0-9][a-z0-9_-]{0,63}$/u)
export const appIdSchema = z
    .string()
    .regex(/^[a-z](?:[a-z0-9-]{0,30}[a-z0-9])?\.[a-z](?:[a-z0-9-]{0,62}[a-z0-9])?$/u)

/** Provider profiles an app may offer; they match the built-in features apps can take over. */
export const appProviderProfiles = [
    'monitoring',
    'docker-discovery',
    'load-balancer',
    'dns',
    'oidc',
    'crowdsec',
] as const
export const appProviderProfileSchema = z.enum(appProviderProfiles)
/** Signed-manifest `providers`: the profiles one generation may register. */
export const appProviderProfilesSchema = z
    .array(appProviderProfileSchema)
    .max(appProviderProfiles.length)
    .refine((profiles) => new Set(profiles).size === profiles.length)
