import { z } from 'zod'
import { BACKUP_RUNTIME_POLICY } from '../../web/src/config/backup-runtime.config.ts'
import { APP_AWARE_BACKUP_VERSION } from '../../web/src/config/compatibility.config.ts'

const digest = z.string().regex(/^[a-f0-9]{64}$/u)

const artifact = z.strictObject({
    bytes: z.number().int().positive().max(BACKUP_RUNTIME_POLICY.maximumArtifactBytes),
    sha256: digest,
})

const database = artifact.extend({
    database: z.literal('rentnerproxy'),
    dump: z.literal('postgres.dump'),
    user: z.literal('rentnerproxy'),
})

const key = artifact.extend({ file: z.literal('app-encryption-key') })

const controller = artifact.extend({ archive: z.literal('controller-state.tar') })

const base = {
    applicationEncryptionKey: key,
    controllerState: controller,
    createdAt: z.iso.datetime(),
    format: z.literal('rentnerproxy-production-backup'),
    postgres: database,
    redis: z.literal('excluded'),
}

export const deploymentSchema = z.strictObject({
    publicOrigin: z.string().url().max(4096),
    trustedProxyCidrs: z.string().max(8192),
})

const metadata = z.strictObject({
    ...base,

    crowdSecState: artifact.extend({ archive: z.literal('crowdsec-state.tar') }),
    deployment: deploymentSchema,
    source: z.union([
        z.strictObject({
            imageId: z.string().regex(/^sha256:[a-f0-9]{64}$/u),
            revision: z.string().max(128).nullable(),
            version: z.string().max(128).nullable(),
        }),
        z.strictObject({
            imageId: z.null(),
            revision: z
                .string()
                .regex(/^[a-f0-9]{40}$/u)
                .nullable(),
            version: z.string().min(1).max(128),
            buildSha256: digest,
        }),
    ]),
})

export const appBackupInstallations = z
    .array(
        z.strictObject({
            id: z.string().regex(/^[a-z0-9][a-z0-9_-]{0,63}$/u),
            appId: z.string().min(1).max(98),
            uid: z.number().int().min(20000).max(59999),
            generation: z.number().int().nonnegative().max(Number.MAX_SAFE_INTEGER),
            authorityRecorded: z.boolean().optional(),
        }),
    )
    .min(1)
    .max(256)

export const metadataSchema = z.discriminatedUnion('version', [
    metadata.extend({ version: z.literal(4) }),
    metadata.extend({
        version: z.literal(APP_AWARE_BACKUP_VERSION),
        applications: artifact.extend({
            bytes: z.number().int().positive().max(BACKUP_RUNTIME_POLICY.maximumAppStateBytes),
            installations: appBackupInstallations,
        }),
    }),
])
