import type { z } from 'zod'

import type { deploymentSchema } from '../validation.ts'

export type DeploymentSettings = z.infer<typeof deploymentSchema>

export type StateArchiveEntry = Readonly<{
    name: string
    directory: boolean
    bytes: Uint8Array
}>

export type StateArchiveFileEntry = Readonly<{
    name: string
    directory: boolean
    bodyOffset: number
    size: number
}>

export type AppStateValidationOptions = Readonly<{
    target?: string | undefined
    signal?: AbortSignal | undefined
    progress?: (() => void) | undefined
    checkCapacity?: (() => Promise<void>) | undefined
}>

import type { metadataSchema } from '../validation.ts'

export type BackupMetadata = z.infer<typeof metadataSchema>
