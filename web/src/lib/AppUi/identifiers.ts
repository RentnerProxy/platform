import { z } from 'zod'

export const appRecordId = z.string().regex(/^[a-z0-9][a-z0-9_-]{0,63}$/u)
export const appIdSchema = z
    .string()
    .regex(/^[a-z](?:[a-z0-9-]{0,30}[a-z0-9])?\.[a-z](?:[a-z0-9-]{0,62}[a-z0-9])?$/u)
