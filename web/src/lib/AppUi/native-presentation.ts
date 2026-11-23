import { z } from 'zod'
import { appRecordId } from './identifiers.ts'

const text = z.string().trim().min(1).max(500)
const translatedText = z.union([
    text,
    z.strictObject({
        en: text,
        de: text.optional(),
    }),
])
const fieldName = z.string().regex(/^[A-Za-z][A-Za-z0-9_]{0,63}$/u)
const column = z.strictObject({
    field: fieldName,
    label: translatedText,
})
const field = column
    .extend({
        help: translatedText.optional(),
        minLength: z.int().min(0).max(500).optional(),
        maxLength: z.int().min(1).max(500).optional(),
        trim: z.boolean().optional(),
    })
    .refine(({ minLength, maxLength }) => (minLength ?? 0) <= (maxLength ?? 500))
const page = {
    route: appRecordId,
    label: translatedText,
    description: translatedText.optional(),
    read: appRecordId,
}

const form = z.strictObject({
    ...page,
    kind: z.literal('form'),
    write: appRecordId,
    confirm: appRecordId.optional(),
    submitLabel: translatedText,
    fields: z.array(field).min(1).max(12),
})
const table = z.strictObject({
    ...page,
    kind: z.literal('table'),
    rowsField: fieldName.optional(),
    columns: z.array(column).min(1).max(12),
})
const pageSchema = z.discriminatedUnion('kind', [form, table])
export const nativeAppPresentationSchema = z.strictObject({
    formatVersion: z.literal(1),
    pages: z.array(pageSchema).min(1).max(8),
})

export type NativeAppPresentation = z.infer<typeof nativeAppPresentationSchema>
export type NativeAppPage = z.infer<typeof pageSchema>
export type NativeAppForm = z.infer<typeof form>
export type NativeAppTable = z.infer<typeof table>
export type NativeAppText = z.infer<typeof translatedText>

export function nativeText(value: NativeAppText, locale: string): string {
    if (typeof value === 'string') return value
    return locale.split('-')[0] === 'de' ? (value.de ?? value.en) : value.en
}
