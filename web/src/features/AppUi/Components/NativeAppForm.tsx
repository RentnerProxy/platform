import { TextInput } from '@rentnerkev/inputs'
import { toast } from '@rentnerkev/toasts'
import { CustomTooltip } from '@rentnerkev/tooltips/tooltip'
import { useMutation, useQueryClient } from '@tanstack/react-query'
import { Info } from 'lucide-react'
import { useEffect, useEffectEvent, useId, useRef, useState } from 'react'

import { nativeText, type NativeAppForm as Form } from '@/lib/AppUi/native-presentation.ts'
import { buttonClassName } from '@/shared/Buttons/buttonStyles.ts'
import useTranslationStore from '@/shared/Language/Hooks/useTranslationStore.ts'
import { useAppUi } from '../AppUiProvider.tsx'
import {
    nativeReadKey,
    useNativeAppRead,
    type NativeAppSession,
} from '../Hooks/useNativeAppUiLogic.ts'

export default function NativeAppForm({
    page,
    session,
    appName,
    active,
}: {
    page: Form
    session: NativeAppSession
    appName: string
    active: boolean
}) {
    const { t, locale } = useTranslationStore()
    const ui = useAppUi()
    const queryClient = useQueryClient()
    const blockId = useId()
    const read = useNativeAppRead(session, page.read, active)
    const canRead = session.operations.includes(page.read)
    const canWrite = session.operations.includes(page.write)
    const [draft, setDraft] = useState<Record<string, string>>({})
    const [confirming, setConfirming] = useState(false)
    const intent = useRef<{ body: string; key: ReturnType<Crypto['randomUUID']> } | null>(null)
    const inProgress = useRef(false)
    const cancelConfirmation = useEffectEvent(() => ui?.cancelDialog(blockId))
    useEffect(() => () => cancelConfirmation(), [])

    const savedValues = page.fields.map(({ field }) => {
        const value = read.data && Object.hasOwn(read.data, field) ? read.data[field] : undefined
        return typeof value === 'string' ? value : undefined
    })
    const values = page.fields.map(({ field }, index) =>
        Object.hasOwn(draft, field) ? (draft[field] ?? '') : (savedValues[index] ?? ''),
    )
    const ready = canRead && savedValues.every((value) => value !== undefined)
    const prepared = page.fields.map(({ trim }, index) => {
        const value = values[index] ?? ''
        return trim ? value.trim() : value
    })
    const valid = page.fields.every(({ minLength, maxLength }, index) => {
        const size = [...(prepared[index] ?? '')].length
        return size >= (minLength ?? 0) && size <= (maxLength ?? 500)
    })
    const changed = prepared.some((value, index) => value !== savedValues[index])
    const save = useMutation({
        mutationFn: async (payload: Record<string, string>) => {
            const body = JSON.stringify(payload)
            const previous = intent.current
            const key = previous?.body === body ? previous.key : crypto.randomUUID()
            intent.current = { body, key }
            return session.handler.call(page.write, payload, AbortSignal.timeout(15_000), key)
        },
        onSuccess: async () => {
            intent.current = null
            await queryClient.invalidateQueries({
                queryKey: nativeReadKey(session, page.read),
                exact: true,
            })
            setDraft({})
            toast.success(t('appUi.saved'), { title: t('toast.titles.success') })
        },
        onError: () => toast.error(t('appUi.saveFailed'), { title: t('toast.titles.error') }),
        onSettled: () => {
            inProgress.current = false
        },
    })

    function handleSubmit() {
        if (
            !ready ||
            !canWrite ||
            !valid ||
            !changed ||
            inProgress.current ||
            (page.confirm && !ui)
        )
            return
        inProgress.current = true
        const payload = Object.fromEntries(
            page.fields.map(({ field }, index) => [field, prepared[index] ?? '']),
        )
        if (page.confirm && ui) {
            setConfirming(true)
            ui.openDialog({
                appName,
                dialogId: page.confirm,
                mount: blockId,
                settle(outcome) {
                    setConfirming(false)
                    if (outcome === 'confirmed') save.mutate(payload)
                    else inProgress.current = false
                },
            })
        } else {
            save.mutate(payload)
        }
    }

    if (!canRead || read.isError || (!read.isPending && !ready)) {
        return (
            <div className="flex items-center gap-3">
                <output className="text-sm text-muted">{t('appUi.unavailable')}</output>
                {canRead && (
                    <button
                        type="button"
                        className={buttonClassName('secondary')}
                        onClick={() => void read.refetch()}
                    >
                        {t('common.retry')}
                    </button>
                )}
            </div>
        )
    }
    const busy = save.isPending || confirming
    return (
        <form
            className="max-w-2xl rounded-2xl border border-border bg-surface p-6"
            aria-busy={read.isPending || busy}
            onSubmit={(event) => {
                event.preventDefault()
                handleSubmit()
            }}
        >
            <fieldset className="m-0 grid min-w-0 gap-5 border-0 p-0" disabled={!ready || busy}>
                {page.fields.map(({ field, label, help, maxLength }, index) => {
                    const id = blockId + '-' + field
                    const title = nativeText(label, locale)
                    return (
                        <div key={field} className="grid gap-[0.45rem]">
                            <div className="flex items-center gap-2">
                                <label
                                    className="text-[0.82rem] font-[750] text-ink-soft"
                                    htmlFor={id}
                                >
                                    {title}
                                </label>
                                {help && (
                                    <CustomTooltip content={nativeText(help, locale)}>
                                        <button
                                            type="button"
                                            aria-label={nativeText(help, locale)}
                                            className="inline-flex rounded-md p-1 text-muted hover:text-ink focus-visible:outline-2 focus-visible:outline-accent-ring"
                                        >
                                            <Info className="size-4" aria-hidden="true" />
                                        </button>
                                    </CustomTooltip>
                                )}
                            </div>
                            <TextInput
                                id={id}
                                value={values[index] ?? ''}
                                readOnly={!canWrite}
                                maxLength={(maxLength ?? 500) * 2}
                                onValueChange={(value) =>
                                    setDraft((old) => ({
                                        ...old,
                                        [field]: [...value].slice(0, maxLength ?? 500).join(''),
                                    }))
                                }
                            />
                        </div>
                    )
                })}
                {canWrite && (
                    <div>
                        <button
                            type="submit"
                            disabled={!valid || !changed || busy || Boolean(page.confirm && !ui)}
                            className={buttonClassName('primary')}
                        >
                            {save.isPending
                                ? t('common.saving')
                                : nativeText(page.submitLabel, locale)}
                        </button>
                    </div>
                )}
            </fieldset>
            {read.isPending && (
                <output className="mt-3 block text-sm text-muted">{t('appUi.loading')}</output>
            )}
        </form>
    )
}
