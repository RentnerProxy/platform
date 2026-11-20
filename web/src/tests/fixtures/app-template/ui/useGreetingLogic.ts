import { useEffect, useRef, useState } from 'react'

import { connectGreetingBridge, type Context } from './bridge.ts'

const copy = {
    en: {
        app: 'Greeting',
        details: 'Details',
        overview: 'Overview',
        field: 'New greeting',
        save: 'Save greeting',
        waiting: 'Waiting for the app…',
        busy: 'Working…',
        saved: 'Greeting saved.',
        unavailable: 'The greeting is unavailable.',
        detailsText: 'Your greeting is stored in this app installation.',
    },
    de: {
        app: 'Gruß',
        details: 'Details',
        overview: 'Übersicht',
        field: 'Neuer Gruß',
        save: 'Gruß speichern',
        waiting: 'Die App wird vorbereitet…',
        busy: 'In Arbeit…',
        saved: 'Gruß gespeichert.',
        unavailable: 'Der Gruß ist nicht verfügbar.',
        detailsText: 'Dein Gruß wird in dieser App-Installation gespeichert.',
    },
}

export function useGreetingLogic() {
    const bridge = useRef<ReturnType<typeof connectGreetingBridge> | null>(null)
    const [context, setContext] = useState<Context>()
    const [greeting, setGreeting] = useState('')
    const [draft, setDraft] = useState('')
    const [busy, setBusy] = useState(false)
    const [status, setStatus] = useState<'saved' | 'unavailable'>()
    const ready = context?.ready ?? false
    const generation = context?.generation

    useEffect(() => {
        const channel = connectGreetingBridge(setContext)
        bridge.current = channel
        return () => {
            bridge.current = null
            channel.close()
        }
    }, [])

    useEffect(() => {
        document.documentElement.lang = context?.locale ?? 'en'
        document.documentElement.dataset.theme = context?.theme ?? 'light'
    }, [context?.locale, context?.theme])

    useEffect(() => {
        const channel = bridge.current
        if (!ready || generation === undefined || !channel) return
        let current = true
        void channel.greeting('get-greeting', {}).then(
            (value) => {
                if (!current) return
                setGreeting(value)
                setDraft(value)
            },
            () => {
                if (current) setStatus('unavailable')
            },
        )
        return () => {
            current = false
        }
    }, [ready, generation])

    const labels = context?.locale.toLowerCase().startsWith('de') ? copy.de : copy.en
    const disabled = busy || !ready || !draft.trim() || draft.trim() === greeting

    async function save() {
        const channel = bridge.current
        if (!channel || disabled) return
        setStatus(undefined)
        setBusy(true)
        try {
            if (!(await channel.confirmSave())) return
            const value = await channel.greeting('save-greeting', { greeting: draft.trim() })
            setGreeting(value)
            setDraft(value)
            setStatus('saved')
        } catch {
            setStatus('unavailable')
        } finally {
            setBusy(false)
        }
    }

    return {
        state: { greeting, draft, busy, status, ready, disabled, labels, route: context?.route },
        handler: {
            save,
            navigate: (route: 'overview' | 'details') => bridge.current?.navigate(route),
        },
        setter: { setDraft },
    }
}
