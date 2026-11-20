import type { KeyboardEvent } from 'react'
import useTranslationStore from '@/shared/Language/Hooks/useTranslationStore.ts'
import type { ProxyHostFormTabsProps } from '../Types/form-sections.types.ts'

export default function ProxyHostFormTabs({
    activeTab,
    formId,
    tabs,
    invalidTabs,
    isPending,
    setActiveTab,
    apps,
    activeApp,
    selectApp,
}: ProxyHostFormTabsProps) {
    const { t } = useTranslationStore()
    const entries = [
        ...tabs.map((tab) => ({
            id: tab,
            label: t(`admin.proxyHosts.form.tabs.${tab}`),
            active: !activeApp && activeTab === tab,
            invalid: invalidTabs.includes(tab),
            select: () => setActiveTab(tab),
        })),
        ...apps.map((app) => ({
            id: `app-${app.installationId}`,
            label: app.name,
            active: activeApp === app.installationId,
            invalid: false,
            select: () => selectApp(app.installationId),
        })),
    ]

    function handleTabKeyDown(event: KeyboardEvent<HTMLButtonElement>, index: number) {
        const last = entries.length - 1
        const target = {
            ArrowRight: index === last ? 0 : index + 1,
            ArrowLeft: index === 0 ? last : index - 1,
            Home: 0,
            End: last,
        }
        if (!Object.hasOwn(target, event.key)) return
        const next = entries[target[event.key as keyof typeof target]]
        if (!next) return
        event.preventDefault()
        next.select()
        document.getElementById(`${formId}-tab-${next.id}`)?.focus()
    }

    return (
        <div
            role="tablist"
            aria-label={t('admin.proxyHosts.form.tabs.label')}
            className="flex gap-1 overflow-x-auto py-1"
        >
            {entries.map((tab, index) => (
                <button
                    key={tab.id}
                    id={`${formId}-tab-${tab.id}`}
                    type="button"
                    role="tab"
                    aria-selected={tab.active}
                    aria-controls={`${formId}-panel-${tab.id}`}
                    aria-describedby={tab.invalid ? `${formId}-tab-error` : undefined}
                    data-invalid={tab.invalid}
                    tabIndex={tab.active ? 0 : -1}
                    disabled={isPending}
                    className={`min-h-10 flex-1 shrink-0 cursor-pointer whitespace-nowrap rounded-lg border px-3 py-2 text-sm font-bold transition-colors focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-accent-ring disabled:cursor-not-allowed disabled:opacity-50 motion-reduce:transition-none ${tab.active ? 'border-accent-border bg-accent-muted text-accent-ring' : 'border-transparent text-muted hover:border-border-strong hover:bg-surface-hover hover:text-ink'}`}
                    onClick={tab.select}
                    onKeyDown={(event) => handleTabKeyDown(event, index)}
                >
                    {tab.label}
                    {tab.invalid ? (
                        <span
                            aria-hidden="true"
                            className="ml-2 inline-flex size-4 items-center justify-center rounded-full bg-danger-bg text-xs font-extrabold text-danger-text"
                        >
                            !
                        </span>
                    ) : null}
                </button>
            ))}
            {invalidTabs.length > 0 ? (
                <span id={`${formId}-tab-error`} className="sr-only">
                    {t('admin.proxyHosts.form.tabs.hasErrors')}
                </span>
            ) : null}
        </div>
    )
}
