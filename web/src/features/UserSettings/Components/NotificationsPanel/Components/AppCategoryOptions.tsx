import OptionToggle from '@/shared/Forms/OptionToggle.tsx'
import useTranslationStore from '@/shared/Language/Hooks/useTranslationStore.ts'
import type { AppCategoryOptionsProps } from '../Types/notifications-panel.types.ts'

export default function AppCategoryOptions(props: AppCategoryOptionsProps) {
    const { t } = useTranslationStore()
    return (
        <fieldset disabled={props.disabled} className="grid gap-3">
            <legend className="mb-1 text-sm font-bold text-ink">
                {t('account.notifications.appCategories')}
            </legend>
            <p className="text-sm text-muted">{t('account.notifications.appCategoriesHint')}</p>
            {props.groups.map((group) => (
                <div key={group.appId} className="grid gap-2">
                    <p className="text-sm font-bold text-ink">{group.appName}</p>
                    <div className="flex flex-wrap gap-2">
                        {group.categories.map((category) => (
                            <OptionToggle
                                key={category.key}
                                label={category.name}
                                checked={props.selected.includes(category.key)}
                                onChange={(event) =>
                                    props.onToggle(category.key, event.target.checked)
                                }
                            />
                        ))}
                    </div>
                </div>
            ))}
            {props.unavailable.length > 0 ? (
                <div className="grid gap-2">
                    <p className="text-sm font-bold text-ink">
                        {t('account.notifications.appCategoriesUnavailable')}
                    </p>
                    <div className="flex flex-wrap gap-2">
                        {props.unavailable.map((key) => (
                            <OptionToggle
                                key={key}
                                label={key}
                                checked
                                onChange={(event) => props.onToggle(key, event.target.checked)}
                            />
                        ))}
                    </div>
                </div>
            ) : null}
        </fieldset>
    )
}
