import { CustomSelect } from '@rentnerkev/select/select'
import type { CatalogProxyHost } from '@/lib/AppCatalog/grantApproval.ts'
import useTranslationStore from '@/shared/Language/Hooks/useTranslationStore.ts'

/** Select the proxy hosts an app may use for one capability; at least one is required. */
export default function GrantHostPicker({
    id,
    hosts,
    value,
    loading,
    failed,
    onChange,
}: {
    id: string
    hosts: readonly CatalogProxyHost[]
    value: readonly string[]
    loading: boolean
    failed: boolean
    onChange: (ids: string[]) => void
}) {
    const { t } = useTranslationStore()
    const empty = !loading && !failed && hosts.length === 0

    return (
        <div className="grid min-w-0 gap-1.5">
            <CustomSelect
                id={id}
                label={t('appCatalog.grants.hosts.label')}
                multiple
                searchable
                textOverflow="wrap"
                value={[...value]}
                options={hosts.map((host) => ({
                    value: host.id,
                    label: host.enabled
                        ? host.hostname
                        : t('appCatalog.grants.hosts.disabled', { hostname: host.hostname }),
                }))}
                onValueChange={onChange}
                disabled={loading || failed || empty}
                placeholder={t('appCatalog.grants.hosts.placeholder')}
                aria-invalid={value.length === 0}
                messages={{
                    searchPlaceholder: t('appCatalog.grants.hosts.search'),
                    noResults: t('table.noResults'),
                }}
            />
            {failed ? (
                <p role="alert" className="text-sm text-danger-text">
                    {t('appCatalog.grants.hosts.loadFailed')}
                </p>
            ) : empty ? (
                <p className="text-sm text-warning-text">{t('appCatalog.grants.hosts.empty')}</p>
            ) : value.length === 0 && !loading ? (
                <p className="text-sm text-muted">{t('appCatalog.grants.hosts.required')}</p>
            ) : null}
        </div>
    )
}
