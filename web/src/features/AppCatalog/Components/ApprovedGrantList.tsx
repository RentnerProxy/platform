import { ShieldCheck } from 'lucide-react'
import type { CatalogGrant } from '@/lib/AppCatalog/contract.ts'
import {
    canRevokeGrants,
    grantIdentity,
    grantNameKey,
    isSelectableGrant,
    isSupportGrant,
} from '@/lib/AppCatalog/grantApproval.ts'
import { buttonClassName } from '@/shared/Buttons/buttonStyles.ts'
import useTranslationStore from '@/shared/Language/Hooks/useTranslationStore.ts'
import useCatalogProxyHosts from '../Hooks/useCatalogProxyHosts.ts'
import type { CatalogInstallationView } from '../Types/app-catalog.types.ts'

/** The access the Owner approved for the installed release, each revocable on its own. */
export default function ApprovedGrantList({
    app,
    canManage,
    onRevoke,
}: {
    app: CatalogInstallationView
    canManage: boolean
    onRevoke: (app: CatalogInstallationView, grant: CatalogGrant, label: string) => void
}) {
    const { t } = useTranslationStore()
    const grants = (app.installation.grants ?? []).toSorted(
        (left, right) =>
            Number(isSupportGrant(left.capability)) - Number(isSupportGrant(right.capability)),
    )
    const { hostnames } = useCatalogProxyHosts(
        grants.some((grant) => isSelectableGrant(grant.capability)),
    )
    if (grants.length === 0) return null
    const revocable = canRevokeGrants(app.installation)
    const label = (grant: CatalogGrant) => {
        const name = t(`appCatalog.grants.names.${grantNameKey(grant.capability)}`, {
            id: grant.capability.id,
        })
        if (grant.resourceId === app.installation.installationId) return name
        const resource = isSelectableGrant(grant.capability)
            ? (hostnames.get(grant.resourceId) ?? grant.resourceId)
            : grant.resourceId
        return t('appCatalog.grants.onResource', { name, resource })
    }

    return (
        <section
            aria-label={t('appCatalog.grants.approved')}
            className="grid gap-2 border-t border-border pt-3"
        >
            <h4 className="flex items-center gap-2 text-sm font-semibold text-ink">
                <ShieldCheck className="size-4 text-muted" aria-hidden="true" />
                {t('appCatalog.grants.approved')}
            </h4>
            <ul className="grid gap-1.5">
                {grants.map((grant) => (
                    <li
                        key={grantIdentity(grant)}
                        className="flex flex-wrap items-center justify-between gap-2 text-sm"
                    >
                        <span className="min-w-0 wrap-anywhere text-ink-soft">
                            {label(grant)}
                            {grant.allowService ? null : (
                                <span className="text-muted">
                                    {' '}
                                    {t('appCatalog.grants.userOnly')}
                                </span>
                            )}
                        </span>
                        {revocable ? (
                            <button
                                type="button"
                                className={buttonClassName('secondary')}
                                disabled={!canManage}
                                onClick={() => onRevoke(app, grant, label(grant))}
                            >
                                {t('appCatalog.grants.revoke')}
                            </button>
                        ) : null}
                    </li>
                ))}
            </ul>
        </section>
    )
}
