import { CustomSelect } from '@rentnerkev/select/select'
import { useId } from 'react'
import {
    grantNameKey,
    grantScopeKey,
    isSupportGrant,
    type GrantDraftItem,
} from '@/lib/AppCatalog/grantApproval.ts'
import OptionToggle from '@/shared/Forms/OptionToggle.tsx'
import useTranslationStore from '@/shared/Language/Hooks/useTranslationStore.ts'
import { Modal } from '@/shared/Modal/index.tsx'
import { ModalActionButton, ModalCancelButton } from '@/shared/Modal/Components/ModalActions.tsx'
import useGrantApprovalLogic from '../Hooks/useGrantApprovalLogic.ts'
import type { CatalogApprovalRequest } from '../Types/app-catalog.types.ts'
import GrantHostPicker from './GrantHostPicker.tsx'

/** Not a valid permission key, so it stands for "no app permission required". */
const NO_PERMISSION_KEY = '-'

const approveLabels = {
    install: 'appCatalog.grants.approveInstall',
    update: 'appCatalog.grants.approveUpdate',
    reinstall: 'appCatalog.grants.approveReinstall',
} as const

/** Ask the Owner to approve exactly the access a release requests before it starts. */
export default function GrantApprovalDialog({
    request,
    onOpenChange,
}: {
    request: CatalogApprovalRequest
    onOpenChange: (open: boolean) => void
}) {
    const { t } = useTranslationStore()
    const { state, handler } = useGrantApprovalLogic(request)
    const id = useId()

    const row = ({
        item,
        index,
        resources,
    }: {
        item: GrantDraftItem
        index: number
        resources: string[]
    }) => {
        const scope = grantScopeKey(item.capability)
        return (
            <li
                key={`${item.capability.id}:${item.capability.scope}:${item.resourceId ?? ''}`}
                className="grid min-w-0 gap-3 rounded-xl border border-border bg-surface-subtle p-4"
            >
                <div className="min-w-0">
                    <p className="font-semibold wrap-anywhere text-ink">
                        {t(`appCatalog.grants.names.${grantNameKey(item.capability)}`, {
                            id: item.capability.id,
                        })}
                    </p>
                    <p className="mt-0.5 text-sm wrap-anywhere text-muted">
                        {t(`appCatalog.grants.scope.${item.allHosts ? 'allProxyHosts' : scope}`, {
                            resource: item.resourceId,
                            scope: item.capability.scope,
                        })}
                    </p>
                </div>
                {item.allHostsAvailable ? (
                    <div className="grid gap-1">
                        <OptionToggle
                            label={t('appCatalog.grants.hosts.all')}
                            checked={item.allHosts}
                            onChange={(event) =>
                                handler.handleChange(index, { allHosts: event.target.checked })
                            }
                        />
                        <p className="text-xs text-muted">{t('appCatalog.grants.hosts.allHint')}</p>
                    </div>
                ) : null}
                {item.selectable && !item.allHosts ? (
                    <GrantHostPicker
                        id={`${id}-hosts-${index}`}
                        hosts={state.hosts}
                        value={resources}
                        loading={state.hostsLoading}
                        failed={state.hostsFailed}
                        onChange={(selected) =>
                            handler.handleChange(index, { resources: selected })
                        }
                    />
                ) : null}
                {item.serviceRequested ? (
                    <div className="grid gap-1">
                        <OptionToggle
                            label={t('appCatalog.grants.allowService')}
                            checked={item.allowService}
                            onChange={(event) =>
                                handler.handleChange(index, {
                                    allowService: event.target.checked,
                                })
                            }
                        />
                        <p className="text-xs text-muted">
                            {t('appCatalog.grants.allowServiceHint')}
                        </p>
                    </div>
                ) : null}
                {request.permissionKeys.length > 0 && !isSupportGrant(item.capability) ? (
                    <CustomSelect
                        id={`${id}-permission-${index}`}
                        label={t('appCatalog.grants.permissionKey')}
                        value={item.permissionKey ?? NO_PERMISSION_KEY}
                        options={[
                            {
                                value: NO_PERMISSION_KEY,
                                label: t('appCatalog.grants.permissionKeyNone'),
                            },
                            ...request.permissionKeys.map((key) => ({ value: key, label: key })),
                        ]}
                        onValueChange={(value) =>
                            handler.handleChange(index, {
                                permissionKey:
                                    value === NO_PERMISSION_KEY || value === null
                                        ? undefined
                                        : value,
                            })
                        }
                    />
                ) : null}
            </li>
        )
    }

    return (
        <Modal
            open
            onOpenChange={onOpenChange}
            size="lg"
            title={t('appCatalog.grants.title')}
            description={t('appCatalog.grants.description', {
                name: request.name,
                version: request.version,
            })}
            footer={
                <>
                    <ModalCancelButton onClick={() => onOpenChange(false)}>
                        {t('appCatalog.grants.decline')}
                    </ModalCancelButton>
                    <ModalActionButton
                        disabled={!state.complete}
                        onClick={handler.handleApprove}
                        variant="primary"
                    >
                        {t(approveLabels[request.kind], { version: request.version })}
                    </ModalActionButton>
                </>
            }
        >
            <div className="grid gap-6">
                {state.capabilities.length > 0 ? (
                    <section aria-labelledby={`${id}-capabilities`} className="grid gap-3">
                        <h3 id={`${id}-capabilities`} className="font-bold text-ink">
                            {t('appCatalog.grants.capabilities')}
                        </h3>
                        <ul className="grid gap-3">{state.capabilities.map(row)}</ul>
                    </section>
                ) : null}
                {state.support.length > 0 ? (
                    <section aria-labelledby={`${id}-support`} className="grid gap-3">
                        <div>
                            <h3 id={`${id}-support`} className="font-bold text-ink">
                                {t('appCatalog.grants.support')}
                            </h3>
                            <p className="mt-0.5 text-sm text-muted">
                                {t('appCatalog.grants.supportHint')}
                            </p>
                        </div>
                        <ul className="grid gap-3">{state.support.map(row)}</ul>
                    </section>
                ) : null}
                <p className="text-sm text-muted">{t('appCatalog.grants.declineHint')}</p>
            </div>
        </Modal>
    )
}
