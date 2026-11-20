import { useState } from 'react'
import { ModalActionButton } from '@/shared/Modal/Components/ModalActions.tsx'
import { CustomTooltip } from '@rentnerkev/tooltips/tooltip'
import { Info } from 'lucide-react'
import { ACME_TERMS_INFORMATION_URL } from '@/config/certificates.config.ts'
import useTranslationStore from '@/shared/Language/Hooks/useTranslationStore.ts'
import { Modal } from '@/shared/Modal/index.tsx'
import { ConfirmDialog } from '@/shared/Modal/Components/ConfirmDialog.tsx'
import AppUiFrame from '@/features/AppUi/AppUiFrame.tsx'
import { useAppUiSlot } from '@/features/AppUi/AppUiProvider.tsx'
import useProxyHostFormModalLogic from './Hooks/useProxyHostFormModalLogic.ts'
import type { ProxyHostFormModalProps } from './Types/proxy-host-form.types.ts'
import ProxyHostSetupGuide from './Components/ProxyHostSetupGuide.tsx'
import ProxyHostFormFields from './Components/ProxyHostFormFields.tsx'
import ProxyHostFormModalFooter from './Components/ProxyHostFormModalFooter.tsx'
import ProxyHostFormTabs from './Components/ProxyHostFormTabs.tsx'

export default function ProxyHostFormModal(props: ProxyHostFormModalProps) {
    const { state, handler, refs, form, certificateRequestForm } = useProxyHostFormModalLogic(props)
    const { t } = useTranslationStore()
    const appTabs = useAppUiSlot('proxyHostTab')
    const [selectedApp, setSelectedApp] = useState<string>()
    const hostId = props.mode === 'edit' && props.open ? props.proxyHost?.id : undefined
    const activeApp = hostId ? appTabs.find((app) => app.installationId === selectedApp) : undefined

    return (
        <>
            <Modal
                open={props.open}
                onOpenChange={props.onOpenChange}
                title={state.title}
                description={state.description}
                size="lg"
                fixedHeight
                closeDisabled={state.isPending || state.disableConfirmationOpen}
                navigation={
                    <ProxyHostFormTabs
                        activeTab={state.activeTab}
                        formId={state.formId}
                        tabs={state.tabs}
                        invalidTabs={state.invalidTabs}
                        isPending={state.isPending}
                        setActiveTab={(tab) => {
                            setSelectedApp(undefined)
                            handler.setActiveTab(tab)
                        }}
                        apps={hostId ? appTabs : []}
                        activeApp={activeApp?.installationId}
                        selectApp={setSelectedApp}
                    />
                }
                footer={
                    activeApp ? undefined : (
                        <div className="contents [&_button[type=submit]]:h-auto [&_button[type=submit]]:min-h-12 [&_button[type=submit]]:py-2">
                            {state.requestNewCertificate ? (
                                <p
                                    id={`${state.formId}-acme-consent`}
                                    className="m-0 w-full text-xs leading-relaxed text-muted"
                                >
                                    {t('admin.proxyHosts.form.acmeSubmitConsent')}{' '}
                                    <a
                                        href={ACME_TERMS_INFORMATION_URL}
                                        target="_blank"
                                        rel="noopener noreferrer"
                                        className="font-semibold text-accent-ring underline underline-offset-2"
                                    >
                                        {t('admin.proxyHosts.form.acmeTermsLink')}
                                    </a>
                                </p>
                            ) : null}
                            <div className="mr-auto shrink-0">
                                <CustomTooltip
                                    collisionPadding={10}
                                    content={t(
                                        state.guide.open
                                            ? 'admin.proxyHosts.guide.skip'
                                            : 'admin.proxyHosts.guide.open',
                                    )}
                                >
                                    <ModalActionButton
                                        type="button"
                                        variant="secondary"
                                        aria-label={t(
                                            state.guide.open
                                                ? 'admin.proxyHosts.guide.skip'
                                                : 'admin.proxyHosts.guide.open',
                                        )}
                                        aria-expanded={state.guide.open}
                                        aria-controls={
                                            state.guide.open ? `${state.formId}-guide` : undefined
                                        }
                                        disabled={state.isPending}
                                        onClick={handler.handleToggleGuide}
                                    >
                                        <Info
                                            aria-hidden="true"
                                            className="size-5"
                                            strokeWidth={1.8}
                                        />
                                    </ModalActionButton>
                                </CustomTooltip>
                            </div>
                            <ProxyHostFormModalFooter
                                {...state}
                                form={form}
                                onOpenChange={props.onOpenChange}
                            />
                        </div>
                    )
                }
            >
                <form
                    id={state.formId}
                    className="grid gap-4"
                    hidden={activeApp !== undefined}
                    noValidate
                    onSubmit={handler.handleSubmit}
                >
                    <ProxyHostSetupGuide
                        guide={state.guide}
                        guideHeading={refs.guideHeading}
                        formId={state.formId}
                        handleNextGuideStep={handler.handleNextGuideStep}
                        handlePreviousGuideStep={handler.handlePreviousGuideStep}
                    />
                    <ProxyHostFormFields
                        certificateRequestForm={certificateRequestForm}
                        {...state}
                        form={form}
                        addDomain={handler.addDomain}
                        removeDomain={handler.removeDomain}
                        setRequestNewCertificate={handler.setRequestNewCertificate}
                        handleBrowserCacheChange={handler.handleBrowserCacheChange}
                    />
                </form>
                {hostId
                    ? appTabs.map((app) => {
                          const isActive = app.installationId === activeApp?.installationId
                          return (
                              <section
                                  key={app.installationId}
                                  id={`${state.formId}-panel-app-${app.installationId}`}
                                  role="tabpanel"
                                  aria-labelledby={`${state.formId}-tab-app-${app.installationId}`}
                                  hidden={!isActive}
                              >
                                  {isActive ? (
                                      <AppUiFrame app={app} slot="proxyHostTab" hostId={hostId} />
                                  ) : null}
                              </section>
                          )
                      })
                    : null}
            </Modal>
            {state.disableConfirmationOpen ? (
                <ConfirmDialog
                    open
                    onOpenChange={handler.setDisableConfirmationOpen}
                    title={t('admin.proxyHosts.confirm.disableTitle')}
                    description={t('admin.proxyHosts.confirm.disableDescription')}
                    confirmLabel={t('admin.proxyHosts.confirm.saveDisabled')}
                    pendingLabel={t('common.saving')}
                    destructive
                    isPending={state.isPending}
                    onConfirm={handler.confirmDisable}
                />
            ) : null}
        </>
    )
}
