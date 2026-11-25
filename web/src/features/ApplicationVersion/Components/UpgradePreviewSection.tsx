import useTranslationStore from '@/shared/Language/Hooks/useTranslationStore.ts'
import type {
    UpgradePreviewFeature,
    UpgradePreviewIssue,
} from '../Types/application-update.types.ts'
import type { UpgradePreviewSectionProps } from '../Types/application-update-dialog.types.ts'

const attention = 'border-amber-500/40 bg-amber-500/10'

function issueKey(issue: UpgradePreviewIssue): string {
    return issue.kind === 'app-incompatible'
        ? `${issue.kind}:${issue.installationId}`
        : `${issue.kind}:${issue.domain}`
}

export default function UpgradePreviewSection({
    requirements,
    preview,
    loading,
}: UpgradePreviewSectionProps) {
    const { t } = useTranslationStore()
    const detailed = preview && 'features' in preview ? preview : null
    const summary =
        requirements.status !== 'verified'
            ? `updates.preview.requirements.${requirements.status}`
            : loading || !preview
              ? 'updates.preview.loading'
              : `updates.preview.status.${preview.status}`
    const featureName = (domain: UpgradePreviewFeature['domain']) =>
        t(`updates.preview.features.${domain}`)
    const list = (values: readonly string[]) => values.join(', ') || t('updates.preview.none')
    const issueText = (issue: UpgradePreviewIssue) =>
        issue.kind === 'app-incompatible'
            ? t('updates.preview.issues.app-incompatible', {
                  app: issue.appId,
                  version: issue.version,
              })
            : t(`updates.preview.issues.${issue.kind}`, {
                  feature: featureName(issue.domain),
                  apps: issue.kind === 'feature-retired-without-app' ? list(issue.apps) : '',
              })
    const configured = (feature: UpgradePreviewFeature) =>
        feature.configured === null
            ? t('updates.preview.configured.unknown')
            : t(`updates.preview.configured.${feature.configured ? 'yes' : 'no'}`)

    return (
        <section className="grid gap-3" aria-label={t('updates.preview.title')}>
            <h3 className="m-0 font-bold">{t('updates.preview.title')}</h3>
            <p
                className={`m-0 rounded-lg border p-3 ${detailed?.status === 'ready' ? 'border-border' : attention}`}
            >
                {t(summary)}
            </p>
            {detailed && detailed.issues.length > 0 ? (
                <ul
                    className={`m-0 grid list-disc gap-2 rounded-lg border py-3 pr-3 pl-8 ${attention}`}
                    aria-label={t('updates.preview.issuesTitle')}
                >
                    {detailed.issues.map((issue) => (
                        <li key={issueKey(issue)}>{issueText(issue)}</li>
                    ))}
                </ul>
            ) : null}
            {detailed ? (
                <>
                    <h4 className="m-0 font-semibold">{t('updates.preview.featuresTitle')}</h4>
                    <ul className="m-0 grid list-none gap-2 p-0 sm:grid-cols-2">
                        {detailed.features.map((feature) => (
                            <li
                                key={feature.domain}
                                className="grid gap-1 rounded-lg border border-border p-3"
                            >
                                <span className="font-semibold">{featureName(feature.domain)}</span>
                                <span>{t(`updates.preview.target.${feature.target}`)}</span>
                                <span className="text-muted">
                                    {t(`updates.preview.owner.${feature.owner}`)} ·{' '}
                                    {configured(feature)}
                                    {feature.references === null
                                        ? null
                                        : ` · ${t('updates.preview.references')}: ${feature.references}`}
                                </span>
                                {feature.apps.length > 0 ? (
                                    <span className="wrap-anywhere">
                                        {t('updates.preview.requiredApps')}:{' '}
                                        <span className="font-mono">{list(feature.apps)}</span>
                                    </span>
                                ) : null}
                                {feature.providers && feature.providers.length > 0 ? (
                                    <span className="wrap-anywhere">
                                        {t('updates.preview.providedBy')}:{' '}
                                        <span className="font-mono">{list(feature.providers)}</span>
                                    </span>
                                ) : null}
                            </li>
                        ))}
                    </ul>
                    <h4 className="m-0 font-semibold">{t('updates.preview.appsTitle')}</h4>
                    {detailed.apps === null ? (
                        <p className="m-0">{t('updates.preview.appsUnavailable')}</p>
                    ) : detailed.apps.length === 0 ? (
                        <p className="m-0">{t('updates.preview.noApps')}</p>
                    ) : (
                        <ul className="m-0 grid list-none gap-2 p-0">
                            {detailed.apps.map((app) => (
                                <li
                                    key={app.installationId}
                                    className={`grid gap-1 rounded-lg border p-3 ${app.target === 'compatible' ? 'border-border' : attention}`}
                                >
                                    <span className="font-mono wrap-anywhere">
                                        {app.appId} {app.version}
                                    </span>
                                    <span>{t(`updates.preview.apps.${app.target}`)}</span>
                                </li>
                            ))}
                        </ul>
                    )}
                </>
            ) : null}
        </section>
    )
}
