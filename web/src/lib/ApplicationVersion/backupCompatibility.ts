import {
    APP_AWARE_BACKUP_VERSION,
    CURRENT_COMPATIBILITY_PROFILE,
} from '../../config/compatibility.config.ts'

const acceptedVersions = [
    ...CURRENT_COMPATIBILITY_PROFILE.backup.acceptedVersions,
    APP_AWARE_BACKUP_VERSION,
]

export function isSupportedBackupVersion(version: unknown): boolean {
    return typeof version === 'number' && acceptedVersions.some((accepted) => version === accepted)
}

export function supportedBackupFormatLabel(): string {
    return acceptedVersions.map((version) => `v${version}`).join(', ')
}
