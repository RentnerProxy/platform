import type { PORTABLE_APP_BACKUP_VERSION } from '../../../web/src/config/compatibility.config.ts'
import type { BackupMetadata } from './format.types.ts'

export type CapturedInstallations = Extract<
    BackupMetadata,
    { version: typeof PORTABLE_APP_BACKUP_VERSION }
>['applications']['installations']
