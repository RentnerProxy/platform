export const BACKUP_ERRORS = [
    'invalid_input',
    'busy',
    'revision_conflict',
    'capacity',
    'unavailable',
    'not_found',
    'artifact_invalid',
    'offline_restore_required',
    'appliance_required',
] as const
export class BackupDomainError extends Error {
    constructor(readonly code: (typeof BACKUP_ERRORS)[number]) {
        super(code)
    }
}
