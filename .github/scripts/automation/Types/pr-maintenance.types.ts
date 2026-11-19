export type GitHubRequest = (
    method: 'GET' | 'POST' | 'PUT' | 'PATCH',
    path: string,
    body?: unknown,
) => Promise<unknown>

export interface MaintenanceResult {
    number: number
    action:
        | 'update-requested'
        | 'merged'
        | 'closed'
        | 'skipped'
        | 'failed'
        | 'would-update'
        | 'would-merge'
        | 'would-close'
    reason: string
}

export interface MaintenanceOptions {
    repository: string
    dryRun: boolean
    trustedMergeBotLogin?: string
}
