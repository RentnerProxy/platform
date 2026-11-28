export class HostMonitoringError extends Error {
    constructor(
        readonly code:
            | 'invalid_input'
            | 'host_not_found'
            | 'conflict'
            | 'limit_reached'
            // An app took monitoring over, or a handoff to one is in progress.
            | 'handed_off'
            // Built-in monitoring still owns the domain, so the app has nothing to report.
            | 'not_handed_off',
    ) {
        super(code)
    }
}
