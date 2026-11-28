export type ProxyHostDomainErrorCode =
    | 'domain_conflict'
    | 'proxy_host_not_found'
    | 'invalid_status_transition'
    | 'invalid_input'
    | 'discovery_managed'
    // The host's monitoring is being handed over to an app; delete it once that finished.
    | 'monitoring_handoff_open'
