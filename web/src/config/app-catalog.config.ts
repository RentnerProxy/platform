export const APP_CATALOG_INSTALL_RATE_LIMIT = {
    scope: 'app-catalog-install',
    limit: 10,
    windowMs: 60_000,
} as const

/**
 * Revocations withdraw access, so installs and updates must never hold them back. Their own
 * bucket still bounds how often a session can make the app manager write its journal.
 */
export const APP_CATALOG_REVOKE_RATE_LIMIT = {
    scope: 'app-catalog-revoke',
    limit: 60,
    windowMs: 60_000,
} as const
