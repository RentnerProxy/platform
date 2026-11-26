export const APP_CATALOG_INSTALL_RATE_LIMIT = {
    scope: 'app-catalog-install',
    limit: 10,
    windowMs: 60_000,
} as const

/**
 * Revocations count against their own bucket, keyed by the Owner's user ID like installs, so
 * that used install and update quota never causes a 429 for a revocation. The app manager's
 * lifecycle checks still apply: a revocation submitted while another operation is pending is
 * refused with 409.
 */
export const APP_CATALOG_REVOKE_RATE_LIMIT = {
    scope: 'app-catalog-revoke',
    limit: 60,
    windowMs: 60_000,
} as const
