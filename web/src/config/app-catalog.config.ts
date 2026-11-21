export const APP_CATALOG_INSTALL_RATE_LIMIT = {
    scope: 'app-catalog-install',
    limit: 10,
    windowMs: 60_000,
} as const
