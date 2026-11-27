import {
    APP_CATALOG_INSTALL_PATH,
    APP_CATALOG_LIFECYCLE_PATH,
    catalogInstallSchema,
    catalogLifecycleSchema,
    sameCatalogLifecycle,
    sameCatalogRelease,
    type CatalogLifecycleInput,
    type CatalogSelector,
} from './contract.ts'

const requestErrors = {
    400: 'invalid',
    401: 'forbidden',
    403: 'forbidden',
    409: 'conflict',
    413: 'invalid',
    422: 'approvalRequired',
    429: 'rateLimited',
} as const

class CatalogRequestError extends Error {
    constructor(readonly code: (typeof requestErrors)[keyof typeof requestErrors]) {
        super(code)
    }
}

function isKnownRequestError(status: number): status is keyof typeof requestErrors {
    return Object.hasOwn(requestErrors, status)
}

export function catalogRequestError(error: unknown) {
    return error instanceof CatalogRequestError ? error.code : 'unavailable'
}

async function postCatalog(path: string, input: CatalogSelector | CatalogLifecycleInput) {
    const response = await fetch(path, {
        method: 'POST',
        credentials: 'same-origin',
        cache: 'no-store',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(input),
    })
    if (isKnownRequestError(response.status)) {
        throw new CatalogRequestError(requestErrors[response.status])
    }
    if (!response.ok) throw new Error('Catalog request is unavailable.')
    return (await response.json()) as unknown
}

export async function installCatalogRelease(input: CatalogSelector) {
    const { appId, version, archiveSha256 } = input
    const result = catalogInstallSchema.parse(
        await postCatalog(APP_CATALOG_INSTALL_PATH, { appId, version, archiveSha256 }),
    )
    if (!sameCatalogRelease(result, input)) throw new Error('Unexpected catalog selection.')
    return result
}

export async function manageCatalogInstallation(input: CatalogLifecycleInput) {
    const result = catalogLifecycleSchema.parse(
        await postCatalog(APP_CATALOG_LIFECYCLE_PATH, input),
    )
    if (result.status !== 'pending' || !sameCatalogLifecycle(result, input))
        throw new Error('Unexpected catalog operation.')
    return result
}
