import '@tanstack/react-start/server-only'

import type { z } from 'zod'
import { APP_CATALOG_INSTALL_RATE_LIMIT } from '@/config/app-catalog.config.ts'
import { catalogLifecycleInputSchema, catalogSelectorSchema } from '@/lib/AppCatalog/contract.ts'
import { requireOwnerSessionService } from '@/server/Auth/Access/authorization.service.ts'
import { isAuthDomainError } from '@/server/Auth/Core/errors.server.ts'
import { getPublicOrigin } from '@/server/env.server.ts'
import { consumeRateLimit, RateLimitError } from '@/server/Valkey/rate-limiter.service.ts'
import { appUiEnabled, appUiSignal, readAppUiJson, uiProblems } from '../ui/transport.server.ts'
import { nativeCatalogInstall, nativeCatalogLifecycle } from './transport.server.ts'

const defaultDependencies = {
    enabled: appUiEnabled,
    origin: getPublicOrigin,
    ownerId: async () => (await requireOwnerSessionService()).user.id,
    limit: async (identifier: string) => {
        await consumeRateLimit({ ...APP_CATALOG_INSTALL_RATE_LIMIT, identifier })
    },
}

function catalogFailure(error: unknown, headers: Headers) {
    if (isAuthDomainError(error)) {
        if (error.code === 'authentication_required')
            return Response.json({ error: 'forbidden' }, { status: 401, headers })
        if (error.code === 'owner_required')
            return Response.json({ error: 'forbidden' }, { status: 403, headers })
    }
    if (error instanceof RateLimitError) {
        headers.set('Retry-After', String(Math.max(1, Math.ceil(error.retryAfterMs / 1_000))))
        return Response.json({ error: 'rateLimited' }, { status: 429, headers })
    }
    if (error === uiProblems.invalid)
        return Response.json({ error: 'invalid' }, { status: 400, headers })
    if (error === uiProblems.tooLarge)
        return Response.json({ error: 'invalid' }, { status: 413, headers })
    if (error === uiProblems.conflict)
        return Response.json({ error: 'conflict' }, { status: 409, headers })
    return Response.json({ error: 'unavailable' }, { status: 503, headers })
}

function createCatalogMutationHandler<Input, Result>(
    dependencies: typeof defaultDependencies,
    schema: z.ZodType<Input>,
    submit: (input: Input, signal: AbortSignal) => Promise<Result>,
    status: (result: Result) => number,
) {
    return async (request: Request): Promise<Response> => {
        const headers = new Headers({
            'Cache-Control': 'private, no-store',
            'X-Content-Type-Options': 'nosniff',
        })
        const origin = dependencies.origin()
        if (!origin || request.headers.get('origin') !== origin)
            return Response.json({ error: 'forbidden' }, { status: 403, headers })
        try {
            const ownerId = await dependencies.ownerId()
            if (!dependencies.enabled()) return catalogFailure(uiProblems.unavailable, headers)
            const signal = appUiSignal(request)
            const input = schema.safeParse(await readAppUiJson(request, signal, 1_024))
            if (!input.success) return catalogFailure(uiProblems.invalid, headers)
            await dependencies.limit(ownerId)
            if ((await dependencies.ownerId()) !== ownerId)
                return Response.json({ error: 'forbidden' }, { status: 403, headers })
            signal.throwIfAborted()
            const result = await submit(input.data, signal)
            return Response.json(result, { status: status(result), headers })
        } catch (error) {
            return catalogFailure(error, headers)
        }
    }
}

export function createCatalogInstallHandler(
    dependencies = { ...defaultDependencies, install: nativeCatalogInstall },
) {
    return createCatalogMutationHandler(
        dependencies,
        catalogSelectorSchema,
        dependencies.install,
        (install) => (install.status === 'installing' ? 202 : 200),
    )
}

export function createCatalogLifecycleHandler(
    dependencies = { ...defaultDependencies, lifecycle: nativeCatalogLifecycle },
) {
    return createCatalogMutationHandler(
        dependencies,
        catalogLifecycleInputSchema,
        dependencies.lifecycle,
        () => 202,
    )
}

export const handleCatalogInstall = createCatalogInstallHandler()
export const handleCatalogLifecycle = createCatalogLifecycleHandler()
