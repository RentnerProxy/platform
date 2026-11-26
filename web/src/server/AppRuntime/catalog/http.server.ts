import '@tanstack/react-start/server-only'

import type { z } from 'zod'
import { APP_CATALOG_INSTALL_RATE_LIMIT } from '@/config/app-catalog.config.ts'
import {
    catalogInstallInputSchema,
    catalogLifecycleInputSchema,
    type CatalogInstallInput,
    type CatalogLifecycleInput,
} from '@/lib/AppCatalog/contract.ts'
import type { AuditEventInput } from '@/lib/Admin/AuditLogs/Types/audit-events.types.ts'
import { requireOwnerSessionService } from '@/server/Auth/Access/authorization.service.ts'
import { isAuthDomainError } from '@/server/Auth/Core/errors.server.ts'
import { getPublicOrigin } from '@/server/env.server.ts'
import { consumeRateLimit, RateLimitError } from '@/server/Valkey/rate-limiter.service.ts'
import { appUiEnabled, appUiSignal, readAppUiJson, uiProblems } from '../ui/transport.server.ts'
import {
    APP_CATALOG_REQUEST_BYTES,
    nativeCatalogInstall,
    nativeCatalogLifecycle,
} from './transport.server.ts'

const defaultDependencies = {
    enabled: appUiEnabled,
    origin: getPublicOrigin,
    ownerId: async () => (await requireOwnerSessionService()).user.id,
    limit: async (identifier: string) => {
        await consumeRateLimit({ ...APP_CATALOG_INSTALL_RATE_LIMIT, identifier })
    },
}

type CatalogDependencies = typeof defaultDependencies & {
    /** Records an accepted grant decision; defaults to the best-effort audit log. */
    audit?: (event: AuditEventInput) => Promise<void>
}

/** Load the audit log only for a grant decision, so the catalog boundary needs no database. */
async function auditGrantDecision(event: AuditEventInput): Promise<void> {
    const { recordAuditEventBestEffortService } = await import('@/server/Audit/audit.service.ts')
    await recordAuditEventBestEffortService(event)
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
    if (error === uiProblems.approvalRequired)
        return Response.json({ error: 'approvalRequired' }, { status: 422, headers })
    return Response.json({ error: 'unavailable' }, { status: 503, headers })
}

/** The Owner's grant decision that the Rust app manager accepted, for the audit log. */
function grantDecision(
    input: CatalogInstallInput | CatalogLifecycleInput,
    ownerId: string,
): AuditEventInput | undefined {
    const grants = 'grants' in input ? input.grants : undefined
    const decided = input.approval ?? grants
    if (decided === undefined) return undefined
    return {
        actorUserId: ownerId,
        actorKind: 'user',
        action: grants === undefined ? 'accept' : 'delete',
        resource: 'app-grants',
        targetId: null,
        result: 'success',
        metadata: {
            count: decided.length,
            ...('appId' in input ? { appId: input.appId } : {}),
            ...('installationId' in input ? { installationId: input.installationId } : {}),
        },
    }
}

function createCatalogMutationHandler<
    Input extends CatalogInstallInput | CatalogLifecycleInput,
    Result,
>(
    dependencies: CatalogDependencies,
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
            const input = schema.safeParse(
                await readAppUiJson(request, signal, APP_CATALOG_REQUEST_BYTES),
            )
            if (!input.success) return catalogFailure(uiProblems.invalid, headers)
            await dependencies.limit(ownerId)
            if ((await dependencies.ownerId()) !== ownerId)
                return Response.json({ error: 'forbidden' }, { status: 403, headers })
            signal.throwIfAborted()
            const result = await submit(input.data, signal)
            const decision = grantDecision(input.data, ownerId)
            // The core accepted the decision; a missing audit entry must not report a failure.
            if (decision)
                await (dependencies.audit ?? auditGrantDecision)(decision).catch(() => undefined)
            return Response.json(result, { status: status(result), headers })
        } catch (error) {
            return catalogFailure(error, headers)
        }
    }
}

export function createCatalogInstallHandler(
    dependencies: CatalogDependencies & {
        install: typeof nativeCatalogInstall
    } = { ...defaultDependencies, install: nativeCatalogInstall },
) {
    return createCatalogMutationHandler(
        dependencies,
        catalogInstallInputSchema,
        dependencies.install,
        (install) => (install.status === 'installing' ? 202 : 200),
    )
}

export function createCatalogLifecycleHandler(
    dependencies: CatalogDependencies & {
        lifecycle: typeof nativeCatalogLifecycle
    } = { ...defaultDependencies, lifecycle: nativeCatalogLifecycle },
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
