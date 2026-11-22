import { useQuery } from '@tanstack/react-query'
import { callAppUi } from '@/lib/AppUi/client.ts'
import type { AppUiPayload, AppUiSummary } from '@/lib/AppUi/contract.ts'
import { useAppUi } from '../AppUiProvider.tsx'
import { openAppUiHandler } from '../middleware.ts'

export function useNativeAppUiLogic(app: AppUiSummary) {
    const inventory = useAppUi()
    const sessionId = inventory?.sessionId
    const scope = [
        'native-app-ui',
        sessionId,
        app.installationId,
        app.generation,
        app.permissionKeys.toSorted(),
    ] as const
    const source = useQuery({
        queryKey: [...scope, 'presentation'],
        enabled: Boolean(sessionId),
        staleTime: Infinity,
        retry: false,
        queryFn: async ({ signal }) => {
            if (!sessionId) throw new Error('App session unavailable')
            const result = await openAppUiHandler({
                data: {
                    installationId: app.installationId,
                    generation: app.generation,
                    sessionId,
                    native: true,
                },
                signal,
            })
            if (!result.ok) {
                if (result.problem.code === 'staleGeneration') {
                    void inventory?.refresh().catch(() => undefined)
                }
                throw new Error('App presentation unavailable')
            }
            if (!result.native) throw new Error('App presentation unavailable')
            return { ...result.native, frameToken: result.frameToken }
        },
    })

    async function call(
        operationId: string,
        payload: AppUiPayload,
        signal: AbortSignal,
        idempotencyKey = crypto.randomUUID(),
    ) {
        const open = source.data
        if (!open?.operations.includes(operationId)) throw new Error('App operation unavailable')
        const result = await callAppUi({
            data: {
                installationId: app.installationId,
                generation: app.generation,
                frameToken: open.frameToken,
                operationId,
                idempotencyKey,
                requestId: crypto.randomUUID(),
                payload,
            },
            signal: AbortSignal.any([signal, AbortSignal.timeout(15_000)]),
        })
        if (!result.ok) {
            if (
                result.problem.code === 'staleGeneration' ||
                result.problem.code === 'frameRevoked'
            ) {
                void inventory?.refresh().catch(() => undefined)
            }
            throw new Error('App operation failed')
        }
        return result.payload
    }

    return { state: { source, scope }, handler: { call } }
}

export type NativeAppSession = Pick<ReturnType<typeof useNativeAppUiLogic>, 'handler'> & {
    scope: ReturnType<typeof useNativeAppUiLogic>['state']['scope']
    operations: readonly string[]
}

export function nativeReadKey(session: NativeAppSession, operationId: string) {
    return [...session.scope, 'read', operationId] as const
}

export function useNativeAppRead(session: NativeAppSession, operationId: string, active: boolean) {
    return useQuery({
        queryKey: nativeReadKey(session, operationId),
        enabled: active && session.operations.includes(operationId),
        queryFn: ({ signal }) => session.handler.call(operationId, {}, signal),
        retry: false,
        staleTime: Infinity,
    })
}
