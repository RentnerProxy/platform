import type { AppUiPayload, AppUiResult } from './contract.ts'
import { APP_UI_PREFIX } from './paths.ts'

interface CallAppUi {
    data: {
        installationId: string
        generation: number
        frameToken: string
        requestId: string
        operationId: string
        idempotencyKey: string
        payload: AppUiPayload
    }
    signal?: AbortSignal
}

export async function callAppUi({ data, signal }: CallAppUi): Promise<AppUiResult> {
    try {
        const response = await fetch(APP_UI_PREFIX + 'call', {
            method: 'POST',
            credentials: 'same-origin',
            redirect: 'error',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(data),
            ...(signal && { signal }),
        })
        const result = (await response.json()) as AppUiResult
        if (typeof result?.ok === 'boolean') return result
    } catch {
        // A cancelled or failed transport still has a stable bridge failure.
    }
    return {
        ok: false,
        problem: {
            type: 'urn:rentnerproxy:problem:unavailable',
            title: 'App UI is unavailable.',
            status: 503,
            code: 'unavailable',
            requestId: data.requestId,
        },
    }
}
