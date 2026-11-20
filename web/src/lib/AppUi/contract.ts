export type AppUiSlot = 'navigation' | 'proxyHostTab' | 'dashboardWidget' | 'search'

export type AppUiSummary = {
    appId: string
    installationId: string
    generation: number
    name: string
    slots: AppUiSlot[]
    routes: string[]
    dialogs: string[]
    events: string[]
    permissionKeys: string[]
}

type AppUiJson = null | boolean | number | string | AppUiJson[] | AppUiPayload

export type AppUiPayload = { [key: string]: AppUiJson }

export type AppUiProblem = {
    type: string
    title: string
    status: number
    code: string
    requestId: string
}

export type AppUiResult = { ok: true; payload: AppUiPayload } | { ok: false; problem: AppUiProblem }
