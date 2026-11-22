import '@tanstack/react-start/server-only'

import {
    nativeAppPresentationSchema,
    type NativeAppPresentation,
} from '@/lib/AppUi/native-presentation.ts'
import { qualifyAppRuntimePermission } from '../authority.server.ts'
import { nativeAppUiPolicy, uiProblems, type NativeAppUi } from './transport.server.ts'

const greetingArchives = new Set([
    '4d7e1b3282b663cc1bf4c268d8124c2048596d99d1f112e55161c2f199199244',
    '1db86d4617764e83643ee1567367bcbd476dfff8cdb046fdfeb53f6a8b1c636a',
])

// Provide the native presentation for the immutable Greeting 1.0.0 packages.
const greetingPresentation = {
    formatVersion: 1,
    pages: [
        {
            kind: 'form',
            route: 'overview',
            label: { en: 'Overview', de: 'Übersicht' },
            read: 'get-greeting',
            write: 'save-greeting',
            confirm: 'confirm-save',
            submitLabel: { en: 'Save greeting', de: 'Gruß speichern' },
            fields: [
                {
                    field: 'greeting',
                    label: { en: 'New greeting', de: 'Neuer Gruß' },
                    help: {
                        en: 'The greeting is saved in this app installation.',
                        de: 'Der Gruß wird in dieser App-Installation gespeichert.',
                    },
                    minLength: 1,
                    maxLength: 120,
                    trim: true,
                },
            ],
        },
        {
            kind: 'table',
            route: 'details',
            label: 'Details',
            description: {
                en: 'Your greeting is stored in this app installation.',
                de: 'Dein Gruß wird in dieser App-Installation gespeichert.',
            },
            read: 'get-greeting',
            columns: [{ field: 'greeting', label: { en: 'Greeting', de: 'Gruß' } }],
        },
    ],
} satisfies NativeAppPresentation

export function resolveNativePresentation(app: NativeAppUi): NativeAppPresentation | undefined {
    const legacyGreeting =
        app.appId === 'rentnerproxy.greeting' && greetingArchives.has(app.archiveSha256)
    const result = nativeAppPresentationSchema.safeParse(
        app.nativePresentation ?? (legacyGreeting ? greetingPresentation : undefined),
    )
    if (!result.success) return
    const { pages } = result.data
    const routes = new Set(pages.map((page) => page.route))
    if (
        routes.size !== pages.length ||
        app.routes.length !== routes.size ||
        !app.routes.every((route) => routes.has(route))
    )
        return
    for (const page of pages) {
        const fields = page.kind === 'form' ? page.fields : page.columns
        if (new Set(fields.map(({ field }) => field)).size !== fields.length) return
        if (page.kind === 'form' && page.confirm && !app.dialogs.includes(page.confirm)) return
    }
    return result.data
}

export async function authorizedNativeOperations(
    app: NativeAppUi,
    presentation: NativeAppPresentation,
    permissions: readonly string[],
    signal: AbortSignal,
): Promise<string[]> {
    const operationIds = new Set(
        presentation.pages.flatMap((page) =>
            page.kind === 'form' ? [page.read, page.write] : [page.read],
        ),
    )
    const allowed = await Promise.all(
        Array.from(operationIds, async (operationId) => {
            try {
                const policy = await nativeAppUiPolicy(
                    {
                        installationId: app.installationId,
                        generation: app.generation,
                        operationId,
                    },
                    signal,
                )
                return (
                    !policy.resource &&
                    permissions.includes(
                        qualifyAppRuntimePermission(app.appId, policy.permissionKey),
                    )
                )
            } catch (error) {
                if (error === uiProblems.missing) return false
                throw error
            }
        }),
    )
    return [...operationIds].filter((_, index) => allowed[index])
}
