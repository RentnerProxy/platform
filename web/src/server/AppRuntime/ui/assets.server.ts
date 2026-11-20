import '@tanstack/react-start/server-only'

import { z } from 'zod'
import { appUiAssetPolicy, appUiAssetType } from '@/lib/AppUi/asset-policy.ts'
import { APP_UI_PREFIX } from '@/lib/AppUi/paths.ts'
import {
    decodeBase64Url,
    decryptSecret,
    encryptSecret,
} from '@/server/Auth/Core/encryption.server.ts'
import { appGenerationSchema, appIdSchema, appRecordId, appUidSchema } from '../contract.ts'
import { authorizeAppUi } from './access.server.ts'
import {
    appUiTokenPattern,
    nativeAppUiAsset,
    uiProblems,
    validUiPackagePath,
    type NativeAppUi,
} from './transport.server.ts'

const frameGrant = z.strictObject({
    appId: appIdSchema,
    installationId: appRecordId,
    generation: appGenerationSchema,
    uid: appUidSchema,
    document: z.string().refine(validUiPackagePath),
    sessionId: z.uuid(),
    expiresAt: z.number().int().positive(),
})

type FrameGrantUse = 'asset' | 'rpc'

function frameContext(origin: string, use: FrameGrantUse): string {
    return 'app-ui-frame:v1:' + use + ':' + origin
}

async function sealFrameGrant(plaintext: string, origin: string, use: FrameGrantUse) {
    const { iv, ciphertext } = await encryptSecret(plaintext, frameContext(origin, use))
    return (
        Buffer.from(iv).toString('base64url') + '.' + Buffer.from(ciphertext).toString('base64url')
    )
}

export async function appUiFrameSource(
    app: NativeAppUi,
    sessionId: string,
    sessionExpiresAt: Date,
    origin: string,
) {
    const { appId, installationId, generation, uid } = app
    const document = app.entrypoint.slice('ui/'.length)
    const plaintext = JSON.stringify({
        appId,
        installationId,
        generation,
        uid,
        document,
        sessionId,
        expiresAt: sessionExpiresAt.getTime(),
    })
    const [assetToken, frameToken] = await Promise.all([
        sealFrameGrant(plaintext, origin, 'asset'),
        sealFrameGrant(plaintext, origin, 'rpc'),
    ])
    return { src: APP_UI_PREFIX + assetToken + '/' + document, frameToken }
}

async function readFrameGrant(token: string, origin: string, use: FrameGrantUse) {
    const match = appUiTokenPattern.exec(token)
    if (!match?.[1] || !match[2]) return null
    const iv = decodeBase64Url(match[1])
    const ciphertext = decodeBase64Url(match[2])
    if (!iv || !ciphertext) return null
    try {
        const plaintext = await decryptSecret({ iv, ciphertext }, frameContext(origin, use))
        const result = frameGrant.safeParse(JSON.parse(plaintext))
        return result.success && result.data.expiresAt > Date.now() ? result.data : null
    } catch {
        return null
    }
}

export async function requireAppUiFrameGrant(
    token: string,
    binding: { installationId: string; generation: number },
    sessionId: string,
    origin: string,
) {
    const grant = await readFrameGrant(token, origin, 'rpc')
    if (
        !grant ||
        grant.sessionId !== sessionId ||
        grant.installationId !== binding.installationId ||
        grant.generation !== binding.generation
    )
        throw uiProblems.frameRevoked
    return grant
}

export async function serveAppUiAsset(
    request: Request,
    url: URL,
    origin: string,
    signal: AbortSignal,
    readDocumentSessionId: () => Promise<string | undefined>,
): Promise<Response> {
    if (request.method !== 'GET' || url.search) throw uiProblems.missing
    const [token, ...parts] = url.pathname.slice(APP_UI_PREFIX.length).split('/')
    const path = parts.join('/')
    if (!token || !validUiPackagePath(path)) throw uiProblems.missing
    const grant = await readFrameGrant(token, origin, 'asset')
    if (!grant) throw uiProblems.missing
    const document = path === grant.document
    const contentType = appUiAssetType(request, path, document)
    if (!contentType) throw uiProblems.forbidden
    if (document && (await readDocumentSessionId()) !== grant.sessionId) throw uiProblems.forbidden
    await authorizeAppUi(grant.sessionId, grant, signal)
    const response = await nativeAppUiAsset(grant, path, signal)
    return new Response(response.body, {
        headers: {
            'Content-Type': contentType,
            'Content-Security-Policy': appUiAssetPolicy(origin, token),
            'Cache-Control': 'private, no-store',
            'X-Content-Type-Options': 'nosniff',
            'Referrer-Policy': 'no-referrer',
            ...(!document && { 'Access-Control-Allow-Origin': 'null' }),
            ...(origin.startsWith('https:') && { 'Strict-Transport-Security': 'max-age=31536000' }),
        },
    })
}
