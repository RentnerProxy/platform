import { timingSafeEqual } from 'node:crypto'
import { chmodSync, closeSync, readFileSync } from 'node:fs'

import { hasFields, isJsonObject, Providers } from './app-providers.ts'

const maxBodySize = 4096

interface Bootstrap {
    appSocket: string
    coreSocket: string
    installationId: string
    generation: number
    appCredential: string
    coreCredential: string
}

type JsonBody = { kind: 'json'; value: unknown } | { kind: 'tooLarge' } | { kind: 'invalid' }

function isSocketPath(value: unknown): value is string {
    return typeof value === 'string' && value.startsWith('/') && !value.includes('\0')
}

function isCredential(value: unknown): value is string {
    return typeof value === 'string' && value.length === 64 && /^[0-9a-f]+$/.test(value)
}

function readBootstrap(): Bootstrap {
    const descriptor = 3
    let input: string
    try {
        input = readFileSync(descriptor, 'utf8')
    } finally {
        closeSync(descriptor)
    }
    const value: unknown = JSON.parse(input)
    if (
        !isJsonObject(value) ||
        !hasFields(
            value,
            'appSocket',
            'coreSocket',
            'installationId',
            'generation',
            'appCredential',
            'coreCredential',
        )
    ) {
        throw new Error('Invalid app bootstrap')
    }

    const { appSocket, coreSocket, installationId, generation, appCredential, coreCredential } =
        value
    if (!isSocketPath(appSocket) || !isSocketPath(coreSocket) || appSocket === coreSocket) {
        throw new Error('Invalid app bootstrap sockets')
    }
    if (
        typeof installationId !== 'string' ||
        installationId.length === 0 ||
        typeof generation !== 'number' ||
        !Number.isSafeInteger(generation) ||
        generation < 1
    ) {
        throw new Error('Invalid app bootstrap installation')
    }
    if (!isCredential(appCredential) || !isCredential(coreCredential)) {
        throw new Error('Invalid app bootstrap credentials')
    }
    return { appSocket, coreSocket, installationId, generation, appCredential, coreCredential }
}

async function readJson(body: ReadableStream<Uint8Array> | null): Promise<JsonBody> {
    if (!body) return { kind: 'invalid' }
    const buffer = new Uint8Array(maxBodySize)
    let size = 0
    try {
        for await (const chunk of body) {
            if (size + chunk.byteLength > maxBodySize) return { kind: 'tooLarge' }
            buffer.set(chunk, size)
            size += chunk.byteLength
        }
        const text = new TextDecoder('utf-8', { fatal: true }).decode(buffer.subarray(0, size))
        const value: unknown = JSON.parse(text)
        return { kind: 'json', value }
    } catch {
        return { kind: 'invalid' }
    }
}

function coreUnavailable(): Response {
    return Response.json({ error: 'coreContextUnavailable' }, { status: 503 })
}

async function checkCore(bootstrap: Bootstrap): Promise<Response> {
    const { coreSocket, coreCredential, installationId, generation } = bootstrap
    try {
        const response = await fetch('http://localhost/platform/v1/context', {
            unix: coreSocket,
            headers: {
                authorization: `Bearer ${coreCredential}`,
                'x-app-installation': installationId,
                'x-app-generation': String(generation),
            },
            redirect: 'error',
            signal: AbortSignal.timeout(2000),
        })
        if (response.status !== 200) {
            await response.body?.cancel()
            return coreUnavailable()
        }
        const body = await readJson(response.body)
        if (
            body.kind !== 'json' ||
            !isJsonObject(body.value) ||
            body.value.installationId !== installationId ||
            body.value.generation !== generation
        ) {
            return coreUnavailable()
        }
        return Response.json({
            ready: true,
            bun: Bun.version,
            core: { installationId, generation },
        })
    } catch {
        return coreUnavailable()
    }
}

async function probe(request: Request, providers: Providers): Promise<Response> {
    const contentType = request.headers.get('content-type')?.split(';', 1)[0]?.trim().toLowerCase()
    if (
        contentType !== 'application/json' &&
        !/^application\/[^/]+\+json$/.test(contentType ?? '')
    ) {
        return Response.json({ error: 'unsupportedContentType' }, { status: 415 })
    }
    const body = await readJson(request.body)
    if (body.kind === 'tooLarge')
        return Response.json({ error: 'requestTooLarge' }, { status: 413 })
    if (body.kind === 'invalid') return Response.json({ error: 'invalidJson' }, { status: 400 })
    return providers.call(body.value)
}

async function startApp(bootstrap: Bootstrap) {
    const { appSocket, appCredential, installationId, generation } = bootstrap
    const generationHeader = String(generation)
    const expectedAuthorization = Buffer.from(`Bearer ${appCredential}`)
    const providers = new Providers()

    // Bind with restrictive permissions before the broker can see the socket.
    const previousMask = process.umask(0o117)
    try {
        const server = Bun.serve({
            unix: appSocket,
            maxRequestBodySize: maxBodySize,
            fetch(request) {
                const route = new URL(request.url).pathname
                if (route !== '/app/v1/ready' && route !== '/app/v1/probe') {
                    return new Response(null, { status: 404 })
                }
                const authorization = Buffer.from(request.headers.get('authorization') ?? '')
                if (
                    request.headers.get('x-app-installation') !== installationId ||
                    request.headers.get('x-app-generation') !== generationHeader ||
                    authorization.length !== expectedAuthorization.length ||
                    !timingSafeEqual(authorization, expectedAuthorization)
                ) {
                    return Response.json({ error: 'installationContextRejected' }, { status: 403 })
                }
                const method = route === '/app/v1/ready' ? 'GET' : 'POST'
                if (request.method !== method) {
                    return new Response(null, { status: 405, headers: { allow: method } })
                }
                return route === '/app/v1/ready' ? checkCore(bootstrap) : probe(request, providers)
            },
            error() {
                return Response.json({ error: 'internalError' }, { status: 500 })
            },
        })
        try {
            chmodSync(appSocket, 0o660)
        } catch {
            await server.stop(true)
            throw new Error('Could not set app socket permissions')
        }
    } finally {
        process.umask(previousMask)
    }
}

try {
    await startApp(readBootstrap())
} catch {
    process.exit(1)
}
