import { randomUUID, timingSafeEqual } from 'node:crypto'
import { chmodSync } from 'node:fs'
import { rename, rm, writeFile } from 'node:fs/promises'

import { defaultGreeting, isGeneration, isRecord, isRecordId, readGreeting } from './greeting.ts'

const maxBodySize = 4096
const protocolVersion = '1.0.0'
const statePath = 'greeting.json'

async function readJson(stream: ReadableStream<Uint8Array>) {
    const buffer = new Uint8Array(maxBodySize)
    let size = 0
    for await (const chunk of stream) {
        if (size + chunk.byteLength > buffer.length) throw new Error('JSON exceeds the size limit')
        buffer.set(chunk, size)
        size += chunk.byteLength
    }
    const value: unknown = JSON.parse(
        new TextDecoder('utf-8', { fatal: true }).decode(buffer.subarray(0, size)),
    )
    return value
}

function socketPath(value: unknown): value is string {
    return (
        typeof value === 'string' &&
        value.startsWith('/') &&
        !value.includes('\0') &&
        value
            .slice(1)
            .split('/')
            .every((segment) => segment !== '' && segment !== '.' && segment !== '..')
    )
}

function credential(value: unknown): value is string {
    return typeof value === 'string' && /^[A-Za-z0-9_-]{43}$/u.test(value)
}

async function readBootstrap() {
    if (process.env.RENTNERPROXY_APP_BOOTSTRAP_FD !== '0') throw new Error('Missing bootstrap')
    const value = await readJson(Bun.stdin.stream())
    if (
        !isRecord(value) ||
        value.formatVersion !== 1 ||
        value.runtimeProfile !== 'rentnerproxy-linux-v1' ||
        value.appId !== 'rentnerproxy.greeting' ||
        !isRecordId(value.installationId) ||
        !isGeneration(value.generation) ||
        !socketPath(value.appSocket) ||
        !socketPath(value.coreSocket) ||
        value.appSocket === value.coreSocket ||
        !credential(value.appCredential) ||
        !credential(value.coreCredential) ||
        value.appCredential === value.coreCredential ||
        !isRecord(value.versions) ||
        value.versions.appProtocol !== protocolVersion ||
        value.versions.platformApi !== protocolVersion ||
        value.versions.uiBridge !== protocolVersion
    ) {
        throw new Error('Invalid bootstrap')
    }
    return {
        appSocket: value.appSocket,
        authorization: Buffer.from('Bearer ' + value.appCredential),
        installationId: value.installationId,
        generation: String(value.generation),
    }
}

async function loadGreeting() {
    try {
        const greeting = readGreeting(await readJson(Bun.file(statePath).stream()))
        if (greeting === undefined) throw new Error('Invalid greeting state')
        return greeting
    } catch (error) {
        if (error instanceof Error && 'code' in error && error.code === 'ENOENT')
            return defaultGreeting
        throw error
    }
}

async function saveGreeting(greeting: string) {
    const temporaryPath = `${statePath}.${randomUUID()}.tmp`
    try {
        await writeFile(temporaryPath, JSON.stringify({ greeting }) + '\n', {
            flag: 'wx',
            mode: 0o600,
            flush: true,
        })
        await rename(temporaryPath, statePath)
    } finally {
        await rm(temporaryPath, { force: true })
    }
}

function problem(status: number, code: string, title: string) {
    return Response.json(
        { type: 'urn:rentnerproxy:problem:' + code, code, status, title, requestId: randomUUID() },
        {
            status,
            headers: { 'Content-Type': 'application/problem+json' },
        },
    )
}

function methodNotAllowed(method: string) {
    return new Response(null, { status: 405, headers: { Allow: method } })
}

async function start() {
    const bootstrap = await readBootstrap()
    let greeting = await loadGreeting()
    let pendingWrite = Promise.resolve()
    const previousMask = process.umask(0o117)
    try {
        const server = Bun.serve({
            unix: bootstrap.appSocket,
            maxRequestBodySize: maxBodySize,
            async fetch(request) {
                const authorization = Buffer.from(request.headers.get('Authorization') ?? '')
                if (
                    authorization.length !== bootstrap.authorization.length ||
                    !timingSafeEqual(authorization, bootstrap.authorization) ||
                    request.headers.get('X-App-Installation') !== bootstrap.installationId ||
                    request.headers.get('X-App-Generation') !== bootstrap.generation
                ) {
                    return problem(403, 'scopeDenied', 'Installation context rejected')
                }
                const url = new URL(request.url)
                if (url.search) return problem(404, 'notFound', 'Operation not found')
                if (url.pathname === '/app/v1/health' || url.pathname === '/app/v1/ready') {
                    if (request.method !== 'GET') return methodNotAllowed('GET')
                    return url.pathname.endsWith('/health')
                        ? Response.json({ healthy: true })
                        : Response.json({ ready: true, protocolVersion, providers: [] })
                }
                const reading = url.pathname === '/app/v1/api/get-greeting'
                if (!reading && url.pathname !== '/app/v1/api/save-greeting') {
                    return problem(404, 'notFound', 'Operation not found')
                }
                if (request.method !== 'POST') return methodNotAllowed('POST')
                if (!isRecordId(request.headers.get('Idempotency-Key'))) {
                    return problem(400, 'invalidRequest', 'Invalid idempotency key')
                }
                const contentType = request.headers
                    .get('Content-Type')
                    ?.split(';')[0]
                    ?.trim()
                    .toLowerCase()
                if (!request.body || contentType !== 'application/json') {
                    return problem(415, 'invalidRequest', 'Expected a JSON request')
                }
                const input = await readJson(request.body).catch(() => undefined)
                if (reading) {
                    if (!isRecord(input) || Object.keys(input).length !== 0) {
                        return problem(400, 'invalidRequest', 'Expected an empty object')
                    }
                    await pendingWrite
                    return Response.json({ greeting })
                }
                const next = readGreeting(input)
                if (next === undefined) return problem(400, 'invalidRequest', 'Invalid greeting')
                const write = pendingWrite.then(async () => {
                    if (next === greeting) return
                    await saveGreeting(next)
                    greeting = next
                })
                pendingWrite = write.catch(() => undefined)
                await write
                return Response.json({ greeting: next })
            },
            error() {
                return problem(500, 'internalError', 'Greeting operation failed')
            },
        })
        try {
            chmodSync(bootstrap.appSocket, 0o660)
        } catch (error) {
            await server.stop(true)
            throw error
        }
    } finally {
        process.umask(previousMask)
    }
}

await start().catch(() => process.exit(1))
