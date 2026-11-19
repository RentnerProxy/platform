import { lstat, realpath } from 'node:fs/promises'
import { join, resolve } from 'node:path'

const maximumFileBytes = 16 * 1024 * 1024

function byteRange(value: string, size: number) {
    const match = /^bytes=(\d*)-(\d*)$/u.exec(value)
    const first = match?.[1],
        last = match?.[2]
    if ((!first && !last) || !size) return null
    const end = last ? Number(last) : size - 1
    if (!Number.isSafeInteger(end)) return null
    const start = first ? Number(first) : Math.max(0, size - end)
    const stop = first ? Math.min(end, size - 1) : size - 1
    return Number.isSafeInteger(start) && start <= stop ? { start, stop } : null
}

export async function serveFixture(directory: string, hostname: string, port: number) {
    const root = await realpath(resolve(directory))
    return Bun.serve({
        hostname,
        port,
        idleTimeout: 15,
        async fetch(request) {
            if (request.method !== 'GET' && request.method !== 'HEAD')
                return new Response(null, { status: 405, headers: { Allow: 'GET, HEAD' } })
            const path = new URL(request.url).pathname
            if (
                !/^\/repo-(?:initial|upgrade)\/(?:apt|rpm)(?:\/[A-Za-z0-9_.+-]+)+$/u.test(path) ||
                path.split('/').some((part) => part === '.' || part === '..')
            )
                return new Response(null, { status: 404 })
            try {
                const filePath = join(root, path.slice(1))
                if ((await realpath(filePath)) !== filePath)
                    return new Response(null, { status: 404 })
                const info = await lstat(filePath)
                if (!info.isFile() || info.nlink !== 1 || info.size > maximumFileBytes)
                    return new Response(null, { status: 404 })
                const headers = new Headers({
                    'Accept-Ranges': 'bytes',
                    'Last-Modified': info.mtime.toUTCString(),
                    'Content-Type': 'application/octet-stream',
                })
                const file = Bun.file(filePath)
                const requestedRange = request.headers.get('Range')
                const validator = request.headers.get('If-Range')
                if (requestedRange && (!validator || validator === info.mtime.toUTCString())) {
                    const range = byteRange(requestedRange, info.size)
                    if (!range) {
                        headers.set('Content-Range', `bytes */${info.size}`)
                        return new Response(null, { status: 416, headers })
                    }
                    const { start, stop } = range
                    headers.set('Content-Range', `bytes ${start}-${stop}/${info.size}`)
                    headers.set('Content-Length', String(stop - start + 1))
                    return new Response(
                        request.method === 'HEAD' ? null : file.slice(start, stop + 1),
                        { status: 206, headers },
                    )
                }
                headers.set('Content-Length', String(info.size))
                return new Response(request.method === 'HEAD' ? null : file, { headers })
            } catch {
                return new Response(null, { status: 404 })
            }
        },
    })
}

if (import.meta.main) {
    const [directory] = process.argv.slice(2)
    if (!directory) throw new Error('Expected a distribution fixture directory')
    const server = await serveFixture(directory, '192.0.2.1', 18888)
    const stop = async () => {
        await server.stop(true)
        process.exit(0)
    }
    process.once('SIGTERM', stop)
    process.once('SIGINT', stop)
}
