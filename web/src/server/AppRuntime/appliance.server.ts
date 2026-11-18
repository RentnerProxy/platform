import '@tanstack/react-start/server-only'

import { lstat, unlink } from 'node:fs/promises'
import { getControllerToken } from '@/server/env.server.ts'
import { appRpcLimits } from './contract.ts'
import { createAppRuntimeGateway } from './gateway.server.ts'
import { manageAppRuntime } from './management.server.ts'
import { createAppProxyOperationWorker } from './operations.server.ts'
import { executeAppRuntimeCall } from './services.server.ts'

const socketPath = '/run/rentnerproxy/app-api/web.sock'

async function removeStaleSocket(): Promise<void> {
    const stat = await lstat(socketPath).catch((error: unknown) => {
        if (error instanceof Error && 'code' in error && error.code === 'ENOENT') return null
        throw error
    })
    if (!stat) return
    if (!stat.isSocket() || stat.uid !== process.getuid?.())
        throw new Error('Invalid App API socket')
    await unlink(socketPath)
}

/** The appliance owns the parent directory. The externally reachable HTTP server has no app routes. */
export function createAppRuntimeWorker() {
    const shutdown = new AbortController()
    const operationWorker = createAppProxyOperationWorker()
    let stopServer: (() => Promise<void>) | undefined
    return {
        async start() {
            const token = getControllerToken()
            if (!token) throw new Error('Missing App API bridge credential')
            await removeStaleSocket()
            shutdown.signal.throwIfAborted()
            const gateway = createAppRuntimeGateway(
                token,
                shutdown.signal,
                executeAppRuntimeCall,
                manageAppRuntime,
            )
            const server = Bun.serve({
                unix: socketPath,
                maxRequestBodySize: appRpcLimits.jsonBytes,
                fetch(request, listener) {
                    listener.timeout(request, 15)
                    return gateway(request)
                },
            })
            stopServer = async () => {
                await server.stop(true)
                await removeStaleSocket()
            }
            operationWorker.start()
        },
        async stop() {
            shutdown.abort()
            await Promise.all([stopServer?.(), operationWorker.stop()])
        },
    }
}
