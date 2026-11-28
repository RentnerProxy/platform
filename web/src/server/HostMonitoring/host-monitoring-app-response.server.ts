import '@tanstack/react-start/server-only'
import { HostMonitoringError } from './host-monitoring.errors.ts'
import { errorResponse } from './host-monitoring-response.server.ts'
import { hostMonitoringAppService } from './host-monitoring-app.context.server.ts'

export function createHostMonitoringAppHttpHandler(
    service: Pick<typeof hostMonitoringAppService, 'getAppSummary'> = hostMonitoringAppService,
) {
    return async function appSummary(request: Request): Promise<Response> {
        const headers = new Headers({
            'Cache-Control': 'private, no-store',
            'X-Content-Type-Options': 'nosniff',
        })
        if (request.signal.aborted) return new Response(null, { status: 499, headers })
        if (request.method !== 'GET') {
            headers.set('Allow', 'GET')
            return Response.json({ error: 'invalid_input' }, { status: 405, headers })
        }
        try {
            const params = new URL(request.url).searchParams
            for (const key of params.keys())
                if (key !== 'proxyHostIds' || params.getAll(key).length !== 1)
                    throw new HostMonitoringError('invalid_input')
            return Response.json(
                await service.getAppSummary({
                    proxyHostIds: params.get('proxyHostIds')?.split(','),
                }),
                { headers },
            )
        } catch (error) {
            if (request.signal.aborted) return new Response(null, { status: 499, headers })
            return errorResponse(error, headers)
        }
    }
}

export const hostMonitoringAppHttpHandler = createHostMonitoringAppHttpHandler()
