import { createFileRoute } from '@tanstack/react-router'
import { createServerOnlyFn } from '@tanstack/react-start'
import { hostMonitoringAppHttpHandler } from '@/server/HostMonitoring/host-monitoring-app-response.server.ts'

const handleAppSummary = createServerOnlyFn(hostMonitoringAppHttpHandler)
export const Route = createFileRoute('/api/admin/monitoring/app-summary')({
    server: { handlers: { GET: ({ request }) => handleAppSummary(request) } },
})
