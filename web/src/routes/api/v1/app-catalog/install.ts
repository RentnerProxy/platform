import { createFileRoute } from '@tanstack/react-router'
import { installAppCatalogHandler } from '@/features/AppCatalog/middleware.ts'

export const Route = createFileRoute('/api/v1/app-catalog/install')({
    server: {
        handlers: {
            POST: ({ request }) => installAppCatalogHandler(request),
        },
    },
})
