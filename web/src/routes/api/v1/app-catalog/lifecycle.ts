import { createFileRoute } from '@tanstack/react-router'
import { manageAppCatalogHandler } from '@/features/AppCatalog/middleware.ts'

export const Route = createFileRoute('/api/v1/app-catalog/lifecycle')({
    server: {
        handlers: {
            POST: ({ request }) => manageAppCatalogHandler(request),
        },
    },
})
