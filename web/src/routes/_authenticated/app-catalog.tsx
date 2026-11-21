import { createFileRoute } from '@tanstack/react-router'
import AppCatalogPage from '@/features/AppCatalog/index.tsx'
import { requireOwnerRoute } from '@/features/Auth/route-guards.ts'

export const Route = createFileRoute('/_authenticated/app-catalog')({
    beforeLoad: requireOwnerRoute,
    component: AppCatalogPage,
})
