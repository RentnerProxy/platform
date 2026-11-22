import { useMemo, useState } from 'react'
import type { AppUiPayload } from '@/lib/AppUi/contract.ts'
import { nativeText, type NativeAppTable as Table } from '@/lib/AppUi/native-presentation.ts'
import useTranslationStore from '@/shared/Language/Hooks/useTranslationStore.ts'
import DataTable from '@/shared/Table/index.tsx'
import useClientTable from '@/shared/Table/Hooks/useClientTable.ts'
import type { UseClientTableParams } from '@/shared/Table/Types/table.types.ts'
import { useNativeAppRead, type NativeAppSession } from '../Hooks/useNativeAppUiLogic.ts'

type AppTableRow = { id: string; values: AppUiPayload }
const emptyRows: AppTableRow[] = []
const getRowId = ({ id }: AppTableRow) => id

export default function NativeAppTable({
    page,
    session,
    active,
}: {
    page: Table
    session: NativeAppSession
    active: boolean
}) {
    const { t, locale } = useTranslationStore()
    const [showColumnFilters, setShowColumnFilters] = useState(false)
    const read = useNativeAppRead(session, page.read, active)
    const rows = useMemo(() => {
        if (!read.data) return emptyRows
        if (!page.rowsField) return [{ id: '0', values: read.data }]
        const entries = Object.hasOwn(read.data, page.rowsField) ? read.data[page.rowsField] : null
        return Array.isArray(entries)
            ? entries
                  .filter(
                      (row): row is AppUiPayload =>
                          row !== null && typeof row === 'object' && !Array.isArray(row),
                  )
                  .map((values, index) => ({ id: String(index), values }))
            : emptyRows
    }, [page.rowsField, read.data])
    const columns = useMemo<UseClientTableParams<AppTableRow>['columns']>(
        () =>
            page.columns.map(({ field, label }) => ({
                id: field,
                header: nativeText(label, locale),
                accessorFn: ({ values }) => {
                    const value = Object.hasOwn(values, field) ? values[field] : undefined
                    return typeof value === 'string' ||
                        typeof value === 'number' ||
                        typeof value === 'boolean'
                        ? String(value)
                        : ''
                },
            })),
        [locale, page.columns],
    )
    const { table, state, handler } = useClientTable({ data: rows, columns, getRowId })
    if (read.isError || !session.operations.includes(page.read))
        return <output className="text-sm text-muted">{t('appUi.unavailable')}</output>
    const emptyState = { title: t('quickSearch.noResults'), description: '' }
    return (
        <DataTable
            table={table}
            eyebrow=""
            title={nativeText(page.label, locale)}
            searchInput={state.searchInput}
            searchLabel={t('quickSearch.queryLabel')}
            searchPlaceholder={t('quickSearch.queryLabel')}
            onSearchChange={handler.handleSearchInputChange}
            showColumnFilters={showColumnFilters}
            onToggleColumnFilters={() => setShowColumnFilters((visible) => !visible)}
            onResetFilters={handler.handleResetFilters}
            isLoading={read.isPending}
            loadingLabel={t('appUi.loading')}
            emptyState={emptyState}
            filteredEmptyState={emptyState}
            itemLabel={t('appUi.rows')}
            tableMinWidthClassName="min-w-full"
        />
    )
}
