import { useState } from 'react'
import {
    grantApproval,
    grantDraft,
    grantDraftComplete,
    isSupportGrant,
    updateGrantDraft,
    type GrantDraftItem,
} from '@/lib/AppCatalog/grantApproval.ts'
import type { CatalogApprovalRequest } from '../Types/app-catalog.types.ts'
import useCatalogProxyHosts from './useCatalogProxyHosts.ts'

export default function useGrantApprovalLogic(request: CatalogApprovalRequest) {
    const [draft, setDraft] = useState(() =>
        grantDraft(request.requested, request.permissionKeys, request.previous),
    )
    const needsHosts = draft.some((item) => item.selectable)
    const { hosts, isLoading, isError } = useCatalogProxyHosts(needsHosts)
    // A preselected host that no longer exists is neither shown nor approved.
    const known = new Set(hosts?.map((host) => host.id))
    const exists = (id: string) => known.has(id)
    const rows = draft.map((item, index) => ({
        item,
        index,
        resources: item.resources.filter(exists),
    }))
    const complete = (!needsHosts || hosts !== undefined) && grantDraftComplete(draft, exists)

    return {
        state: {
            capabilities: rows.filter(({ item }) => !isSupportGrant(item.capability)),
            support: rows.filter(({ item }) => isSupportGrant(item.capability)),
            hosts: hosts ?? [],
            hostsLoading: isLoading,
            hostsFailed: isError,
            complete,
        },
        handler: {
            handleChange: (
                index: number,
                change: Partial<
                    Pick<GrantDraftItem, 'allowService' | 'permissionKey' | 'resources'>
                >,
            ) => setDraft((current) => updateGrantDraft(current, index, change)),
            handleApprove: () => {
                if (complete) request.submit(grantApproval(draft, exists))
            },
        },
    }
}
