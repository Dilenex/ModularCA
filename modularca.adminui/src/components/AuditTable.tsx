import React, { useEffect, useState } from 'react';
import type { NoticeInput } from '@shared/notifications/notice';
import { errorNotice } from '@shared-auth/api/notices';
import { apiGet } from '../api/client';
import { DataTable } from '@shared/components/DataTable';
import { AuditDrawer, buildColumns, type Tab } from '../pages/AuditLogs';

/**
 * The audit page's table, embedded with a prefilled filter. This is what a record drawer's
 * Audit tab shows, so every entity's activity is visible without a new endpoint: the list
 * endpoint takes the target the audit rows were stamped with.
 */
const AuditTable: React.FC<{
    tab: Tab;
    target: { type: string; id: string };
    pageSize?: number;
}> = ({ tab, target, pageSize = 25 }) => {
    const [rows, setRows] = useState<any[]>([]);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState<NoticeInput | null>(null);
    const [page, setPage] = useState(1);
    const [totalPages, setTotalPages] = useState(1);
    const [totalCount, setTotalCount] = useState(0);

    useEffect(() => {
        let cancelled = false;
        setLoading(true);
        setError(null);
        const params = new URLSearchParams({ page: String(page), pageSize: String(pageSize), targetEntityType: target.type, targetEntityId: target.id });
        const path = tab === 'General' ? `/api/v1/admin/audit?${params}` : `/api/v1/admin/audit/${tab.toLowerCase()}?${params}`;
        apiGet<any>(path)
            .then((data) => {
                if (cancelled) return;
                const items = Array.isArray(data) ? data : (data.items || []);
                setRows(items);
                setTotalPages(data.totalPages || 1);
                setTotalCount(data.total ?? data.totalCount ?? items.length);
                setLoading(false);
            })
            .catch((err) => { if (!cancelled) { setError(errorNotice(err, 'Failed to load audit entries')); setLoading(false); } });
        return () => { cancelled = true; };
    }, [tab, target.type, target.id, page, pageSize]);

    return (
        <DataTable<any>
            tableId={`audit-embedded-${tab.toLowerCase()}`}
            rows={rows}
            rowKey={(l) => l.id || `${l.timestamp}-${l.actionType || ''}`}
            loading={loading}
            error={error}
            empty="No audit entries for this record"
            columns={buildColumns(tab)}
            disableExport
            renderDrawer={(l) => <AuditDrawer log={l} />}
            drawerTitle={(l) => l.actionType || 'Audit entry'}
            page={page}
            pageSize={pageSize}
            totalPages={totalPages}
            totalCount={totalCount}
            onPageChange={setPage}
        />
    );
};

export default AuditTable;
