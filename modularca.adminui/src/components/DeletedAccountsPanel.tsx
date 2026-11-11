import React, { useEffect, useState } from 'react';
import type { NoticeInput } from '@shared/notifications/notice';
import { errorNotice } from '@shared-auth/api/notices';
import { DataTable, DataTableColumn } from '@shared/components/DataTable';
import { apiGet } from '../api/client';

/** A deleted account whose row was kept because requests or approvals still name it. */
interface RetainedAccount {
    id: string;
    username: string;
    displayName?: string | null;
    deletedAt?: string | null;
    requests: number;
    approvals: number;
}

function formatDate(d?: string | null) {
    if (!d) return '-';
    return new Date(d).toLocaleDateString('en-US', { year: 'numeric', month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' });
}

/** What still names the account, in words. */
export function retainedHistory(a: Pick<RetainedAccount, 'requests' | 'approvals'>): string {
    const parts: string[] = [];
    if (a.requests > 0) parts.push(`${a.requests} request${a.requests === 1 ? '' : 's'}`);
    if (a.approvals > 0) parts.push(`${a.approvals} approval${a.approvals === 1 ? '' : 's'}`);
    return parts.length ? parts.join(', ') : '-';
}

/// <summary>
/// The Users page's "Deleted" tab: accounts that were deleted but kept as a record, because
/// certificate requests or approvals still name them. Read-only; nothing restores one.
/// </summary>
const DeletedAccountsPanel: React.FC = () => {
    const [rows, setRows] = useState<RetainedAccount[]>([]);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState<NoticeInput | null>(null);

    useEffect(() => {
        apiGet<RetainedAccount[]>('/api/v1/admin/users/deleted')
            .then((data) => setRows(Array.isArray(data) ? data : []))
            .catch((err) => setError(errorNotice(err, 'Deleted accounts could not be loaded')))
            .finally(() => setLoading(false));
    }, []);

    const columns: DataTableColumn<RetainedAccount>[] = [
        { key: 'username', header: 'Username', sortValue: (a) => a.username, render: (a) => <span className="font-medium text-ink">{a.username}</span> },
        { key: 'displayName', header: 'Name', sortValue: (a) => a.displayName || '', render: (a) => a.displayName || '-' },
        { key: 'deletedAt', header: 'Deleted', sortValue: (a) => a.deletedAt || '', render: (a) => formatDate(a.deletedAt) },
        { key: 'history', header: 'Still named by', sortValue: (a) => a.requests + a.approvals, render: (a) => retainedHistory(a) },
    ];

    return (
        <div className="space-y-3">
            <p className="text-sm text-ink-muted max-w-3xl">
                These accounts were deleted. They cannot sign in and hold no group, role or credential. Each is kept
                as a record because certificate requests or approvals still name it, and its username cannot be given
                to another account.
            </p>
            <DataTable<RetainedAccount>
                tableId="deleted-users"
                title="Deleted accounts"
                rows={rows}
                rowKey={(a) => a.id}
                loading={loading}
                error={error}
                empty="No deleted account is kept as a record"
                columns={columns}
                exportFileName="deleted-users"
            />
        </div>
    );
};

export default DeletedAccountsPanel;
