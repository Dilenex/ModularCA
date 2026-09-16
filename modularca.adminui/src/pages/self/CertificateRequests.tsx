import React, { useState, useEffect } from 'react';
import type { NoticeInput } from '@shared/notifications/notice';
import { errorNotice } from '@shared-auth/api/notices';
import { apiGet } from '../../api/client';
import { StatusBadge } from '@shared/components/cards/StatusBadge';
import { DataTable, type DataTableColumn } from '@shared/components/DataTable';
import { Link } from 'react-router-dom';

function formatDate(d: string | null) {
    if (!d) return '-';
    return new Date(d).toLocaleDateString('en-US', { year: 'numeric', month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' });
}

function statusType(status: string): 'active' | 'pending' | 'disabled' | 'enabled' {
    switch (status?.toLowerCase()) {
        case 'approved': return 'active';
        case 'pending': return 'pending';
        case 'rejected': return 'disabled';
        case 'issued': return 'enabled';
        default: return 'pending';
    }
}

interface CertRequest {
    id: string;
    subjectDN: string;
    status: string;
    submittedAt: string;
    certProfileId: string | null;
    signingProfileId: string | null;
    issuedCertificateSerial: string | null;
}

const CertificateRequests: React.FC = () => {
    const [requests, setRequests] = useState<CertRequest[]>([]);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState<NoticeInput | null>(null);

    useEffect(() => {
        apiGet<CertRequest[]>('/api/v1/user/requests')
            .then((data) => setRequests(Array.isArray(data) ? data : []))
            .catch((err) => setError(errorNotice(err, 'The request failed.')))
            .finally(() => setLoading(false));
    }, []);

    const columns: DataTableColumn<CertRequest>[] = [
        {
            key: 'status', header: 'Status', defaultWidth: 110, truncate: false,
            exportValue: (r) => r.status,
            render: (r) => <StatusBadge status={statusType(r.status)} label={r.status} />,
        },
        {
            key: 'subject', header: 'Subject', defaultWidth: 280,
            exportValue: (r) => r.subjectDN || '(no subject)',
            render: (r) => <span className="text-sm text-gray-900 dark:text-white truncate">{r.subjectDN || '(no subject)'}</span>,
        },
        {
            key: 'issued', header: 'Issued Serial', defaultWidth: 180,
            exportValue: (r) => r.issuedCertificateSerial || '',
            render: (r) => r.issuedCertificateSerial
                ? <span className="font-mono text-xs text-green-800 dark:text-green-400 truncate">{r.issuedCertificateSerial}</span>
                : <span className="text-xs text-gray-500">-</span>,
        },
        {
            key: 'submitted', header: 'Submitted', defaultWidth: 200, truncate: false,
            exportValue: (r) => formatDate(r.submittedAt),
            render: (r) => <span className="text-xs text-gray-600 dark:text-gray-400 whitespace-nowrap">{formatDate(r.submittedAt)}</span>,
        },
    ];

    const renderExpanded = (req: CertRequest) => (
        <div className="space-y-2">
            <div className="grid grid-cols-1 md:grid-cols-2 gap-2 text-sm">
                <div>
                    <span className="text-xs text-gray-600">Request ID</span>
                    <p className="font-mono text-xs text-gray-800 dark:text-gray-200 break-all">{req.id}</p>
                </div>
                <div>
                    <span className="text-xs text-gray-600">Subject</span>
                    <p className="text-xs text-gray-800 dark:text-gray-200 break-all">{req.subjectDN || '-'}</p>
                </div>
                <div>
                    <span className="text-xs text-gray-600">Status</span>
                    <p className="text-xs text-gray-800 dark:text-gray-200">{req.status}</p>
                </div>
                <div>
                    <span className="text-xs text-gray-600">Submitted</span>
                    <p className="text-xs text-gray-800 dark:text-gray-200">{formatDate(req.submittedAt)}</p>
                </div>
            </div>
            {req.issuedCertificateSerial && (
                <div className="pt-2 border-t border-gray-300 dark:border-gray-700">
                    <span className="text-xs text-gray-600">Issued Certificate</span>
                    <p className="font-mono text-xs text-green-800 dark:text-green-400 break-all">{req.issuedCertificateSerial}</p>
                    <Link to="/certificates" className="text-xs text-blue-800 dark:text-blue-400 hover:underline mt-1 inline-block">
                        View in My Certificates
                    </Link>
                </div>
            )}
            {req.status?.toLowerCase() === 'rejected' && (
                <div className="pt-2 border-t border-gray-300 dark:border-gray-700">
                    <span className="text-xs text-red-800 dark:text-red-400">This request was rejected by an administrator.</span>
                </div>
            )}
        </div>
    );

    return (
        <div className="p-3 sm:p-6 space-y-4 sm:space-y-6">
            <div className="flex items-center justify-between">
                <h1 className="text-2xl font-bold text-gray-900 dark:text-white">My Requests</h1>
                <Link to="/request" className="px-4 py-2 text-sm font-medium bg-blue-600 text-white rounded hover:bg-blue-700 transition-colors">
                    New Request
                </Link>
            </div>

            <DataTable<CertRequest>
                tableId="my-requests"
                title="Requests"
                rows={requests}
                rowKey={(r) => r.id}
                loading={loading}
                error={error}
                empty="No certificate requests found."
                columns={columns}
                exportFileName="my-requests"
                renderExpanded={renderExpanded}
            />
        </div>
    );
};

export default CertificateRequests;
