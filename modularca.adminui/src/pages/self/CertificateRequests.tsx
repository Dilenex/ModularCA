import React, { useState, useEffect } from 'react';
import type { NoticeInput } from '@shared/notifications/notice';
import { errorNotice } from '@shared-auth/api/notices';
import { apiGet } from '../../api/client';
import { StatusBadge } from '@shared/components/cards/StatusBadge';
import { DataTable, type DataTableColumn } from '@shared/components/DataTable';
import { Link } from 'react-router-dom';
import { HeldKeyDownload } from '../../components/HeldKeyDownload';

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
    /** The CA still holds the key it generated for this request. */
    keyHeld: boolean;
    /** When that key was delivered as a .pfx, if it was. */
    heldKeyDeliveredAt: string | null;
}

function subjectCn(subjectDN: string | null): string {
    const m = /(?:^|,)\s*CN=([^,]+)/i.exec(subjectDN || '');
    return (m?.[1] || subjectDN || 'certificate').trim();
}

const CertificateRequests: React.FC = () => {
    const [requests, setRequests] = useState<CertRequest[]>([]);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState<NoticeInput | null>(null);

    const [refresh, setRefresh] = useState(0);
    useEffect(() => {
        apiGet<CertRequest[]>('/api/v1/user/requests')
            .then((data) => setRequests(Array.isArray(data) ? data : []))
            .catch((err) => setError(errorNotice(err, 'The request failed.')))
            .finally(() => setLoading(false));
    }, [refresh]);

    const columns: DataTableColumn<CertRequest>[] = [
        {
            key: 'status', header: 'Status', defaultWidth: 110, truncate: false,
            exportValue: (r) => r.status,
            render: (r) => <StatusBadge status={statusType(r.status)} label={r.status} />,
        },
        {
            key: 'subject', header: 'Subject', defaultWidth: 280,
            exportValue: (r) => r.subjectDN || '(no subject)',
            render: (r) => <span className="text-sm text-ink truncate">{r.subjectDN || '(no subject)'}</span>,
        },
        {
            key: 'issued', header: 'Issued Serial', defaultWidth: 180,
            exportValue: (r) => r.issuedCertificateSerial || '',
            render: (r) => r.issuedCertificateSerial
                ? <span className="data-mono text-ok truncate">{r.issuedCertificateSerial}</span>
                : <span className="text-xs text-ink-muted">-</span>,
        },
        {
            key: 'key', header: 'Private Key', defaultWidth: 150, truncate: false,
            exportValue: (r) => r.heldKeyDeliveredAt ? 'Delivered' : r.keyHeld ? (r.issuedCertificateSerial ? 'Ready to download' : 'Held by the CA') : '',
            render: (r) => r.heldKeyDeliveredAt
                ? <span className="text-xs text-ink-muted">Delivered</span>
                : r.keyHeld
                    ? (r.issuedCertificateSerial
                        ? <span className="text-xs font-medium text-ok">Ready to download</span>
                        : <span className="text-xs text-warn">Held by the CA</span>)
                    : <span className="text-xs text-ink-muted">-</span>,
        },
        {
            key: 'submitted', header: 'Submitted', defaultWidth: 200, truncate: false,
            exportValue: (r) => formatDate(r.submittedAt),
            render: (r) => <span className="text-xs text-ink-muted whitespace-nowrap">{formatDate(r.submittedAt)}</span>,
        },
    ];

    const renderExpanded = (req: CertRequest) => (
        <div className="space-y-2">
            <div className="grid grid-cols-1 md:grid-cols-2 gap-2 text-sm">
                <div>
                    <span className="text-xs text-ink-muted">Request ID</span>
                    <p className="data-mono text-ink break-all">{req.id}</p>
                </div>
                <div>
                    <span className="text-xs text-ink-muted">Subject</span>
                    <p className="text-xs text-ink break-all">{req.subjectDN || '-'}</p>
                </div>
                <div>
                    <span className="text-xs text-ink-muted">Status</span>
                    <p className="text-xs text-ink">{req.status}</p>
                </div>
                <div>
                    <span className="text-xs text-ink-muted">Submitted</span>
                    <p className="text-xs text-ink">{formatDate(req.submittedAt)}</p>
                </div>
            </div>
            {req.issuedCertificateSerial && (
                <div className="pt-2 border-t border-line">
                    <span className="text-xs text-ink-muted">Issued Certificate</span>
                    <p className="data-mono text-ok break-all">{req.issuedCertificateSerial}</p>
                    <Link to="/certificates" className="text-xs text-accent-ink hover:underline mt-1 inline-block">
                        View in My Certificates
                    </Link>
                </div>
            )}
            {(req.keyHeld || req.heldKeyDeliveredAt) && (
                <div className="pt-2 border-t border-line space-y-1">
                    <span className="text-xs text-ink-muted">Private Key</span>
                    {req.keyHeld && !req.issuedCertificateSerial && (
                        <p className="text-xs text-warn">
                            Your private key is held by the CA until the certificate is issued. The .pfx download appears here once it is approved.
                        </p>
                    )}
                    <HeldKeyDownload
                        endpoint={`/api/v1/user/requests/${encodeURIComponent(req.id)}/pkcs12`}
                        requestId={req.id}
                        fileName={subjectCn(req.subjectDN)}
                        keyHeld={req.keyHeld}
                        deliveredAt={req.heldKeyDeliveredAt}
                        issued={!!req.issuedCertificateSerial}
                        onDelivered={() => setRefresh((n) => n + 1)}
                    />
                </div>
            )}
            {req.status?.toLowerCase() === 'rejected' && (
                <div className="pt-2 border-t border-line">
                    <span className="text-xs text-crit">This request was rejected by an administrator.</span>
                </div>
            )}
        </div>
    );

    return (
        <div className="p-3 sm:p-6 space-y-4 sm:space-y-6">
            <div className="flex items-center justify-between">
                <h1 className="text-xl font-semibold text-ink">My Requests</h1>
                <Link to="/request" className="px-4 py-2 text-sm font-medium bg-accent text-on-accent rounded hover:bg-accent-hover transition-colors">
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
