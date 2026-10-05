import React, { useState, useEffect } from 'react';
import type { NoticeInput } from '@shared/notifications/notice';
import { errorNotice } from '@shared-auth/api/notices';
import { apiGet, apiBlob } from '../../api/client';
import { useToast } from '@shared/context/ToastContext';
import { StatusBadge } from '@shared/components/cards/StatusBadge';
import { DetailField } from '@shared/components/cards/DetailField';
import { DataTable, type DataTableColumn } from '@shared/components/DataTable';

function formatDate(d: string | null) {
    if (!d) return '-';
    return new Date(d).toLocaleDateString('en-US', { year: 'numeric', month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' });
}

function sshCertStatus(cert: any): 'active' | 'revoked' | 'expired' {
    if (cert.isRevoked) return 'revoked';
    if (new Date(cert.validBefore) < new Date()) return 'expired';
    return 'active';
}

function statusBadgeType(s: string): 'active' | 'disabled' | 'pending' {
    if (s === 'active') return 'active';
    if (s === 'revoked') return 'disabled';
    return 'pending';
}

interface SshCertificate {
    id: string;
    serialNumber: string;
    keyId: string;
    // Backend stores principals as a JSON-encoded string (e.g. '["alice","bob"]').
    // Tolerate the string form and also accept a real array in case the projection
    // is ever changed server-side.
    principals: string | string[];
    validAfter: string;
    validBefore: string;
    isRevoked: boolean;
    sshCaKeyId: string;
}

function formatPrincipals(raw: string | string[] | null | undefined): string {
    if (raw == null) return '-';
    if (Array.isArray(raw)) return raw.length === 0 ? '-' : raw.join(', ');
    const trimmed = raw.trim();
    if (trimmed === '' || trimmed === '[]') return '-';
    try {
        const parsed = JSON.parse(trimmed);
        if (Array.isArray(parsed)) return parsed.length === 0 ? '-' : parsed.join(', ');
    } catch {
        // Not JSON — fall back to the raw string.
    }
    return trimmed;
}

const MySshCertificates: React.FC = () => {
    const { showToast } = useToast();
    const [certificates, setCertificates] = useState<SshCertificate[]>([]);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState<NoticeInput | null>(null);
    const [endpointUnavailable, setEndpointUnavailable] = useState(false);

    useEffect(() => {
        apiGet<SshCertificate[]>('/api/v1/user/ssh/certificates')
            .then((data) => setCertificates(Array.isArray(data) ? data : []))
            .catch((err) => {
                if (err.message?.includes('404') || err.message?.includes('Not Found')) {
                    setEndpointUnavailable(true);
                } else {
                    setError(errorNotice(err, 'The request failed.'));
                }
            })
            .finally(() => setLoading(false));
    }, []);

    const handleDownload = async (cert: SshCertificate) => {
        try {
            const resp = await apiBlob(`/api/v1/user/ssh/certificates/${cert.id}/download`);
            const text = await resp.text();
            const blob = new Blob([text], { type: 'text/plain' });
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = `${cert.keyId || cert.id}-cert.pub`;
            a.click();
            URL.revokeObjectURL(url);
        } catch (err: any) {
            showToast('error', err.message || 'Download failed');
        }
    };

    const columns: DataTableColumn<SshCertificate>[] = [
        {
            key: 'status', header: 'Status', defaultWidth: 110, truncate: false,
            exportValue: (c) => sshCertStatus(c),
            render: (c) => {
                const s = sshCertStatus(c);
                return <StatusBadge status={statusBadgeType(s)} label={s.charAt(0).toUpperCase() + s.slice(1)} />;
            },
        },
        {
            key: 'keyId', header: 'Key ID', defaultWidth: 220,
            exportValue: (c) => c.keyId || c.id,
            render: (c) => <span className="text-sm text-ink truncate">{c.keyId || c.id}</span>,
        },
        {
            key: 'principals', header: 'Principals', defaultWidth: 180,
            exportValue: (c) => formatPrincipals(c.principals),
            render: (c) => <span className="text-xs text-ink-muted truncate">{formatPrincipals(c.principals)}</span>,
        },
        {
            key: 'validBefore', header: 'Valid Until', defaultWidth: 200, truncate: false,
            exportValue: (c) => formatDate(c.validBefore),
            render: (c) => <span className="text-xs text-ink-muted whitespace-nowrap">{formatDate(c.validBefore)}</span>,
        },
    ];

    const renderExpanded = (cert: SshCertificate) => {
        const status = sshCertStatus(cert);
        return (
            <div className="space-y-3">
                <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
                    <DetailField label="Key ID" value={cert.keyId} />
                    <DetailField label="Serial Number" value={cert.serialNumber} mono />
                    <DetailField label="Principals" value={formatPrincipals(cert.principals)} />
                    <DetailField label="Valid After" value={formatDate(cert.validAfter)} />
                    <DetailField label="Valid Before" value={formatDate(cert.validBefore)} />
                </div>

                {status === 'revoked' && (
                    <div className="bg-crit-soft border border-crit/40 rounded p-2">
                        <span className="text-xs text-crit">This certificate has been revoked.</span>
                    </div>
                )}

                <div className="flex flex-wrap gap-2 pt-2 border-t border-line">
                    <button
                        onClick={() => handleDownload(cert)}
                        className="px-3 py-1.5 text-xs bg-accent text-on-accent rounded hover:bg-accent-hover transition-colors"
                    >
                        Download Certificate
                    </button>
                </div>
            </div>
        );
    };

    return (
        <div className="p-3 sm:p-6 space-y-4 sm:space-y-6">
            <h1 className="text-xl font-semibold text-ink">SSH Certificates</h1>

            {endpointUnavailable ? (
                <div className="bg-raised border border-line rounded-lg p-8 text-center">
                    <p className="text-ink-muted">SSH certificates will appear here once issued.</p>
                </div>
            ) : (
                <DataTable<SshCertificate>
                    tableId="my-ssh-certificates"
                    title="SSH Certificates"
                    rows={certificates}
                    rowKey={(c) => c.id}
                    loading={loading}
                    error={error}
                    empty="No SSH certificates found. They will appear here once issued."
                    columns={columns}
                    exportFileName="my-ssh-certificates"
                    renderExpanded={renderExpanded}
                />
            )}
        </div>
    );
};

export default MySshCertificates;
