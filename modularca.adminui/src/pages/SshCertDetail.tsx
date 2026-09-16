import React, { useEffect, useState } from 'react';
import type { NoticeInput } from '@shared/notifications/notice';
import { InlineNotice } from '@shared/components/InlineNotice';
import { errorNotice } from '@shared-auth/api/notices';
import { useParams, useNavigate, useSearchParams } from 'react-router-dom';
import { apiGet, apiPost, apiBlob } from '../api/client';
import { useToast } from '@shared/context/ToastContext';
import { StatusBadge } from '@shared/components/cards/StatusBadge';
import { DetailField } from '@shared/components/cards/DetailField';
import ConfirmModal from '../components/ConfirmModal';
import { DetailPage, DetailSection } from '../components/DetailPage';

function formatDate(d: string | null) {
    if (!d) return '-';
    return new Date(d).toLocaleDateString('en-US', { year: 'numeric', month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' });
}

function downloadText(content: string, filename: string) {
    const blob = new Blob([content], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url; a.download = filename; a.click();
    URL.revokeObjectURL(url);
}

function parseList(val: any): string[] {
    if (Array.isArray(val)) return val;
    if (typeof val === 'string') {
        try { const parsed = JSON.parse(val); if (Array.isArray(parsed)) return parsed; } catch { }
        return val.split(',').map((s: string) => s.trim()).filter(Boolean);
    }
    return [];
}

/// <summary>
/// Read-only detail page for a single issued SSH certificate. SSH certs are CA-key-scoped, so the
/// owning CA key id is carried in the <c>caKey</c> query param for a robust deep-link/refresh. The
/// page is View-only (Edit disabled); download and revoke live in the action bar.
/// </summary>
const SshCertDetail: React.FC = () => {
    const { id } = useParams<{ id: string }>();
    const navigate = useNavigate();
    const { showToast } = useToast();
    const [searchParams] = useSearchParams();
    const caKey = searchParams.get('caKey') || '';

    const [cert, setCert] = useState<any | null>(null);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState<NoticeInput | null>(null);
    const [refresh, setRefresh] = useState(0);
    const [confirmOpen, setConfirmOpen] = useState(false);
    const [revoking, setRevoking] = useState(false);

    useEffect(() => {
        if (!caKey) { setError('Missing CA key reference — open this certificate from the SSH Certificates page.'); setLoading(false); return; }
        let cancelled = false;
        setLoading(true);
        setError(null);
        apiGet<any>(`/api/v1/admin/ssh/ca-keys/${caKey}/certificates`)
            .then((data) => {
                if (cancelled) return;
                const list = Array.isArray(data) ? data : (data.items || data.certificates || []);
                setCert(list.find((c: any) => c.id === id) || null);
                setLoading(false);
            })
            .catch((err) => { if (!cancelled) { setError(errorNotice(err, 'Failed to load certificate')); setLoading(false); } });
        return () => { cancelled = true; };
    }, [id, caKey, refresh]);

    const handleDownload = async () => {
        try {
            const resp = await apiBlob(`/api/v1/admin/ssh/certificates/${id}/download`);
            const text = await resp.text();
            downloadText(text, `${cert?.keyId || id}-cert.pub`);
        } catch (err: any) {
            showToast('error', err.message || 'Failed to download certificate');
        }
    };

    const doRevoke = async () => {
        setRevoking(true);
        try {
            await apiPost(`/api/v1/admin/ssh/ca-keys/${caKey}/certificates/${id}/revoke`, {});
            showToast('success', 'Certificate revoked');
            setRefresh((r) => r + 1);
        } catch (err: any) {
            showToast('error', err.message || 'Revocation failed');
        } finally {
            setRevoking(false);
            setConfirmOpen(false);
        }
    };

    if (loading) return <div className="p-6 text-sm text-gray-600 dark:text-gray-400">Loading…</div>;
    if (error) return (
        <div className="p-6 space-y-3">
            <InlineNotice notice={error} variant="line" />
            <button onClick={() => navigate('/ssh')} className="px-3 py-1.5 text-sm bg-gray-200 dark:bg-gray-700 rounded">Back to SSH Certificates</button>
        </div>
    );
    if (!cert) return (
        <div className="p-6 space-y-3">
            <p className="text-sm text-gray-600 dark:text-gray-400">SSH certificate not found.</p>
            <button onClick={() => navigate('/ssh')} className="px-3 py-1.5 text-sm bg-gray-200 dark:bg-gray-700 rounded">Back to SSH Certificates</button>
        </div>
    );

    const isUser = (cert.certificateType || cert.type || cert.certType || '').toLowerCase().includes('user');
    const isRevoked = cert.isRevoked;
    const principals = parseList(cert.principals);
    const extensions = parseList(cert.extensions);
    const title = cert.keyId || cert.identity || `#${cert.serialNumber || cert.serial}`;

    return (
        <DetailPage
            breadcrumbs={[{ label: 'SSH Certificates', to: '/ssh' }, { label: title }]}
            title={title}
            status={isRevoked ? <StatusBadge status="revoked" label="Revoked" /> : <StatusBadge status={isUser ? 'pending' : 'active'} label={isUser ? 'User' : 'Host'} />}
            subtitle={<span className="font-mono">#{cert.serialNumber || cert.serial}</span>}
            backTo="/ssh"
            actions={
                <div className="flex items-center gap-2 flex-wrap">
                    <button onClick={handleDownload} className="px-3 py-1.5 text-xs bg-gray-200 dark:bg-gray-700 text-gray-800 dark:text-gray-200 rounded hover:bg-gray-300 dark:hover:bg-gray-600 transition-colors">Download Certificate</button>
                    {!isRevoked && (
                        <button onClick={() => setConfirmOpen(true)} disabled={revoking}
                            className="px-3 py-1.5 text-xs bg-red-50 dark:bg-red-900/50 text-red-800 dark:text-red-300 border border-red-300 dark:border-red-700 rounded hover:bg-red-900 disabled:opacity-50 transition-colors">
                            {revoking ? 'Revoking…' : 'Revoke'}
                        </button>
                    )}
                </div>
            }
        >
            {() => (<>
                <DetailSection title="Certificate">
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-x-8">
                        <DetailField label="ID" value={cert.id} mono />
                        <DetailField label="Serial" value={cert.serialNumber || cert.serial} mono />
                        <DetailField label="Type" value={cert.certificateType || cert.type || cert.certType} />
                        <DetailField label="Key ID" value={cert.keyId || cert.identity} />
                        <DetailField label="Principals" value={principals.join(', ')} />
                        <DetailField label="Valid After" value={formatDate(cert.validAfter || cert.issuedAt)} />
                        <DetailField label="Valid Before" value={formatDate(cert.validBefore || cert.expiresAt)} />
                        <DetailField label="CA Key ID" value={cert.sshCaKeyId} mono />
                        {extensions.length > 0 && <DetailField label="Extensions" value={extensions.join(', ')} />}
                        <DetailField label="Revoked" value={isRevoked ? 'Yes' : 'No'} />
                        <DetailField label="Issued By" value={cert.issuedByUserId || '-'} mono />
                        <DetailField label="Source IP" value={cert.sourceIp || '-'} />
                    </div>
                </DetailSection>

                <ConfirmModal
                    isOpen={confirmOpen}
                    title="Revoke SSH Certificate"
                    message="Revoke this SSH certificate? This action cannot be undone."
                    confirmLabel="Revoke"
                    confirmClass="bg-red-600 hover:bg-red-700"
                    loading={revoking}
                    onConfirm={doRevoke}
                    onCancel={() => setConfirmOpen(false)}
                />
            </>)}
        </DetailPage>
    );
};

export default SshCertDetail;
