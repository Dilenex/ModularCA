import React, { useEffect, useState } from 'react';
import type { NoticeInput } from '@shared/notifications/notice';
import { InlineNotice } from '@shared/components/InlineNotice';
import { errorNotice } from '@shared-auth/api/notices';
import { useParams, useNavigate } from 'react-router-dom';
import { apiGet, apiDeleteWithMfa, apiBlob } from '../api/client';
import { useStepUp } from '../components/StepUpMfaContext';
import { useToast } from '@shared/context/ToastContext';
import { StatusBadge, Tag } from '@shared/components/cards/StatusBadge';
import { DetailField } from '@shared/components/cards/DetailField';
import ConfirmModal from '../components/ConfirmModal';
import { DetailPage, DetailSection } from '../components/DetailPage';
import { StepUpOps } from '@shared/generated';
import { actionButton, actionButtonDanger } from '@shared/components/actionButtons';

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


/// <summary>
/// Read-only detail page for a single SSH CA key: shows algorithm, validity, public key and
/// integration hints, with download / disable actions in the action bar. SSH CA keys are not
/// edited in place, so the page is View-only (Edit disabled).
/// </summary>
const SshCaKeyDetail: React.FC = () => {
    const { id } = useParams<{ id: string }>();
    const navigate = useNavigate();
    const { showToast } = useToast();
    const { requireStepUp } = useStepUp();

    const [key, setKey] = useState<any | null>(null);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState<NoticeInput | null>(null);
    const [refresh, setRefresh] = useState(0);
    const [confirmOpen, setConfirmOpen] = useState(false);
    const [disabling, setDisabling] = useState(false);

    useEffect(() => {
        let cancelled = false;
        setLoading(true);
        setError(null);
        apiGet<any>('/api/v1/admin/ssh/ca-keys')
            .then((data) => {
                if (cancelled) return;
                const list = Array.isArray(data) ? data : (data.items || data.keys || []);
                setKey(list.find((k: any) => k.id === id) || null);
                setLoading(false);
            })
            .catch((err) => { if (!cancelled) { setError(errorNotice(err, 'Failed to load CA key')); setLoading(false); } });
        return () => { cancelled = true; };
    }, [id, refresh]);

    const handleDownloadPublicKey = () => {
        if (key?.publicKey) downloadText(key.publicKey, `${key.name || key.id}.pub`);
    };

    const handleDownloadKrl = async () => {
        try {
            const resp = await apiBlob(`/api/v1/admin/ssh/ca-keys/${id}/krl`);
            const blob = await resp.blob();
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url; a.download = 'revoked_keys.krl'; a.click();
            URL.revokeObjectURL(url);
        } catch (err: any) {
            showToast('error', err.message || 'Failed to download KRL');
        }
    };

    const doDisable = async () => {
        setDisabling(true);
        try {
            const result: any = await apiDeleteWithMfa(`/api/v1/admin/ssh/ca-keys/${id}`, requireStepUp, StepUpOps.DisableSshCa, id!);
            if (result?.requiresCeremony) {
                showToast('info', result.message || 'Key ceremony created for approval.');
                setRefresh((r) => r + 1);
            } else {
                showToast('success', 'CA key disabled successfully.');
                navigate('/ssh');
            }
        } catch (err: any) {
            if (err.message !== 'Step-up MFA cancelled') showToast('error', err.message || 'Failed to disable CA key');
        } finally {
            setDisabling(false);
            setConfirmOpen(false);
        }
    };

    if (loading) return <div className="p-6 text-sm text-ink-muted">Loading…</div>;
    if (error) return <InlineNotice notice={error} />;
    if (!key) return (
        <div className="p-6 space-y-3">
            <p className="text-sm text-ink-muted">SSH CA key not found.</p>
            <button onClick={() => navigate('/ssh')} className="px-3 py-1.5 text-sm bg-sunken rounded">Back to SSH Certificates</button>
        </div>
    );

    const enabled = key.isEnabled !== false;
    const algorithm = `${key.keyType || key.algorithm}${key.keySize ? ` (${key.keySize} bits)` : ''}`;

    return (
        <DetailPage
            breadcrumbs={[{ label: 'SSH Certificates', to: '/ssh' }, { label: key.name || 'Unnamed' }]}
            title={key.name || 'Unnamed'}
            status={enabled ? <Tag label="CA Key" /> : <StatusBadge status="revoked" label="Disabled" />}
            subtitle={algorithm}
            backTo="/ssh"
            actions={
                <div className="flex items-center gap-2 flex-wrap">
                    <button onClick={handleDownloadPublicKey} className={actionButton}>Download Public Key (.pub)</button>
                    <button onClick={handleDownloadKrl} className={actionButton}>Download KRL</button>
                    {enabled && (
                        <button onClick={() => setConfirmOpen(true)} disabled={disabling}
                            className={actionButtonDanger}>
                            {disabling ? 'Disabling…' : 'Disable'}
                        </button>
                    )}
                </div>
            }
        >
            {() => (<>
                <DetailSection title="SSH CA Key">
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-x-8">
                        <DetailField label="ID" value={key.id} mono />
                        <DetailField label="Algorithm" value={algorithm} />
                        <DetailField label="Max Validity" value={`${key.maxValidityHours}h`} />
                        <DetailField label="Created" value={formatDate(key.createdAt)} />
                        <DetailField label="User CA" value={key.isUserCa ? 'Yes' : 'No'} />
                        <DetailField label="Host CA" value={key.isHostCa ? 'Yes' : 'No'} />
                    </div>
                    <div className="mt-2">
                        <DetailField label="Public Key" value={key.publicKey} mono />
                    </div>
                </DetailSection>

                <DetailSection title="Integration">
                    <div className="text-xs text-ink-muted space-y-1">
                        {key.isUserCa && (
                            <p><span className="text-ink font-medium">User CA:</span> Add to <code className="text-accent-ink">TrustedUserCAKeys</code> in sshd_config</p>
                        )}
                        {key.isHostCa && (
                            <p><span className="text-ink font-medium">Host CA:</span> Add to <code className="text-accent-ink">known_hosts</code> with <code className="text-accent-ink">@cert-authority * {key.publicKey?.split(' ').slice(0, 2).join(' ')}...</code></p>
                        )}
                        <p><span className="text-ink font-medium">Public URL:</span> <code className="text-accent-ink">/ssh/ca-keys/{key.id}/public-key</code></p>
                    </div>
                </DetailSection>

                <ConfirmModal
                    isOpen={confirmOpen}
                    title="Disable SSH CA Key"
                    message={`Disable "${key.name}"? All active certificates will be revoked. This action cannot be undone.`}
                    confirmLabel="Disable"
                    tone="crit"
                    loading={disabling}
                    onConfirm={doDisable}
                    onCancel={() => setConfirmOpen(false)}
                />
            </>)}
        </DetailPage>
    );
};

export default SshCaKeyDetail;
