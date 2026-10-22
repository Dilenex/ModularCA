import React, { useEffect, useState } from 'react';
import type { NoticeInput } from '@shared/notifications/notice';
import { InlineNotice } from '@shared/components/InlineNotice';
import { errorNotice } from '@shared-auth/api/notices';
import { useParams, useNavigate, useSearchParams, useLocation, Link } from 'react-router-dom';
import { apiGet, apiBlob, apiPostWithMfa } from '../api/client';
import { useToast } from '@shared/context/ToastContext';
import { StatusBadge, Tag } from '@shared/components/cards/StatusBadge';
import { DetailField } from '@shared/components/cards/DetailField';
import ConfirmModal from '../components/ConfirmModal';
import { DetailPage, DetailSection } from '../components/DetailPage';
import { actionButton, actionButtonDanger } from '@shared/components/actionButtons';
import { StepUpOps } from '@shared/generated';
import { useStepUp } from '../components/StepUpMfaContext';
import { LoginNameGrounds, SignedCertificateHandOver } from '../components/SshCertificateParts';
import {
    certificateBadge, certificateStatus, dayTimeText, isUserCertificate, issuedByDetail, issuedToDetail, issuedToText, jsonList, sshdKeyType,
    type SshCertificateView,
} from './sshLoginNames';
import { SSH_CERTIFICATES_PATH, SSH_SIGN_PATH, signedHandOver, sshCaKeyPath } from './sshPlaces';

function downloadText(content: string, filename: string) {
    const blob = new Blob([content], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url; a.download = filename; a.click();
    URL.revokeObjectURL(url);
}

/// <summary>
/// Read-only detail page for a single issued SSH certificate, under Certificates: who it was issued to and by, the
/// name hosts log for it, and for a user certificate each login name with why its holder had it.
/// A <c>used</c> query param, set when the page is opened from a host log line, marks the login
/// name that line shows. The Sign key form opens this page with the certificate it signed in the
/// navigation state, which the page hands over for copy and download until dismissed. The page
/// is View-only (Edit disabled); download and revoke live in the action bar.
/// </summary>
const SshCertDetail: React.FC = () => {
    const { id } = useParams<{ id: string }>();
    const navigate = useNavigate();
    const location = useLocation();
    const handOver = signedHandOver(location.state, id);
    const { showToast } = useToast();
    const { requireStepUp } = useStepUp();
    const [searchParams] = useSearchParams();
    const usedName = searchParams.get('used');

    const [cert, setCert] = useState<SshCertificateView | null>(null);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState<NoticeInput | null>(null);
    const [refresh, setRefresh] = useState(0);
    const [confirmOpen, setConfirmOpen] = useState(false);
    const [revoking, setRevoking] = useState(false);

    useEffect(() => {
        let cancelled = false;
        setLoading(true);
        setError(null);
        apiGet<SshCertificateView>(`/api/v1/admin/ssh/certificates/${id}`, { toast: false })
            .then((data) => { if (!cancelled) { setCert(data || null); setLoading(false); } })
            .catch((err) => {
                if (cancelled) return;
                if (err?.problem?.status === 404) setCert(null);
                else setError(errorNotice(err, 'Failed to load certificate'));
                setLoading(false);
            });
        return () => { cancelled = true; };
    }, [id, refresh]);

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
        if (!cert) return;
        setRevoking(true);
        try {
            await apiPostWithMfa(`/api/v1/admin/ssh/ca-keys/${cert.sshCaKeyId}/certificates/${id}/revoke`, {}, requireStepUp, StepUpOps.RevokeSshCert, id);
            showToast('success', 'Certificate revoked');
            setRefresh((r) => r + 1);
        } catch (err: any) {
            if (err.message !== 'Step-up MFA cancelled') showToast('error', err.message || 'Revocation failed');
        } finally {
            setRevoking(false);
            setConfirmOpen(false);
        }
    };

    if (loading) return <div className="p-6 text-sm text-ink-muted">Loading…</div>;
    if (error) return (
        <div className="p-6 space-y-3">
            <InlineNotice notice={error} variant="line" />
            <button onClick={() => navigate(SSH_CERTIFICATES_PATH)} className="px-3 py-1.5 text-sm bg-sunken rounded">Back to SSH certificates</button>
        </div>
    );
    if (!cert) return (
        <div className="p-6 space-y-3">
            <p className="text-sm text-ink-muted">SSH certificate not found, or it was issued by an SSH CA you may not view.</p>
            <button onClick={() => navigate(SSH_CERTIFICATES_PATH)} className="px-3 py-1.5 text-sm bg-sunken rounded">Back to SSH certificates</button>
        </div>
    );

    const isUser = isUserCertificate(cert);
    const status = certificateStatus(cert, new Date());
    const names = jsonList(cert.principals);
    const extensions = jsonList(cert.extensions);
    const title = `Certificate ${cert.serialNumber}`;
    const subject = cert.subject;

    return (
        <DetailPage
            breadcrumbs={[{ label: 'All Certificates', to: SSH_CERTIFICATES_PATH }, { label: title }]}
            title={title}
            status={<>
                <StatusBadge {...certificateBadge(status)} />
                <Tag label={isUser ? 'User certificate' : 'Host certificate'} />
            </>}
            subtitle={<>Issued to {issuedToText(cert)}</>}
            backTo={SSH_CERTIFICATES_PATH}
            actions={
                <div className="flex items-center gap-2 flex-wrap">
                    <button onClick={handleDownload} className={actionButton}>Download Certificate</button>
                    {!cert.isRevoked && (
                        <button onClick={() => setConfirmOpen(true)} disabled={revoking}
                            className={actionButtonDanger}>
                            {revoking ? 'Revoking…' : 'Revoke'}
                        </button>
                    )}
                </div>
            }
        >
            {() => (<>
                {handOver && (
                    <SignedCertificateHandOver
                        title="Certificate signed"
                        signedCertificate={handOver.signedCertificate}
                        publicKey={handOver.publicKey || cert.publicKey || ''}
                        forHost={!isUser}
                        onDismiss={() => navigate(`${location.pathname}${location.search}`, { replace: true, state: null })}
                    >
                        {handOver.forUser && <>{handOver.forUser} also finds it under My Certificates, on the SSH tab, in their own portal. </>}
                        <Link to={SSH_SIGN_PATH} className="text-accent-ink hover:underline">Sign another key</Link>.
                    </SignedCertificateHandOver>
                )}
                <DetailSection title="Certificate">
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-x-8">
                        <DetailField label="Issued to" value={subject?.kind === 'user' && subject.userId
                            ? <><Link to={`/users/${subject.userId}`} className="text-accent-ink hover:underline">{subject.username || cert.keyId}</Link>, a user of this console</>
                            : issuedToDetail(cert)} />
                        <DetailField label="Issued by" value={issuedByDetail(cert)} />
                        <DetailField label="Name in host logs" value={cert.keyId} mono />
                        <DetailField label="SSH CA" value={<Link to={sshCaKeyPath(cert.sshCaKeyId)} className="text-accent-ink hover:underline">{cert.sshCaKey?.name || cert.sshCaKeyId}</Link>} />
                        <DetailField label="Serial" value={String(cert.serialNumber)} mono />
                        <DetailField label="Valid" value={`${dayTimeText(cert.validAfter)} to ${dayTimeText(cert.validBefore)}`} />
                        {cert.isRevoked && <DetailField label="Revoked" value={cert.revokedAt ? dayTimeText(cert.revokedAt) : 'Yes. The time was not recorded.'} />}
                        <DetailField label="Key" value={cert.keyFingerprint ? `${sshdKeyType(cert.publicKey)} ${cert.keyFingerprint}` : null} mono />
                        <DetailField label="SSH CA fingerprint" value={cert.sshCaKey?.fingerprint} mono />
                        {!isUser && <DetailField label="Hostnames" value={names.join(', ')} />}
                        {extensions.length > 0 && <DetailField label="Extensions" value={extensions.join(', ')} />}
                        <DetailField label="ID" value={cert.id} mono />
                    </div>
                    <p className="mt-2 text-xs text-ink-muted max-w-3xl">
                        The CA writes the name in host logs: a user's username, svc: and the label of a service identity, or a host certificate's first hostname. Every host records it with each login, whichever account is used.
                    </p>
                </DetailSection>

                {isUser && (
                    <DetailSection title={`Login names, and why ${subject?.kind === 'user' || subject?.kind === 'service' ? issuedToText(cert) : 'the holder'} had each`}>
                        <p className="mb-3 text-xs text-ink-muted max-w-3xl">
                            The accounts this certificate may log in as, with the reason each was allowed when the certificate was issued. A login name is the SSH principal.
                        </p>
                        <LoginNameGrounds cert={cert} usedName={usedName} linkGroups />
                    </DetailSection>
                )}

                <ConfirmModal
                    isOpen={confirmOpen}
                    title="Revoke SSH Certificate"
                    message="Revoke this SSH certificate? A host refuses it once the host has fetched the SSH CA's revocation list. This action cannot be undone."
                    confirmLabel="Revoke"
                    tone="crit"
                    loading={revoking}
                    onConfirm={doRevoke}
                    onCancel={() => setConfirmOpen(false)}
                />
            </>)}
        </DetailPage>
    );
};

export default SshCertDetail;
