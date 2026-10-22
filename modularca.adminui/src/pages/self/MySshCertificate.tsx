import React, { useEffect, useState } from 'react';
import { Link, useLocation, useNavigate, useParams } from 'react-router-dom';
import type { NoticeInput } from '@shared/notifications/notice';
import { InlineNotice } from '@shared/components/InlineNotice';
import { errorNotice } from '@shared-auth/api/notices';
import { StatusBadge } from '@shared/components/cards/StatusBadge';
import { actionButton } from '@shared/components/actionButtons';
import { apiBlob, apiGet } from '../../api/client';
import { useToast } from '@shared/context/ToastContext';
import { DetailPage, DetailSection } from '../../components/DetailPage';
import { SignedCertificateHandOver } from '../../components/SshCertificateParts';
import { certificateBadge, certificateStatus, type SshCertificateView } from '../sshLoginNames';
import { SELF_SSH_CERTIFICATES_PATH, SELF_SSH_REQUEST_PATH, signedHandOver } from '../sshPlaces';
import { MySshCertificateFields } from './MySshCertificates';

function downloadText(content: string, filename: string) {
    const blob = new Blob([content], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url; a.download = filename; a.click();
    URL.revokeObjectURL(url);
}

/// <summary>
/// One of the reader's SSH certificates, on a page of its own in self-service. The request form
/// opens it with the certificate just signed in the navigation state, which the page hands over
/// for copy and download until dismissed.
/// </summary>
const MySshCertificate: React.FC = () => {
    const { id } = useParams<{ id: string }>();
    const navigate = useNavigate();
    const location = useLocation();
    const { showToast } = useToast();
    const handOver = signedHandOver(location.state, id);
    const [cert, setCert] = useState<SshCertificateView | null>(null);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState<NoticeInput | null>(null);

    useEffect(() => {
        let cancelled = false;
        setLoading(true);
        apiGet<SshCertificateView[]>('/api/v1/user/ssh/certificates', { toast: false })
            .then((data) => { if (!cancelled) setCert((Array.isArray(data) ? data : []).find((c) => c.id === id) ?? null); })
            .catch((err) => { if (!cancelled) setError(errorNotice(err, 'Failed to load the certificate')); })
            .finally(() => { if (!cancelled) setLoading(false); });
        return () => { cancelled = true; };
    }, [id]);

    const handleDownload = async () => {
        try {
            const resp = await apiBlob(`/api/v1/user/ssh/certificates/${id}/download`);
            downloadText(await resp.text(), `${cert?.keyId || id}-cert.pub`);
        } catch (err: any) {
            showToast('error', err.message || 'Download failed');
        }
    };

    if (loading) return <div className="p-6 text-sm text-ink-muted">Loading…</div>;
    if (error || !cert) return (
        <div className="p-6 space-y-3">
            {error ? <InlineNotice notice={error} variant="line" /> : <p className="text-sm text-ink-muted">SSH certificate not found among your certificates.</p>}
            <Link to={SELF_SSH_CERTIFICATES_PATH} className={actionButton}>Back to my SSH certificates</Link>
        </div>
    );

    return (
        <DetailPage
            breadcrumbs={[{ label: 'My Certificates', to: SELF_SSH_CERTIFICATES_PATH }, { label: `Certificate ${cert.serialNumber}` }]}
            title={`Certificate ${cert.serialNumber}`}
            status={<StatusBadge {...certificateBadge(certificateStatus(cert, new Date()))} />}
            subtitle={<>SSH user certificate from {cert.sshCaKey?.name || 'an SSH CA'}</>}
            backTo={SELF_SSH_CERTIFICATES_PATH}
            modeToggle={false}
            actions={<button onClick={handleDownload} className={actionButton}>Download Certificate</button>}
        >
            {() => (<>
                {handOver && (
                    <SignedCertificateHandOver
                        title="Your certificate is ready"
                        signedCertificate={handOver.signedCertificate}
                        publicKey={handOver.publicKey || cert.publicKey || ''}
                        onDismiss={() => navigate(location.pathname, { replace: true, state: null })}
                    >
                        It stays under <Link to={SELF_SSH_CERTIFICATES_PATH} className="text-accent-ink hover:underline">My Certificates, on the SSH tab</Link>; Download Certificate above names the file after you, so rename it the same way. <Link to={SELF_SSH_REQUEST_PATH} className="text-accent-ink hover:underline">Request another</Link>.
                    </SignedCertificateHandOver>
                )}
                <DetailSection title="Certificate">
                    <MySshCertificateFields cert={cert} />
                </DetailSection>
            </>)}
        </DetailPage>
    );
};

export default MySshCertificate;
