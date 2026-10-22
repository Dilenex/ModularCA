import React, { useEffect, useState } from 'react';
import type { NoticeInput } from '@shared/notifications/notice';
import { InlineNotice } from '@shared/components/InlineNotice';
import { errorNotice } from '@shared-auth/api/notices';
import { useParams, useNavigate } from 'react-router-dom';
import { apiGet, apiPut, apiDeleteWithMfa, apiBlob } from '../api/client';
import { useStepUp } from '../components/StepUpMfaContext';
import { useToast } from '@shared/context/ToastContext';
import { StatusBadge } from '@shared/components/cards/StatusBadge';
import { DetailField } from '@shared/components/cards/DetailField';
import ConfirmModal from '../components/ConfirmModal';
import { DetailPage, DetailSection } from '../components/DetailPage';
import { StepUpOps } from '@shared/generated';
import { actionButton, actionButtonDanger } from '@shared/components/actionButtons';
import { signBlockedReason, sshKeyCustody } from './sshKeyCustody';
import { SshPlaintextNoticePanel, useSshPlaintextNotice } from '../components/SshPlaintextNotice';
import { SshKeyLoginNames } from '../components/SshLoginNameGrants';
import { KRL_DESTINATION, krlLastRevocationText, krlVersionText } from './sshKrl';
import { Capabilities } from '@shared/generated';
import { useAuth } from '../context/AuthContext';
import { FieldHint, inputClassNarrow, labelClass } from '@shared/components/forms';
import { actionButtonPrimary } from '@shared/components/actionButtons';
import { canOnSshCa, dayText } from './sshLoginNames';
import { SSH_CA_KEYS_PATH } from './sshPlaces';
import {
    REVIEW_DATE_ACTS_ON_NOTHING, SSH_CA_REVIEW_YEARS, hoursText, reviewByProblem, reviewByToSend, reviewDateFieldValue, sshCaKeyReview,
} from './sshCaDefaults';

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
/// The "Review" section of an SSH CA key's page: the advisory review date, the sentence that
/// nothing stops working on it, a warning within 90 days of the date and after it, and, where
/// the reader may manage the SSH CA, a date field that moves it.
/// </summary>
const SshCaKeyReviewSection: React.FC<{ caKey: any; onMoved: () => void }> = ({ caKey, onMoved }) => {
    const { showToast } = useToast();
    const { capabilities } = useAuth();
    const canMove = canOnSshCa(capabilities, caKey, Capabilities.CaManage) && caKey.isEnabled !== false;
    const [moving, setMoving] = useState(false);
    const [date, setDate] = useState('');
    const [busy, setBusy] = useState(false);
    const [error, setError] = useState<NoticeInput | null>(null);

    const review = sshCaKeyReview(caKey, new Date());
    const problem = moving ? reviewByProblem(date, new Date()) : null;
    const defaultYears = caKey.isHostCa && !caKey.isUserCa ? SSH_CA_REVIEW_YEARS.host : SSH_CA_REVIEW_YEARS.user;

    const save = async (e: React.FormEvent) => {
        e.preventDefault();
        if (problem) return;
        setBusy(true);
        setError(null);
        try {
            await apiPut(`/api/v1/admin/ssh/ca-keys/${caKey.id}/review-by`, { reviewBy: reviewByToSend(date) }, { toast: false });
            showToast('success', 'Review date moved.');
            setMoving(false);
            onMoved();
        } catch (err: any) {
            setError(errorNotice(err, 'The review date could not be moved.'));
        } finally {
            setBusy(false);
        }
    };

    return (
        <DetailSection title="Review">
            <div className="max-w-4xl space-y-2">
                {review.warning && (
                    <div role="status" className="bg-warn-soft border border-warn/40 rounded-md px-3 py-2">
                        <p className="text-sm font-semibold text-warn">{review.warning}</p>
                    </div>
                )}
                <div>
                    <DetailField label="Review by" value={caKey.reviewBy ? dayText(caKey.reviewBy) : 'No date set'} />
                    <DetailField label="What it means" value={`${REVIEW_DATE_ACTS_ON_NOTHING} A key of this type is first given a date ${defaultYears} years after it is created.`} />
                </div>
                {canMove && !moving && (
                    <button type="button" onClick={() => { setDate(reviewDateFieldValue(caKey)); setError(null); setMoving(true); }} className={actionButton}>Move the date</button>
                )}
                {canMove && moving && (
                    <form onSubmit={save} className="space-y-2">
                        <div>
                            <label htmlFor="ssh-ca-review-by" className={labelClass}>Review by</label>
                            <input id="ssh-ca-review-by" type="date" value={date} onChange={(e) => setDate(e.target.value)} className={`${inputClassNarrow} w-48`} />
                            {problem
                                ? <FieldHint tone="warn">{problem}</FieldHint>
                                : <FieldHint>A date in the future, at most ten years ahead. Moving it changes the reminder and nothing else.</FieldHint>}
                        </div>
                        <InlineNotice notice={error} onDismiss={() => setError(null)} />
                        <div className="flex gap-2">
                            <button type="submit" disabled={busy || !!problem} className={actionButtonPrimary}>{busy ? 'Saving…' : 'Save'}</button>
                            <button type="button" onClick={() => setMoving(false)} className={actionButton}>Cancel</button>
                        </div>
                    </form>
                )}
            </div>
        </DetailSection>
    );
};

/// <summary>
/// Detail page for a single SSH CA key, under Authorities: shows algorithm, validity, public key, its advisory review
/// date, where the private key is held, its login names, its revocation list (the KRL's URL,
/// version and last revocation, and how a host is given it) and integration hints, with download / disable actions in the action bar. A key that was a plaintext file on
/// the node also carries the plaintext notice. The key itself is not edited in place, so the page
/// is View-only (Edit disabled); the Review section moves the review date and the Login names
/// section changes the grants, where the reader may manage the SSH CA.
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
    const plaintextNotice = useSshPlaintextNotice(refresh);

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
                navigate(SSH_CA_KEYS_PATH);
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
            <button onClick={() => navigate(SSH_CA_KEYS_PATH)} className="px-3 py-1.5 text-sm bg-sunken rounded">Back to Authorities</button>
        </div>
    );

    const enabled = key.isEnabled !== false;
    const algorithm = `${key.keyType || key.algorithm}${key.keySize ? ` (${key.keySize} bits)` : ''}`;
    const custody = sshKeyCustody(key);
    const signBlocked = signBlockedReason(key);
    const wasPlaintext = !!key.importedAt || custody.state === 'awaitingImport';
    const custodyBadge = <StatusBadge status={custody.badge.status} label={custody.badge.label} />;
    const reviewBadge = sshCaKeyReview(key, new Date()).badge;

    return (
        <DetailPage
            breadcrumbs={[{ label: 'Authorities', to: SSH_CA_KEYS_PATH }, { label: key.name || 'Unnamed' }]}
            title={key.name || 'Unnamed'}
            status={<>
                {enabled ? <StatusBadge status="active" label="Enabled" /> : <StatusBadge status="revoked" label="Disabled" />}
                {custody.state !== 'held' && custodyBadge}
                {reviewBadge && <StatusBadge status={reviewBadge.status} label={reviewBadge.label} />}
            </>}
            subtitle={algorithm}
            backTo={SSH_CA_KEYS_PATH}
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
                        <DetailField label="Longest certificate" value={hoursText(key.maxValidityHours)} />
                        <DetailField label="Created" value={formatDate(key.createdAt)} />
                        <DetailField label="User CA" value={key.isUserCa ? 'Yes' : 'No'} />
                        <DetailField label="Host CA" value={key.isHostCa ? 'Yes' : 'No'} />
                    </div>
                    <div className="mt-2">
                        <DetailField label="Public Key" value={key.publicKey} mono />
                    </div>
                </DetailSection>

                <SshCaKeyReviewSection caKey={key} onMoved={() => setRefresh((r) => r + 1)} />

                <DetailSection title="Key storage">
                    <div className="max-w-4xl">
                        <DetailField label="Held in" value={custody.heldIn} />
                        <DetailField label="State" value={custodyBadge} />
                        <DetailField label="What it means" value={custody.summary} />
                        <DetailField label="Reason" value={custody.reason} />
                        <DetailField label="Expected key file" value={custody.keyFile} mono />
                        <DetailField label="What to do" value={custody.remedy} />
                        {signBlocked && (
                            <DetailField label="Signing" value="Unavailable with this key. The Sign key form on the SSH tab of Request Certificate does not sign with it. Certificates it has already issued can still be revoked, and its KRL is still served." />
                        )}
                        {key.importedAt && (
                            <DetailField label="Imported" value={`${formatDate(key.importedAt)}, from a plaintext key file on the node`} />
                        )}
                    </div>
                </DetailSection>

                {wasPlaintext && plaintextNotice?.applies && (
                    <SshPlaintextNoticePanel notice={plaintextNotice} currentKeyId={key.id} />
                )}

                <SshKeyLoginNames caKey={key} />

                {key.krlUrl && (
                    <DetailSection title="Revocation list (KRL)">
                        <div className="max-w-4xl">
                            <DetailField label="KRL URL" value={key.krlUrl} mono />
                            <DetailField label="Version" value={krlVersionText(key)} />
                            <DetailField label="Last revocation" value={krlLastRevocationText(key, formatDate)} />
                            <DetailField label="What it means" value="A certificate revoked here is refused by a host only once that host has the new list. The list stays the same, version included, until a certificate of this key is revoked: an unchanged list is answered 304 Not Modified." />
                            {key.isUserCa && (
                                <DetailField label="On a host" value={<>
                                    sshd reads the list from the file <code className="text-accent-ink">RevokedKeys</code> names and does not fetch it. Copy the list to each host, from Download KRL or the KRL URL, as <code className="text-accent-ink">{KRL_DESTINATION}</code>, and again after each revocation. sshd refuses every public-key login while that file is missing, so copy it before adding the line to sshd_config.
                                </>} />
                            )}
                        </div>
                    </DetailSection>
                )}

                <DetailSection title="Integration">
                    <div className="text-xs text-ink-muted space-y-1">
                        {key.isUserCa && (
                            <p><span className="text-ink font-medium">User CA:</span> Add to <code className="text-accent-ink">TrustedUserCAKeys</code> in sshd_config. A host lets a certificate in when one of its login names is the account being logged in to, or is listed for that account in <code className="text-accent-ink">AuthorizedPrincipalsFile</code>.</p>
                        )}
                        {key.isUserCa && key.krlUrl && (
                            <p><span className="text-ink font-medium">Revocation:</span> Each host holds a copy of the revocation list above and names the file in <code className="text-accent-ink">RevokedKeys</code>. A certificate revoked here is refused only once the host has the new list.</p>
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
