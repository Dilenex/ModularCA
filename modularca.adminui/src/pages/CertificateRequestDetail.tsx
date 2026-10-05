import React, { useEffect, useState, useCallback } from 'react';
import type { NoticeInput } from '@shared/notifications/notice';
import { InlineNotice } from '@shared/components/InlineNotice';
import { errorNotice } from '@shared-auth/api/notices';
import { useParams, useNavigate } from 'react-router-dom';
import { apiGet, apiPost } from '../api/client';
import { useToast } from '@shared/context/ToastContext';
import { StatusBadge } from '@shared/components/cards/StatusBadge';
import { DetailField } from '@shared/components/cards/DetailField';
import { DetailPage, DetailSection } from '../components/DetailPage';
import ConfirmModal from '../components/ConfirmModal';
import { HeldKeyDownload } from '../components/HeldKeyDownload';
import { FieldHint } from '@shared/components/forms';
import {
    type ApprovalRecord, csrId, csrStatus, csrStatusLabel, decisionBadgeStatus,
    parseJsonSafe, canApprove, canIssue, canCancel, isoPeriodToMaxDate,
} from './CertificateRequests';
import { readDiagnostics } from '@shared-auth/api/problem';
import { diagnosticNotices } from '@shared-auth/api/notices';
import { mergeNotices, worstSeverity } from '@shared/notifications/notice';

function formatDate(d: string | null) {
    if (!d) return '-';
    return new Date(d).toLocaleDateString('en-US', { year: 'numeric', month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' });
}

/**
 * Reads the serial number out of a PEM certificate so the page can land on the certificate it
 * just issued. The issue endpoint answers with the PEM only (no serial), and the certificate
 * routes are keyed by serial. DER walk: Certificate ::= SEQUENCE { tbsCertificate SEQUENCE {
 * [0] version OPTIONAL, serialNumber INTEGER, ... } }. The result is uppercase hex with leading
 * zeros stripped, which is how the CA formats serials (BigInteger.ToString(16)). Null on anything
 * unexpected; the caller then falls back to the request list.
 */
export function serialFromPem(pem: unknown): string | null {
    if (typeof pem !== 'string') return null;
    const b64 = pem.replace(/-----(BEGIN|END)[^-]*-----/g, '').replace(/\s+/g, '');
    let bytes: Uint8Array;
    try { bytes = Uint8Array.from(atob(b64), (c) => c.charCodeAt(0)); } catch { return null; }
    const header = (pos: number): { tag: number; len: number; hl: number } | null => {
        if (pos + 1 >= bytes.length) return null;
        const tag = bytes[pos];
        let len = bytes[pos + 1];
        let hl = 2;
        if (len & 0x80) {
            const n = len & 0x7f;
            if (n === 0 || n > 4 || pos + 2 + n > bytes.length) return null;
            len = 0;
            for (let i = 0; i < n; i++) len = len * 256 + bytes[pos + 2 + i];
            hl = 2 + n;
        }
        return { tag, len, hl };
    };
    let p = 0;
    let h = header(p);
    if (!h || h.tag !== 0x30) return null;      // Certificate
    p += h.hl;
    h = header(p);
    if (!h || h.tag !== 0x30) return null;      // tbsCertificate
    p += h.hl;
    h = header(p);
    if (h && h.tag === 0xa0) { p += h.hl + h.len; h = header(p); }   // [0] version
    if (!h || h.tag !== 0x02 || p + h.hl + h.len > bytes.length) return null;   // serialNumber
    const hex = Array.from(bytes.slice(p + h.hl, p + h.hl + h.len)).map((b) => b.toString(16).padStart(2, '0')).join('').toUpperCase();
    return hex.replace(/^0+(?=.)/, '') || null;
}

const REJECT_REASONS = ['Policy violation', 'Invalid subject', 'Weak key', 'Duplicate request', 'Unauthorized requestor', 'Incorrect profile', 'Other'];
const CANCEL_REASONS = ['No longer needed', 'Superseded by new request', 'Incorrect parameters', 'Requestor withdrew', 'Other'];

/// <summary>
/// Detail page for a single certificate request (CSR). Shows status / approval progress / history,
/// and carries the workflow actions (approve, reject, cancel, issue) in the action bar. Read-only —
/// the request itself isn't edited, only acted upon.
/// </summary>
const CertificateRequestDetail: React.FC = () => {
    const { id } = useParams<{ id: string }>();
    const navigate = useNavigate();
    const { showToast } = useToast();

    const [csr, setCsr] = useState<any | null>(null);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState<NoticeInput | null>(null);
    const [refresh, setRefresh] = useState(0);

    const [approvals, setApprovals] = useState<ApprovalRecord[]>([]);
    const [approvalsLoading, setApprovalsLoading] = useState(false);

    const [approveComment, setApproveComment] = useState('');
    const [busy, setBusy] = useState<null | 'approve' | 'issue' | 'reject' | 'cancel'>(null);

    const [rejectOpen, setRejectOpen] = useState(false);
    const [rejectReason, setRejectReason] = useState('');
    const [rejectCustom, setRejectCustom] = useState('');
    const [cancelOpen, setCancelOpen] = useState(false);
    const [cancelReason, setCancelReason] = useState('');
    const [cancelCustom, setCancelCustom] = useState('');

    // Issue confirmation, with the same optional "valid until" the bulk path offers. The cert
    // profile supplies the picker's ceiling; the server clamps to the CA and enforces the minimum.
    const [issueOpen, setIssueOpen] = useState(false);
    const [issueValidUntil, setIssueValidUntil] = useState('');
    const [certProfile, setCertProfile] = useState<any | null>(null);
    const today = new Date().toISOString().slice(0, 10);
    const issueMaxDate = isoPeriodToMaxDate(certProfile?.validityPeriodMax);

    const loadApprovals = useCallback((cid: string) => {
        setApprovalsLoading(true);
        apiGet<ApprovalRecord[]>(`/api/v1/admin/requests/${cid}/approvals`)
            .then((data) => setApprovals(Array.isArray(data) ? data : []))
            .catch(() => setApprovals([]))
            .finally(() => setApprovalsLoading(false));
    }, []);

    useEffect(() => {
        let cancelled = false;
        setLoading(true);
        setError(null);
        apiGet<any[]>('/api/v1/admin/requests')
            .then((data) => {
                if (cancelled) return;
                const found = (Array.isArray(data) ? data : []).find((c: any) => csrId(c) === id) || null;
                setCsr(found);
                setLoading(false);
                if (found) {
                    const s = (found.status || '').toLowerCase();
                    if (['pendingapproval', 'partiallyapproved', 'approved', 'rejected', 'issued'].includes(s) || found.issuedCertificateId) loadApprovals(id!);
                }
            })
            .catch((err) => { if (!cancelled) { setError(errorNotice(err, 'Failed to load request')); setLoading(false); } });
        return () => { cancelled = true; };
    }, [id, refresh, loadApprovals]);

    // The request's cert profile, for the validity picker's ceiling and to name it in the confirm.
    useEffect(() => {
        const cpId = csr?.certificateProfileId || csr?.certProfileId;
        if (!cpId) { setCertProfile(null); return; }
        let cancelled = false;
        apiGet<any>('/api/v1/admin/cert-profiles')
            .then((d) => {
                if (cancelled) return;
                const list = Array.isArray(d) ? d : (d.items || d.profiles || []);
                setCertProfile(list.find((p: any) => (p.id || p.certProfileId) === cpId) || null);
            })
            .catch(() => { if (!cancelled) setCertProfile(null); });
        return () => { cancelled = true; };
    }, [csr?.certificateProfileId, csr?.certProfileId]);

    const handleApprove = async () => {
        if (!csr) return;
        setBusy('approve');
        try {
            const result = await apiPost<{ message: string; status: string; approvalCount: number; requiredCount: number }>(`/api/v1/admin/requests/${id}/approve`, { comment: approveComment });
            showToast('success', result.message || `Approval recorded (${result.approvalCount}/${result.requiredCount})`);
            setApproveComment('');
            setRefresh((r) => r + 1);
        } catch (err: any) {
            showToast('error', err.message || 'Failed to record approval');
        } finally {
            setBusy(null);
        }
    };

    const handleIssue = async () => {
        if (!csr) return;
        setBusy('issue');
        try {
            // Omit NotBefore/NotAfter so validity coalesces from the effective cert profile
            // (ValidityPeriodMax/Min, clamped to the issuing CA) rather than a fixed window; an
            // explicit "valid until" from the confirm shortens it the same way the bulk path does.
            const result = await apiPost<any>('/api/v1/admin/certificates/issue', {
                csrId: id,
                ...(issueValidUntil ? { notAfter: new Date(`${issueValidUntil}T23:59:59Z`).toISOString() } : {}),
            });
            const advisories = diagnosticNotices(readDiagnostics(result));
            // Severity from the diagnostics themselves rather than from whether there are any: an
            // informational diagnostic is not a warning, and a toast that cries wolf teaches the
            // operator to dismiss the one that is not crying wolf. The notice keeps the code in its
            // own slot so it survives long enough to be copied into a ticket — this toast no longer
            // auto-dismisses when a diagnostic makes it a warning.
            showToast(
                worstSeverity(advisories, 'success'),
                mergeNotices(`Certificate issued for ${csr.subjectName || csr.subject}`, advisories),
            );
            setIssueOpen(false);
            // The response carries the PEM, not the serial; read the serial out of it and land on
            // the new certificate rather than the bare list.
            const serial = (typeof result?.serialNumber === 'string' && result.serialNumber) || serialFromPem(result?.pem);
            navigate(serial ? `/certificates/${serial}` : '/certificates/requests');
        } catch (err: any) {
            showToast('error', err.message || 'Failed to issue certificate');
        } finally {
            setBusy(null);
        }
    };

    const handleReject = async () => {
        const reason = rejectReason === 'Other' ? rejectCustom.trim() : rejectReason;
        if (!reason) return;
        setBusy('reject');
        try {
            await apiPost(`/api/v1/admin/requests/${id}/reject`, { reason });
            showToast('success', `Request rejected: ${csr.subjectName || csr.subject}`);
            navigate('/certificates/requests');
        } catch (err: any) {
            showToast('error', err.message || 'Failed to reject request');
        } finally {
            setBusy(null);
            setRejectOpen(false);
        }
    };

    const handleCancel = async () => {
        const reason = cancelReason === 'Other' ? cancelCustom.trim() : cancelReason;
        if (!reason) return;
        setBusy('cancel');
        try {
            await apiPost(`/api/v1/admin/requests/${id}/cancel`, { reason });
            showToast('success', `Request cancelled: ${csr.subjectName || csr.subject}`);
            navigate('/certificates/requests');
        } catch (err: any) {
            showToast('error', err.message || 'Failed to cancel request');
        } finally {
            setBusy(null);
            setCancelOpen(false);
        }
    };

    if (loading) return <div className="p-6 text-sm text-ink-muted">Loading…</div>;
    if (error) return <InlineNotice notice={error} />;
    if (!csr) return (
        <div className="p-6 space-y-3">
            <p className="text-sm text-ink-muted">Certificate request not found.</p>
            <button onClick={() => navigate('/certificates/requests')} className="px-3 py-1.5 text-sm bg-sunken rounded">Back to Certificate Requests</button>
        </div>
    );

    const s = (csr.status || '').toLowerCase();
    const busyAny = busy !== null;
    const title = csr.subjectName || csr.subject || 'Certificate Request';

    return (
        <DetailPage
            breadcrumbs={[{ label: 'Certificate Requests', to: '/certificates/requests' }, { label: title }]}
            title={title}
            status={<StatusBadge status={csrStatus(csr)} label={csrStatusLabel(csr)} />}
            backTo="/certificates/requests"
            actions={
                <div className="flex items-center gap-2 flex-wrap">
                    {canCancel(csr) && <button onClick={() => { setCancelReason(''); setCancelCustom(''); setCancelOpen(true); }} disabled={busyAny} className="px-3 py-1.5 text-xs bg-warn-soft text-warn border border-warn/40 rounded hover:bg-warn/15 disabled:opacity-50 transition-colors">Cancel Request</button>}
                </div>
            }
        >
            {() => (<>
                {s === 'rejected' && (
                    <div className="bg-crit-soft border border-crit/40 rounded px-3 py-2 flex items-center gap-2">
                        <span className="text-xs font-semibold text-crit">REJECTED</span>
                        {csr.rejectionReason && <span className="text-xs text-crit">— {csr.rejectionReason}</span>}
                    </div>
                )}
                {(s === 'pendingapproval' || s === 'partiallyapproved') && (
                    <div className="bg-warn-soft border border-warn/40 rounded px-3 py-3">
                        <div className="flex items-center justify-between mb-2">
                            <span className="text-xs font-semibold text-warn">Approval Progress</span>
                            <span className="text-xs font-bold text-warn">{csr.approvalCount ?? 0} / {csr.requiredCount ?? '?'}</span>
                        </div>
                        <div className="w-full bg-sunken rounded-full h-2">
                            <div className="bg-warn h-2 rounded-full transition-all duration-300" style={{ width: csr.requiredCount ? `${Math.min(100, ((csr.approvalCount ?? 0) / csr.requiredCount) * 100)}%` : '0%' }} />
                        </div>
                    </div>
                )}
                {s === 'approved' && (
                    <div className="bg-ok-soft border border-ok/40 rounded px-3 py-2">
                        <span className="text-xs font-semibold text-ok">FULLY APPROVED</span>
                        <span className="text-xs text-ok ml-2">— Ready for certificate issuance</span>
                    </div>
                )}

                <DetailSection title="Request">
                    <DetailField label="Subject" value={csr.subjectName || csr.subject} />
                    <DetailField label="Status" value={csrStatusLabel(csr)} />
                    <DetailField label="Key Algorithm" value={csr.keyAlgorithm} />
                    <DetailField label="Key Size" value={csr.keySize} />
                    <DetailField label="Signature Algorithm" value={csr.signatureAlgorithm} />
                    <DetailField label="SANs" value={parseJsonSafe(csr.subjectAlternativeNames)} />
                    <DetailField label="Submitted" value={formatDate(csr.submittedAt)} />
                    {csr.certProfileId && <DetailField label="Cert Profile ID" value={csr.certProfileId} mono />}
                    {csr.signingProfileId && <DetailField label="Signing Profile ID" value={csr.signingProfileId} mono />}
                    <DetailField label="Request ID" value={csrId(csr)} mono />
                </DetailSection>

                {/* The key the CA generated for this request, if any: held until the certificate
                    is issued and downloaded as one .pfx, then deleted. */}
                {(csr.keyHeld || csr.heldKeyDeliveredAt) && (
                    <DetailSection title="Private Key">
                        {csr.keyHeld && !csr.issuedCertificateId && (
                            <p className="text-xs text-warn">
                                The CA holds the private key it generated for this request until the certificate is issued; the .pfx download appears here then.
                            </p>
                        )}
                        <HeldKeyDownload
                            endpoint={`/api/v1/admin/requests/${encodeURIComponent(csrId(csr))}/pkcs12`}
                            requestId={csrId(csr)}
                            fileName={(csr.subjectName || csr.subject || 'certificate').replace(/^CN=/i, '').split(',')[0]}
                            keyHeld={!!csr.keyHeld}
                            deliveredAt={csr.heldKeyDeliveredAt}
                            issued={!!csr.issuedCertificateId}
                            onDelivered={() => setRefresh((r) => r + 1)}
                        />
                    </DetailSection>
                )}

                <DetailSection title="Action History">
                    {/* Workflow actions live here: approve (+comment) / reject when pending, issue when approved. */}
                    {(canApprove(csr) || canIssue(csr)) && (
                        <div className="max-w-xl mb-4 pb-4 border-b border-line space-y-2">
                            {canApprove(csr) && (<>
                                <label className="block text-xs font-semibold text-ink-muted">Approval comment (optional)</label>
                                <input type="text" value={approveComment} onChange={(e) => setApproveComment(e.target.value)} placeholder="Add a comment..." className="w-full px-3 py-2 bg-raised border border-line-strong rounded text-sm text-ink placeholder-ink-faint focus:outline-none focus:border-ok" />
                                <div className="flex gap-2 flex-wrap">
                                    <button onClick={handleApprove} disabled={busyAny} className="px-4 py-2 text-sm font-semibold bg-ok text-on-accent rounded hover:bg-ok-hover disabled:opacity-50">{busy === 'approve' ? 'Approving…' : 'Approve'}</button>
                                    <button onClick={() => { setRejectReason(''); setRejectCustom(''); setRejectOpen(true); }} disabled={busyAny} className="px-4 py-2 text-sm bg-crit-soft text-crit border border-crit/40 rounded hover:bg-crit/15 disabled:opacity-50 transition-colors">Reject</button>
                                </div>
                            </>)}
                            {canIssue(csr) && (
                                <button onClick={() => { setIssueValidUntil(''); setIssueOpen(true); }} disabled={busyAny} className="px-4 py-2 text-sm font-semibold bg-accent text-on-accent rounded hover:bg-accent-hover disabled:opacity-50 transition-colors">{busy === 'issue' ? 'Issuing…' : 'Issue Certificate'}</button>
                            )}
                        </div>
                    )}
                    {approvalsLoading && <div className="text-xs text-ink-muted text-center py-2">Loading actions…</div>}
                    {!approvalsLoading && approvals.length === 0 && <div className="text-xs text-ink-muted">No approval or rejection actions recorded yet.</div>}
                    {!approvalsLoading && approvals.map((a) => (
                        <div key={a.id} className="bg-sunken border border-line rounded px-3 py-2 flex items-start gap-3 mb-2 last:mb-0">
                            <div className="flex-1 min-w-0">
                                <div className="flex items-center gap-2 mb-0.5">
                                    <span className="text-xs font-medium text-ink">{a.approverUsername}</span>
                                    <StatusBadge status={decisionBadgeStatus(a.decision)} label={a.decision} />
                                </div>
                                {a.comment && <div className="text-xs text-ink-muted mt-1">{a.comment}</div>}
                            </div>
                            <span className="text-xs text-ink-muted whitespace-nowrap flex-shrink-0">{formatDate(a.timestamp)}</span>
                        </div>
                    ))}
                </DetailSection>

                {/* Issue confirmation — what will be signed, and the same optional valid-until as the bulk path */}
                <ConfirmModal
                    isOpen={issueOpen}
                    title="Issue Certificate"
                    confirmLabel="Issue"
                    confirmClass="px-4 py-2 text-sm bg-accent text-on-accent rounded hover:bg-accent-hover transition-colors disabled:opacity-50"
                    loading={busy === 'issue'}
                    onConfirm={handleIssue}
                    onCancel={() => setIssueOpen(false)}
                    message={(
                        <div className="space-y-3 text-left">
                            <p className="text-xs">This signs the approved request and publishes a certificate immediately; it can only be undone by revoking it.</p>
                            <div className="text-xs space-y-0.5">
                                <div className="break-all"><span className="font-semibold text-ink">Subject:</span> {csr.subjectName || csr.subject}</div>
                                {parseJsonSafe(csr.subjectAlternativeNames) && <div className="break-all"><span className="font-semibold text-ink">SANs:</span> {parseJsonSafe(csr.subjectAlternativeNames)}</div>}
                                {csr.keyAlgorithm && <div><span className="font-semibold text-ink">Key:</span> {csr.keyAlgorithm}{csr.keySize ? ` ${csr.keySize}` : ''}</div>}
                                {certProfile && <div><span className="font-semibold text-ink">Profile:</span> {certProfile.name}{certProfile.validityPeriodMax ? ` (max validity ${certProfile.validityPeriodMax})` : ''}</div>}
                            </div>
                            <div>
                                <label htmlFor="issue-valid-until" className="block text-xs font-semibold text-ink-muted mb-1">Valid until (optional)</label>
                                <input id="issue-valid-until" type="date" value={issueValidUntil} min={today} max={issueMaxDate}
                                    onChange={(e) => setIssueValidUntil(e.target.value)} disabled={busy === 'issue'}
                                    className="w-full px-2 py-1 text-xs bg-raised border border-line-strong rounded text-ink focus:outline-none focus:border-accent disabled:opacity-50" />
                                <FieldHint>Blank uses the profile default{issueMaxDate ? `, at most ${issueMaxDate}` : ''}. The server also clamps to the issuing CA and rejects anything below the profile minimum.</FieldHint>
                            </div>
                        </div>
                    )}
                />

                {/* Reject modal */}
                {rejectOpen && (
                    <div className="fixed inset-0 bg-scrim flex items-center justify-center z-[60]" onClick={() => busy !== 'reject' && setRejectOpen(false)}>
                        <div className="bg-raised border border-line rounded-lg shadow-2xl w-full max-w-md mx-4" onClick={(e) => e.stopPropagation()}>
                            <div className="px-5 py-4 border-b border-line"><h3 className="text-sm font-semibold text-ink">Reject Certificate Request</h3></div>
                            <div className="px-5 py-4 space-y-4">
                                <div className="text-xs text-ink-muted">Rejecting request for <span className="text-ink font-medium">{csr.subjectName || csr.subject}</span></div>
                                <div>
                                    <label className="block text-xs font-semibold text-ink-muted mb-1">Reason *</label>
                                    <select value={rejectReason} onChange={(e) => setRejectReason(e.target.value)} className="w-full px-3 py-2 bg-raised border border-line-strong rounded text-sm text-ink focus:outline-none focus:border-accent">
                                        <option value="">Select a reason...</option>
                                        {REJECT_REASONS.map((r) => <option key={r} value={r}>{r}</option>)}
                                    </select>
                                </div>
                                {rejectReason === 'Other' && (
                                    <div>
                                        <label className="block text-xs font-semibold text-ink-muted mb-1">Custom reason</label>
                                        <textarea value={rejectCustom} onChange={(e) => setRejectCustom(e.target.value)} rows={2} placeholder="Enter rejection reason..." className="w-full px-3 py-2 bg-raised border border-line-strong rounded text-sm text-ink resize-none focus:outline-none focus:border-accent" />
                                    </div>
                                )}
                            </div>
                            <div className="px-5 py-4 border-t border-line flex gap-2 justify-end">
                                <button onClick={() => setRejectOpen(false)} disabled={busy === 'reject'} className="px-4 py-2 text-xs bg-sunken text-ink rounded hover:bg-hover transition-colors disabled:opacity-50">Cancel</button>
                                <button onClick={handleReject} disabled={busy === 'reject' || !(rejectReason === 'Other' ? rejectCustom.trim() : rejectReason)} className="px-4 py-2 text-xs bg-crit text-on-accent rounded hover:bg-crit-hover transition-colors disabled:opacity-50">{busy === 'reject' ? 'Rejecting…' : 'Reject Request'}</button>
                            </div>
                        </div>
                    </div>
                )}

                {/* Cancel modal */}
                {cancelOpen && (
                    <div className="fixed inset-0 bg-scrim flex items-center justify-center z-[60]" onClick={() => busy !== 'cancel' && setCancelOpen(false)}>
                        <div className="bg-raised border border-line rounded-lg shadow-2xl w-full max-w-md mx-4" onClick={(e) => e.stopPropagation()}>
                            <div className="px-5 py-4 border-b border-line"><h3 className="text-sm font-semibold text-ink">Cancel Certificate Request</h3></div>
                            <div className="px-5 py-4 space-y-4">
                                <div className="text-xs text-ink-muted">Cancelling request for <span className="text-ink font-medium">{csr.subjectName || csr.subject}</span></div>
                                <div>
                                    <label className="block text-xs font-semibold text-ink-muted mb-1">Reason *</label>
                                    <select value={cancelReason} onChange={(e) => setCancelReason(e.target.value)} className="w-full px-3 py-2 bg-raised border border-line-strong rounded text-sm text-ink focus:outline-none focus:border-accent">
                                        <option value="">Select a reason...</option>
                                        {CANCEL_REASONS.map((r) => <option key={r} value={r}>{r}</option>)}
                                    </select>
                                </div>
                                {cancelReason === 'Other' && (
                                    <div>
                                        <label className="block text-xs font-semibold text-ink-muted mb-1">Custom reason</label>
                                        <textarea value={cancelCustom} onChange={(e) => setCancelCustom(e.target.value)} rows={2} placeholder="Enter cancellation reason..." className="w-full px-3 py-2 bg-raised border border-line-strong rounded text-sm text-ink resize-none focus:outline-none focus:border-accent" />
                                    </div>
                                )}
                            </div>
                            <div className="px-5 py-4 border-t border-line flex gap-2 justify-end">
                                <button onClick={() => setCancelOpen(false)} disabled={busy === 'cancel'} className="px-4 py-2 text-xs bg-sunken text-ink rounded hover:bg-hover transition-colors disabled:opacity-50">Back</button>
                                <button onClick={handleCancel} disabled={busy === 'cancel' || !(cancelReason === 'Other' ? cancelCustom.trim() : cancelReason)} className="px-4 py-2 text-xs bg-warn text-on-accent rounded hover:bg-warn-hover transition-colors disabled:opacity-50">{busy === 'cancel' ? 'Cancelling…' : 'Cancel Request'}</button>
                            </div>
                        </div>
                    </div>
                )}
            </>)}
        </DetailPage>
    );
};

export default CertificateRequestDetail;
