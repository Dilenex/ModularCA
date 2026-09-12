import React, { useEffect, useState, useCallback } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { apiGet, apiPost } from '../api/client';
import { useToast } from '@shared/context/ToastContext';
import { StatusBadge } from '@shared/components/cards/StatusBadge';
import { DetailField } from '@shared/components/cards/DetailField';
import { DetailPage, DetailSection } from '../components/DetailPage';
import {
    type ApprovalRecord, csrId, csrStatus, csrStatusLabel, decisionBadgeStatus,
    parseJsonSafe, canApprove, canIssue, canCancel,
} from './CertificateRequests';
import { readDiagnostics } from '@shared-auth/api/problem';
import { diagnosticNotices } from '@shared-auth/api/notices';
import { mergeNotices, worstSeverity } from '@shared/notifications/notice';

function formatDate(d: string | null) {
    if (!d) return '-';
    return new Date(d).toLocaleDateString('en-US', { year: 'numeric', month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' });
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
    const [error, setError] = useState<string | null>(null);
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
            .catch((err) => { if (!cancelled) { setError(err.message || 'Failed to load request'); setLoading(false); } });
        return () => { cancelled = true; };
    }, [id, refresh, loadApprovals]);

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
            // (ValidityPeriodMax/Min, clamped to the issuing CA) rather than a fixed window.
            const result = await apiPost<any>('/api/v1/admin/certificates/issue', { csrId: id });
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
            navigate('/certificates/requests');
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

    if (loading) return <div className="p-6 text-sm text-gray-600 dark:text-gray-400">Loading…</div>;
    if (error) return <div className="p-6 text-sm text-red-800 dark:text-red-400">{error}</div>;
    if (!csr) return (
        <div className="p-6 space-y-3">
            <p className="text-sm text-gray-600 dark:text-gray-400">Certificate request not found.</p>
            <button onClick={() => navigate('/certificates/requests')} className="px-3 py-1.5 text-sm bg-gray-200 dark:bg-gray-700 rounded">Back to Certificate Requests</button>
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
                    {canCancel(csr) && <button onClick={() => { setCancelReason(''); setCancelCustom(''); setCancelOpen(true); }} disabled={busyAny} className="px-3 py-1.5 text-xs bg-orange-50 dark:bg-orange-900/50 text-orange-800 dark:text-orange-300 border border-orange-300 dark:border-orange-700 rounded hover:bg-orange-900 disabled:opacity-50 transition-colors">Cancel Request</button>}
                </div>
            }
        >
            {() => (<>
                {s === 'rejected' && (
                    <div className="bg-red-50 dark:bg-red-900/30 border border-red-300 dark:border-red-700 rounded px-3 py-2 flex items-center gap-2">
                        <span className="text-xs font-semibold text-red-800 dark:text-red-400">REJECTED</span>
                        {csr.rejectionReason && <span className="text-xs text-red-800 dark:text-red-300">— {csr.rejectionReason}</span>}
                    </div>
                )}
                {(s === 'pendingapproval' || s === 'partiallyapproved') && (
                    <div className="bg-orange-50 dark:bg-orange-900/20 border border-orange-300 dark:border-orange-700/50 rounded px-3 py-3">
                        <div className="flex items-center justify-between mb-2">
                            <span className="text-xs font-semibold text-orange-800 dark:text-orange-300">Approval Progress</span>
                            <span className="text-xs font-bold text-orange-800 dark:text-orange-200">{csr.approvalCount ?? 0} / {csr.requiredCount ?? '?'}</span>
                        </div>
                        <div className="w-full bg-gray-200 dark:bg-gray-700 rounded-full h-2">
                            <div className="bg-orange-500 h-2 rounded-full transition-all duration-300" style={{ width: csr.requiredCount ? `${Math.min(100, ((csr.approvalCount ?? 0) / csr.requiredCount) * 100)}%` : '0%' }} />
                        </div>
                    </div>
                )}
                {s === 'approved' && (
                    <div className="bg-green-50 dark:bg-green-900/30 border border-green-300 dark:border-green-700 rounded px-3 py-2">
                        <span className="text-xs font-semibold text-green-800 dark:text-green-400">FULLY APPROVED</span>
                        <span className="text-xs text-green-800 dark:text-green-300 ml-2">— Ready for certificate issuance</span>
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

                <DetailSection title="Action History">
                    {/* Workflow actions live here: approve (+comment) / reject when pending, issue when approved. */}
                    {(canApprove(csr) || canIssue(csr)) && (
                        <div className="max-w-xl mb-4 pb-4 border-b border-gray-200 dark:border-gray-700/60 space-y-2">
                            {canApprove(csr) && (<>
                                <label className="block text-xs font-semibold text-gray-600 dark:text-gray-400">Approval comment (optional)</label>
                                <input type="text" value={approveComment} onChange={(e) => setApproveComment(e.target.value)} placeholder="Add a comment..." className="w-full px-3 py-2 bg-gray-50 dark:bg-gray-900 border border-gray-300 dark:border-gray-700 rounded text-sm text-gray-900 dark:text-white placeholder-gray-400 dark:placeholder-gray-500 focus:outline-none focus:border-green-600" />
                                <div className="flex gap-2 flex-wrap">
                                    <button onClick={handleApprove} disabled={busyAny} className="px-4 py-2 text-sm font-semibold bg-green-600 text-white rounded hover:bg-green-700 disabled:opacity-50">{busy === 'approve' ? 'Approving…' : 'Approve'}</button>
                                    <button onClick={() => { setRejectReason(''); setRejectCustom(''); setRejectOpen(true); }} disabled={busyAny} className="px-4 py-2 text-sm bg-red-50 dark:bg-red-900/50 text-red-800 dark:text-red-300 border border-red-300 dark:border-red-700 rounded hover:bg-red-900 disabled:opacity-50 transition-colors">Reject</button>
                                </div>
                            </>)}
                            {canIssue(csr) && (
                                <button onClick={handleIssue} disabled={busyAny} className="px-4 py-2 text-sm font-semibold bg-blue-600 text-white rounded hover:bg-blue-700 disabled:opacity-50 transition-colors">{busy === 'issue' ? 'Issuing…' : 'Issue Certificate'}</button>
                            )}
                        </div>
                    )}
                    {approvalsLoading && <div className="text-xs text-gray-600 text-center py-2">Loading actions…</div>}
                    {!approvalsLoading && approvals.length === 0 && <div className="text-xs text-gray-500">No approval or rejection actions recorded yet.</div>}
                    {!approvalsLoading && approvals.map((a) => (
                        <div key={a.id} className="bg-gray-50/50 dark:bg-gray-900/50 border border-gray-300 dark:border-gray-700 rounded px-3 py-2 flex items-start gap-3 mb-2 last:mb-0">
                            <div className="flex-1 min-w-0">
                                <div className="flex items-center gap-2 mb-0.5">
                                    <span className="text-xs font-medium text-gray-800 dark:text-gray-200">{a.approverUsername}</span>
                                    <StatusBadge status={decisionBadgeStatus(a.decision)} label={a.decision} />
                                </div>
                                {a.comment && <div className="text-xs text-gray-600 dark:text-gray-400 mt-1">{a.comment}</div>}
                            </div>
                            <span className="text-xs text-gray-600 whitespace-nowrap flex-shrink-0">{formatDate(a.timestamp)}</span>
                        </div>
                    ))}
                </DetailSection>

                {/* Reject modal */}
                {rejectOpen && (
                    <div className="fixed inset-0 bg-black/30 dark:bg-black/70 flex items-center justify-center z-[60]" onClick={() => busy !== 'reject' && setRejectOpen(false)}>
                        <div className="bg-gray-100 dark:bg-gray-800 border border-gray-300 dark:border-gray-700 rounded-lg shadow-2xl w-full max-w-md mx-4" onClick={(e) => e.stopPropagation()}>
                            <div className="px-5 py-4 border-b border-gray-300 dark:border-gray-700"><h3 className="text-sm font-semibold text-gray-900 dark:text-white">Reject Certificate Request</h3></div>
                            <div className="px-5 py-4 space-y-4">
                                <div className="text-xs text-gray-600 dark:text-gray-400">Rejecting request for <span className="text-gray-900 dark:text-white font-medium">{csr.subjectName || csr.subject}</span></div>
                                <div>
                                    <label className="block text-xs font-semibold text-gray-600 dark:text-gray-400 mb-1">Reason *</label>
                                    <select value={rejectReason} onChange={(e) => setRejectReason(e.target.value)} className="w-full px-3 py-2 bg-gray-50 dark:bg-gray-900 border border-gray-300 dark:border-gray-700 rounded text-sm text-gray-900 dark:text-white focus:outline-none focus:border-blue-500">
                                        <option value="">Select a reason...</option>
                                        {REJECT_REASONS.map((r) => <option key={r} value={r}>{r}</option>)}
                                    </select>
                                </div>
                                {rejectReason === 'Other' && (
                                    <div>
                                        <label className="block text-xs font-semibold text-gray-600 dark:text-gray-400 mb-1">Custom reason</label>
                                        <textarea value={rejectCustom} onChange={(e) => setRejectCustom(e.target.value)} rows={2} placeholder="Enter rejection reason..." className="w-full px-3 py-2 bg-gray-50 dark:bg-gray-900 border border-gray-300 dark:border-gray-700 rounded text-sm text-gray-900 dark:text-white resize-none focus:outline-none focus:border-blue-500" />
                                    </div>
                                )}
                            </div>
                            <div className="px-5 py-4 border-t border-gray-300 dark:border-gray-700 flex gap-2 justify-end">
                                <button onClick={() => setRejectOpen(false)} disabled={busy === 'reject'} className="px-4 py-2 text-xs bg-gray-200 dark:bg-gray-700 text-gray-700 dark:text-gray-300 rounded hover:bg-gray-300 dark:hover:bg-gray-600 transition-colors disabled:opacity-50">Cancel</button>
                                <button onClick={handleReject} disabled={busy === 'reject' || !(rejectReason === 'Other' ? rejectCustom.trim() : rejectReason)} className="px-4 py-2 text-xs bg-red-600 text-white rounded hover:bg-red-700 transition-colors disabled:opacity-50">{busy === 'reject' ? 'Rejecting…' : 'Reject Request'}</button>
                            </div>
                        </div>
                    </div>
                )}

                {/* Cancel modal */}
                {cancelOpen && (
                    <div className="fixed inset-0 bg-black/30 dark:bg-black/70 flex items-center justify-center z-[60]" onClick={() => busy !== 'cancel' && setCancelOpen(false)}>
                        <div className="bg-gray-100 dark:bg-gray-800 border border-gray-300 dark:border-gray-700 rounded-lg shadow-2xl w-full max-w-md mx-4" onClick={(e) => e.stopPropagation()}>
                            <div className="px-5 py-4 border-b border-gray-300 dark:border-gray-700"><h3 className="text-sm font-semibold text-gray-900 dark:text-white">Cancel Certificate Request</h3></div>
                            <div className="px-5 py-4 space-y-4">
                                <div className="text-xs text-gray-600 dark:text-gray-400">Cancelling request for <span className="text-gray-900 dark:text-white font-medium">{csr.subjectName || csr.subject}</span></div>
                                <div>
                                    <label className="block text-xs font-semibold text-gray-600 dark:text-gray-400 mb-1">Reason *</label>
                                    <select value={cancelReason} onChange={(e) => setCancelReason(e.target.value)} className="w-full px-3 py-2 bg-gray-50 dark:bg-gray-900 border border-gray-300 dark:border-gray-700 rounded text-sm text-gray-900 dark:text-white focus:outline-none focus:border-blue-500">
                                        <option value="">Select a reason...</option>
                                        {CANCEL_REASONS.map((r) => <option key={r} value={r}>{r}</option>)}
                                    </select>
                                </div>
                                {cancelReason === 'Other' && (
                                    <div>
                                        <label className="block text-xs font-semibold text-gray-600 dark:text-gray-400 mb-1">Custom reason</label>
                                        <textarea value={cancelCustom} onChange={(e) => setCancelCustom(e.target.value)} rows={2} placeholder="Enter cancellation reason..." className="w-full px-3 py-2 bg-gray-50 dark:bg-gray-900 border border-gray-300 dark:border-gray-700 rounded text-sm text-gray-900 dark:text-white resize-none focus:outline-none focus:border-blue-500" />
                                    </div>
                                )}
                            </div>
                            <div className="px-5 py-4 border-t border-gray-300 dark:border-gray-700 flex gap-2 justify-end">
                                <button onClick={() => setCancelOpen(false)} disabled={busy === 'cancel'} className="px-4 py-2 text-xs bg-gray-200 dark:bg-gray-700 text-gray-700 dark:text-gray-300 rounded hover:bg-gray-300 dark:hover:bg-gray-600 transition-colors disabled:opacity-50">Back</button>
                                <button onClick={handleCancel} disabled={busy === 'cancel' || !(cancelReason === 'Other' ? cancelCustom.trim() : cancelReason)} className="px-4 py-2 text-xs bg-orange-600 text-white rounded hover:bg-orange-700 transition-colors disabled:opacity-50">{busy === 'cancel' ? 'Cancelling…' : 'Cancel Request'}</button>
                            </div>
                        </div>
                    </div>
                )}
            </>)}
        </DetailPage>
    );
};

export default CertificateRequestDetail;
