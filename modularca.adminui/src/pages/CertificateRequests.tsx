import React, { useState, useEffect } from 'react';
import type { NoticeInput } from '@shared/notifications/notice';
import { errorNotice } from '@shared-auth/api/notices';
import { apiGet, apiPost } from '../api/client';
import { recordTableProps } from '../components/RecordDrawer';
import type { RecordDescriptor } from '@shared/records';
import { useScope } from '../context/ScopeContext';
import { useToast } from '@shared/context/ToastContext';
import { StatusBadge } from '@shared/components/cards/StatusBadge';
import { DetailField } from '@shared/components/cards/DetailField';
import { DataTable, DataTableColumn } from '@shared/components/DataTable';
import { StepUpOps } from '@shared/generated';
import { runWithOneStepUp } from '@shared-auth/api/stepUpBatch';
import { useStepUp } from '../components/StepUpMfaContext';

function formatDate(d: string | null) {
    if (!d) return '-';
    return new Date(d).toLocaleDateString('en-US', { year: 'numeric', month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' });
}

/** Converts an ISO-8601 period (e.g. "P1Y", "P90D") to a yyyy-MM-dd "max date" from today — the upper
 *  bound for the per-cert validity picker. Time components are ignored. Undefined if absent/unparseable. */
export function isoPeriodToMaxDate(iso?: string | null): string | undefined {
    if (!iso) return undefined;
    const m = /^P(?:(\d+)Y)?(?:(\d+)M)?(?:(\d+)W)?(?:(\d+)D)?/.exec(iso);
    if (!m || (!m[1] && !m[2] && !m[3] && !m[4])) return undefined;
    const dt = new Date();
    if (m[1]) dt.setFullYear(dt.getFullYear() + parseInt(m[1], 10));
    if (m[2]) dt.setMonth(dt.getMonth() + parseInt(m[2], 10));
    if (m[3]) dt.setDate(dt.getDate() + parseInt(m[3], 10) * 7);
    if (m[4]) dt.setDate(dt.getDate() + parseInt(m[4], 10));
    return dt.toISOString().slice(0, 10);
}

export const csrId = (csr: any): string => csr.id || csr.requestId;

export function csrStatus(csr: any): 'pending' | 'active' | 'revoked' | 'held' | 'expired' {
    if (csr.issuedCertificateId) return 'active';
    const s = (csr.status || '').toLowerCase();
    if (s === 'issued' || s === 'completed') return 'active';
    if (s === 'rejected' || s === 'failed' || s === 'cancelled') return 'revoked';
    if (s === 'approved') return 'active';
    if (s === 'partiallyapproved') return 'held';
    return 'pending';
}

export function csrStatusLabel(csr: any): string {
    if (csr.issuedCertificateId) return 'Issued';
    const s = (csr.status || '').toLowerCase();
    if (s === 'pendingapproval') return 'Pending Approval';
    if (s === 'partiallyapproved') {
        const count = csr.approvalCount ?? 0;
        const required = csr.requiredCount ?? '?';
        return `Partially Approved (${count}/${required})`;
    }
    return csr.status || 'Pending';
}

export function decisionBadgeStatus(decision: string): 'active' | 'revoked' {
    return decision?.toLowerCase() === 'approved' ? 'active' : 'revoked';
}

export function parseJsonSafe(val: string | null | undefined): string {
    if (!val) return '';
    try { const parsed = JSON.parse(val); if (Array.isArray(parsed)) return parsed.join(', '); return String(parsed); }
    catch { return val; }
}

/** Returns true if the CSR is in a state that allows approval. */
export function canApprove(csr: any): boolean {
    const s = (csr.status || '').toLowerCase();
    return s === 'pending' || s === 'pendingapproval' || s === 'partiallyapproved';
}
/** Returns true if the CSR is fully approved and ready for issuance. */
export function canIssue(csr: any): boolean {
    return (csr.status || '').toLowerCase() === 'approved';
}
/** Returns true if the CSR can be cancelled (pending or approved, not yet issued). */
export function canCancel(csr: any): boolean {
    const s = (csr.status || '').toLowerCase();
    return (s === 'approved' || s === 'pending' || s === 'pendingapproval') && !csr.issuedCertificateId;
}

export interface ApprovalRecord {
    id: string;
    approverUsername: string;
    decision: string;
    comment: string;
    timestamp: string;
}

const STATUS_FILTERS = ['All', 'Pending', 'Approved', 'Issued', 'Rejected', 'Cancelled'] as const;

const CertificateRequests: React.FC = () => {
    const { showToast } = useToast();
    const { requireStepUp } = useStepUp();
    const [requests, setRequests] = useState<any[]>([]);
    const [statusFilter, setStatusFilter] = useState<string>('Pending');
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState<NoticeInput | null>(null);

    // Bulk approve/deny/issue — approve & deny carry one shared message; issue takes an optional
    // per-certificate "valid until" (within each cert's profile range).
    const [bulk, setBulk] = useState<{ type: 'approve' | 'deny' | 'issue'; rows: any[] } | null>(null);
    const [bulkMessage, setBulkMessage] = useState('');
    const [bulkBusy, setBulkBusy] = useState(false);
    const [certProfiles, setCertProfiles] = useState<any[]>([]);
    const [issueValidity, setIssueValidity] = useState<Record<string, string>>({}); // csrId → yyyy-MM-dd

    const { caId: scopeCaId, spaceId: scopeSpaceId, caQuery } = useScope();

    const loadRequests = () => {
        setLoading(true);
        setError(null);
        apiGet<any[]>(`/api/v1/admin/requests${caQuery()}`)
            .then((data) => { setRequests(Array.isArray(data) ? data : []); setLoading(false); })
            .catch((err) => { setError(errorNotice(err, 'Failed to load requests')); setLoading(false); });
    };

    useEffect(() => {
        loadRequests();
        // Cert profiles give each request's validity ceiling for the per-cert issue picker.
        apiGet<any>('/api/v1/admin/cert-profiles')
            .then((d) => setCertProfiles(Array.isArray(d) ? d : (d.items || d.profiles || [])))
            .catch(() => { /* picker just falls back to unbounded + backend enforcement */ });
    }, [scopeCaId, scopeSpaceId]); // eslint-disable-line react-hooks/exhaustive-deps

    const today = new Date().toISOString().slice(0, 10);
    const csrProfileMaxDate = (c: any): string | undefined => {
        const cpId = c.certificateProfileId || c.certProfileId;
        if (!cpId) return undefined;
        const cp = certProfiles.find((p) => (p.id || p.certProfileId) === cpId);
        return isoPeriodToMaxDate(cp?.validityPeriodMax);
    };

    // Bucket each request into a filter tab. "Pending" must include the approval-workflow states
    // (PendingApproval / PartiallyApproved / null) — not just exact "Pending" — otherwise requests
    // awaiting approval are hidden under the default filter while the dashboard still counts them.
    const matchesFilter = (csr: any, filter: string): boolean => {
        if (filter === 'All') return true;
        const s = (csr.status || '').toLowerCase();
        const issued = !!csr.issuedCertificateId || s === 'issued' || s === 'completed';
        switch (filter) {
            case 'Issued': return issued;
            case 'Approved': return !issued && s === 'approved';
            case 'Pending': return !issued && (s === '' || s === 'pending' || s === 'pendingapproval' || s === 'partiallyapproved');
            case 'Rejected': return s === 'rejected' || s === 'failed';
            case 'Cancelled': return s === 'cancelled';
            default: return false;
        }
    };
    const filtered = requests.filter((csr) => matchesFilter(csr, statusFilter));

    const openBulk = (type: 'approve' | 'deny' | 'issue', rows: any[]) => { setBulkMessage(''); setIssueValidity({}); setBulk({ type, rows }); };

    // Approve and deny ask for step-up: one prompt names every selected request, and each is then
    // decided with that token. Issue follows an approval and asks for none. Approve/deny share one
    // message, issue takes an optional per-cert validity. Never abort on a single failure — collect each failure's reason
    // (e.g. "You cannot approve your own request") and surface them in the summary toast.
    //
    // Every call passes `toast: false`. The client's own error toast is per-request and correct for
    // a single action, but here it fires once per failed row and then the summary below says the
    // same thing again in aggregate — approving twelve requests of which eight fail would raise
    // nine toasts for one click. The summary is the better report because it counts and
    // deduplicates, so it is the one that survives.
    const runBulk = async () => {
        if (!bulk) return;
        const { type, rows } = bulk;
        const msg = bulkMessage.trim();
        if (type === 'deny' && !msg) return; // reason required to deny
        setBulkBusy(true);
        let ok = 0;
        const failReasons: string[] = [];
        if (type !== 'issue') {
            try {
                const result = await runWithOneStepUp(rows, csrId, requireStepUp,
                    type === 'approve' ? StepUpOps.ApproveRequest : StepUpOps.RejectRequest,
                    (c, headers) => type === 'approve'
                        ? apiPost(`/api/v1/admin/requests/${csrId(c)}/approve`, { comment: msg }, { toast: false, headers })
                        : apiPost(`/api/v1/admin/requests/${csrId(c)}/reject`, { reason: msg }, { toast: false, headers }));
                if (result.cancelled && result.ok === 0) { setBulkBusy(false); return; }
                ok = result.ok;
                failReasons.push(...result.failures);
            } catch (err: any) {
                failReasons.push(err?.message || 'Failed');
            }
        }
        else for (const c of rows) {
            const cid = csrId(c);
            try {
                // Optional per-cert "valid until" (end of the chosen day); blank → omit so the backend
                // coalesces validity from the effective cert profile (clamped to the issuing CA).
                await apiPost('/api/v1/admin/certificates/issue', {
                    csrId: cid,
                    ...(issueValidity[cid] ? { notAfter: new Date(`${issueValidity[cid]}T23:59:59Z`).toISOString() } : {}),
                }, { toast: false });
                ok++;
            } catch (err: any) {
                failReasons.push(err?.message || 'Failed');
            }
        }
        setBulkBusy(false);
        setBulk(null);
        setBulkMessage('');
        // Two stacked toasts: a success for what went through, then a warning per distinct failure
        // reason — so "Approved 5" sits above "1 failed — You cannot approve your own request".
        const noun = type === 'issue' ? 'certificate' : 'request';
        const verb = type === 'approve' ? 'Approved' : type === 'deny' ? 'Denied' : 'Issued';
        if (ok > 0) showToast('success', `${verb} ${ok} ${noun}${ok === 1 ? '' : 's'}`);
        if (failReasons.length > 0) {
            const distinct = Array.from(new Set(failReasons));
            showToast('warning', `${failReasons.length} failed — ${distinct.join('; ')}`);
        }
        if (ok === 0 && failReasons.length === 0) showToast('info', 'No changes made');
        loadRequests();
    };

    const record: RecordDescriptor<any> = {
        kind: 'certificate-request',
        key: csrId,
        title: (c) => c.subjectName || c.subject || 'Certificate Request',
        status: (c) => { const st = csrStatus(c); return { label: csrStatusLabel(c), tone: st === 'active' ? 'ok' : st === 'revoked' ? 'bad' : st === 'pending' ? 'warn' : 'neutral' }; },
        columns: [
            { key: 'status', header: 'Status', defaultWidth: 180, minWidth: 120, truncate: false, exportValue: (c) => csrStatusLabel(c), render: (c) => <StatusBadge status={csrStatus(c)} label={csrStatusLabel(c)} /> },
            { key: 'subject', header: 'Subject', defaultWidth: 280, minWidth: 160, sortable: true, exportValue: (c) => c.subjectName || c.subject || '', render: (c) => <span className="text-sm text-ink truncate">{c.subjectName || c.subject}</span> },
            { key: 'algorithm', header: 'Algorithm', defaultWidth: 110, sortable: true, exportValue: (c) => c.keyAlgorithm || '', render: (c) => <span className="text-xs text-ink-muted">{c.keyAlgorithm}</span> },
            { key: 'size', header: 'Size', defaultWidth: 80, exportValue: (c) => (c.keySize ?? ''), render: (c) => <span className="text-xs text-ink-muted">{c.keySize}</span> },
            { key: 'submitted', header: 'Submitted', defaultWidth: 160, sortable: true, sortValue: (c) => c.submittedAt ? new Date(c.submittedAt) : null, exportValue: (c) => formatDate(c.submittedAt), render: (c) => <span className="text-xs text-ink-muted">{formatDate(c.submittedAt)}</span> },
        ],
        sections: [
            { fields: [
                { label: 'Subject', value: (c) => c.subjectName || c.subject },
                { label: 'SANs', value: (c) => parseJsonSafe(c.subjectAlternativeNames) },
                { label: 'Submitted', value: (c) => formatDate(c.submittedAt) },
            ] },
            { title: 'Key', fields: [
                { label: 'Key Algorithm', value: (c) => c.keyAlgorithm },
                { label: 'Key Size', value: (c) => c.keySize },
                { label: 'Signature Algorithm', value: (c) => c.signatureAlgorithm },
            ] },
            { fields: [{ label: 'Next', value: () => 'Open the full page to approve, reject, cancel or issue.' }] },
        ],
        audit: { tab: 'General', target: (c) => ({ type: 'CertificateRequest', id: csrId(c) }) },
        page: { path: (c) => `/certificates/requests/${csrId(c)}` },
    };

    return (
        <div className="p-3 sm:p-6 space-y-4 sm:space-y-6">
            <div className="flex items-center justify-between flex-wrap gap-2">
                <h1 className="text-xl font-semibold text-ink">Certificate Requests</h1>
                <div className="flex gap-2 items-center">
                    <div className="flex rounded overflow-hidden border border-line-strong">
                        {STATUS_FILTERS.map((f) => (
                            <button key={f} onClick={() => setStatusFilter(f)}
                                className={`px-3 py-1.5 text-xs font-medium transition-colors ${statusFilter === f ? 'bg-accent text-on-accent' : 'bg-sunken text-ink hover:bg-hover'}`}>
                                {f}
                            </button>
                        ))}
                    </div>
                    <button onClick={loadRequests} className="px-3 py-1.5 text-xs bg-sunken text-ink rounded hover:bg-hover transition-colors">Refresh</button>
                </div>
            </div>

            <DataTable<any>
                tableId="certificate-requests"
                title="Certificate Requests"
                rows={filtered}
                loading={loading}
                error={error}
                empty="No certificate requests found"
                {...recordTableProps(record)}
                selectable
                bulkActions={[
                    { label: 'Approve', variant: 'primary', enabledFor: canApprove, onClick: (rows) => openBulk('approve', rows) },
                    { label: 'Deny', variant: 'danger', enabledFor: canApprove, onClick: (rows) => openBulk('deny', rows) },
                    { label: 'Issue', variant: 'primary', enabledFor: canIssue, onClick: (rows) => openBulk('issue', rows) },
                ]}
                exportFileName="certificate-requests"
            />

            {/* Bulk approve / deny — one message for the whole batch */}
            {bulk && (
                <div className="fixed inset-0 bg-scrim flex items-center justify-center z-[60]" onClick={() => !bulkBusy && setBulk(null)}>
                    <div className="bg-raised border border-line rounded-lg shadow-2xl w-full max-w-md mx-4" onClick={(e) => e.stopPropagation()}>
                        <div className="px-5 py-4 border-b border-line">
                            <h3 className="text-sm font-semibold text-ink">
                                {bulk.type === 'approve' ? 'Approve' : bulk.type === 'deny' ? 'Deny' : 'Issue'} {bulk.rows.length} {bulk.type === 'issue' ? 'certificate' : 'request'}{bulk.rows.length === 1 ? '' : 's'}
                            </h3>
                        </div>
                        <div className="px-5 py-4 space-y-3">
                            <p className="text-xs text-ink-muted">
                                {bulk.type === 'approve'
                                    ? 'This records your approval on each selected request. Requests needing more approvers stay pending.'
                                    : bulk.type === 'deny'
                                        ? 'This rejects every selected request. This cannot be undone.'
                                        : "This issues a certificate for each selected approved request. Validity defaults to each request's cert profile; optionally set an earlier valid-until per certificate below."}
                            </p>
                            {bulk.type !== 'issue' && (
                                <div>
                                    <label className="block text-xs font-semibold text-ink-muted mb-1">
                                        {bulk.type === 'approve' ? 'Approval comment (optional)' : 'Rejection reason *'}
                                    </label>
                                    <textarea value={bulkMessage} onChange={(e) => setBulkMessage(e.target.value)} rows={3}
                                        placeholder={bulk.type === 'approve' ? 'Applied to every approval…' : 'Applied to every rejection…'}
                                        className="w-full px-3 py-2 bg-raised border border-line-strong rounded text-sm text-ink placeholder-ink-faint resize-none focus:outline-none focus:border-accent" />
                                </div>
                            )}
                            {bulk.type === 'issue' && (
                                <div className="space-y-1.5">
                                    <div className="flex items-center justify-between px-1">
                                        <label className="text-xs font-semibold text-ink-muted">Valid until (optional)</label>
                                        <span className="text-[10px] text-ink-muted">blank = profile default</span>
                                    </div>
                                    <div className="max-h-60 overflow-y-auto border border-line rounded divide-y divide-line">
                                        {bulk.rows.map((c) => {
                                            const cid = csrId(c);
                                            const max = csrProfileMaxDate(c);
                                            return (
                                                <div key={cid} className="flex items-center gap-2 px-3 py-2">
                                                    <span className="flex-1 min-w-0 truncate text-xs text-ink" title={c.subjectName || c.subject}>{c.subjectName || c.subject}</span>
                                                    <input type="date" value={issueValidity[cid] || ''} min={today} max={max}
                                                        onChange={(e) => setIssueValidity((prev) => ({ ...prev, [cid]: e.target.value }))}
                                                        className="px-2 py-1 text-xs bg-raised border border-line-strong rounded text-ink focus:outline-none focus:border-accent" />
                                                </div>
                                            );
                                        })}
                                    </div>
                                    <p className="text-[10px] text-ink-muted px-1">Capped at each certificate's profile maximum; the server also clamps to the issuing CA and rejects anything below the profile minimum.</p>
                                </div>
                            )}
                        </div>
                        <div className="px-5 py-4 border-t border-line flex gap-2 justify-end">
                            <button onClick={() => setBulk(null)} disabled={bulkBusy} className="px-4 py-2 text-xs bg-sunken text-ink rounded hover:bg-hover transition-colors disabled:opacity-50">Cancel</button>
                            <button onClick={runBulk} disabled={bulkBusy || (bulk.type === 'deny' && !bulkMessage.trim())}
                                className={`px-4 py-2 text-xs text-on-accent rounded transition-colors disabled:opacity-50 ${bulk.type === 'deny' ? 'bg-crit hover:bg-crit-hover' : bulk.type === 'issue' ? 'bg-accent hover:bg-accent-hover' : 'bg-ok hover:bg-ok-hover'}`}>
                                {bulkBusy
                                    ? (bulk.type === 'approve' ? 'Approving…' : bulk.type === 'deny' ? 'Denying…' : 'Issuing…')
                                    : `${bulk.type === 'approve' ? 'Approve' : bulk.type === 'deny' ? 'Deny' : 'Issue'} ${bulk.rows.length}`}
                            </button>
                        </div>
                    </div>
                </div>
            )}
        </div>
    );
};

export default CertificateRequests;
