import React, { useState, useEffect } from 'react';
import { apiGet, apiPost } from '../api/client';
import { useToast } from '@shared/context/ToastContext';
import { StatusBadge } from '@shared/components/cards/StatusBadge';
import { DetailField } from '@shared/components/cards/DetailField';
import { DataTable, DataTableColumn } from '@shared/components/DataTable';

function formatDate(d: string | null) {
    if (!d) return '-';
    return new Date(d).toLocaleDateString('en-US', { year: 'numeric', month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' });
}

/** Converts an ISO-8601 period (e.g. "P1Y", "P90D") to a yyyy-MM-dd "max date" from today — the upper
 *  bound for the per-cert validity picker. Time components are ignored. Undefined if absent/unparseable. */
function isoPeriodToMaxDate(iso?: string | null): string | undefined {
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
    const [requests, setRequests] = useState<any[]>([]);
    const [statusFilter, setStatusFilter] = useState<string>('Pending');
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState<string | null>(null);

    // Bulk approve/deny/issue — approve & deny carry one shared message; issue takes an optional
    // per-certificate "valid until" (within each cert's profile range).
    const [bulk, setBulk] = useState<{ type: 'approve' | 'deny' | 'issue'; rows: any[] } | null>(null);
    const [bulkMessage, setBulkMessage] = useState('');
    const [bulkBusy, setBulkBusy] = useState(false);
    const [certProfiles, setCertProfiles] = useState<any[]>([]);
    const [issueValidity, setIssueValidity] = useState<Record<string, string>>({}); // csrId → yyyy-MM-dd

    const loadRequests = () => {
        setLoading(true);
        setError(null);
        apiGet<any[]>('/api/v1/admin/requests')
            .then((data) => { setRequests(Array.isArray(data) ? data : []); setLoading(false); })
            .catch((err) => { setError(err.message || 'Failed to load requests'); setLoading(false); });
    };

    useEffect(() => {
        loadRequests();
        // Cert profiles give each request's validity ceiling for the per-cert issue picker.
        apiGet<any>('/api/v1/admin/cert-profiles')
            .then((d) => setCertProfiles(Array.isArray(d) ? d : (d.items || d.profiles || [])))
            .catch(() => { /* picker just falls back to unbounded + backend enforcement */ });
    }, []);

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

    // Loop the (no-step-up) per-request endpoints; approve/deny share one message, issue takes an
    // optional per-cert validity. Never abort on a single failure — collect each failure's reason
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
        for (const c of rows) {
            const cid = csrId(c);
            try {
                if (type === 'approve') await apiPost(`/api/v1/admin/requests/${cid}/approve`, { comment: msg }, { toast: false });
                else if (type === 'deny') await apiPost(`/api/v1/admin/requests/${cid}/reject`, { reason: msg }, { toast: false });
                // Optional per-cert "valid until" (end of the chosen day); blank → omit so the backend
                // coalesces validity from the effective cert profile (clamped to the issuing CA).
                else await apiPost('/api/v1/admin/certificates/issue', {
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

    const columns: DataTableColumn<any>[] = [
        { key: 'status', header: 'Status', defaultWidth: 180, minWidth: 120, truncate: false, exportValue: (c) => csrStatusLabel(c), render: (c) => <StatusBadge status={csrStatus(c)} label={csrStatusLabel(c)} /> },
        { key: 'subject', header: 'Subject', defaultWidth: 280, minWidth: 160, exportValue: (c) => c.subjectName || c.subject || '', render: (c) => <span className="text-sm text-gray-800 dark:text-gray-200 truncate">{c.subjectName || c.subject}</span> },
        { key: 'algorithm', header: 'Algorithm', defaultWidth: 110, exportValue: (c) => c.keyAlgorithm || '', render: (c) => <span className="text-xs text-gray-600 dark:text-gray-400">{c.keyAlgorithm}</span> },
        { key: 'size', header: 'Size', defaultWidth: 80, exportValue: (c) => (c.keySize ?? ''), render: (c) => <span className="text-xs text-gray-600 dark:text-gray-400">{c.keySize}</span> },
        { key: 'submitted', header: 'Submitted', defaultWidth: 160, exportValue: (c) => formatDate(c.submittedAt), render: (c) => <span className="text-xs text-gray-600 dark:text-gray-400">{formatDate(c.submittedAt)}</span> },
    ];

    const drawer = (c: any) => (
        <div className="text-sm">
            <DetailField label="Subject" value={c.subjectName || c.subject} />
            <DetailField label="Status" value={csrStatusLabel(c)} />
            <DetailField label="Key Algorithm" value={c.keyAlgorithm} />
            <DetailField label="Key Size" value={c.keySize} />
            <DetailField label="Signature Algorithm" value={c.signatureAlgorithm} />
            <DetailField label="SANs" value={parseJsonSafe(c.subjectAlternativeNames)} />
            <DetailField label="Submitted" value={formatDate(c.submittedAt)} />
            <p className="text-[11px] text-gray-500 pt-3">Open the full page to approve, reject, cancel or issue.</p>
        </div>
    );

    return (
        <div className="p-3 sm:p-6 space-y-4 sm:space-y-6">
            <div className="flex items-center justify-between flex-wrap gap-2">
                <h1 className="text-2xl font-bold text-gray-900 dark:text-white">Certificate Requests</h1>
                <div className="flex gap-2 items-center">
                    <div className="flex rounded overflow-hidden border border-gray-400 dark:border-gray-600">
                        {STATUS_FILTERS.map((f) => (
                            <button key={f} onClick={() => setStatusFilter(f)}
                                className={`px-3 py-1.5 text-xs font-medium transition-colors ${statusFilter === f ? 'bg-blue-600 text-white' : 'bg-gray-200 dark:bg-gray-700 text-gray-700 dark:text-gray-300 hover:bg-gray-300 dark:hover:bg-gray-600'}`}>
                                {f}
                            </button>
                        ))}
                    </div>
                    <button onClick={loadRequests} className="px-3 py-1.5 text-xs bg-gray-200 dark:bg-gray-700 text-gray-700 dark:text-gray-300 rounded hover:bg-gray-300 dark:hover:bg-gray-600 transition-colors">Refresh</button>
                </div>
            </div>

            <DataTable<any>
                tableId="certificate-requests"
                title="Certificate Requests"
                rows={filtered}
                rowKey={csrId}
                loading={loading}
                error={error}
                empty="No certificate requests found"
                columns={columns}
                selectable
                bulkActions={[
                    { label: 'Approve', variant: 'primary', enabledFor: canApprove, onClick: (rows) => openBulk('approve', rows) },
                    { label: 'Deny', variant: 'danger', enabledFor: canApprove, onClick: (rows) => openBulk('deny', rows) },
                    { label: 'Issue', variant: 'primary', enabledFor: canIssue, onClick: (rows) => openBulk('issue', rows) },
                ]}
                exportFileName="certificate-requests"
                renderDrawer={drawer}
                drawerTitle={(c) => c.subjectName || c.subject || 'Certificate Request'}
                detailPath={(c) => `/certificates/requests/${csrId(c)}`}
            />

            {/* Bulk approve / deny — one message for the whole batch */}
            {bulk && (
                <div className="fixed inset-0 bg-black/30 dark:bg-black/70 flex items-center justify-center z-[60]" onClick={() => !bulkBusy && setBulk(null)}>
                    <div className="bg-gray-100 dark:bg-gray-800 border border-gray-300 dark:border-gray-700 rounded-lg shadow-2xl w-full max-w-md mx-4" onClick={(e) => e.stopPropagation()}>
                        <div className="px-5 py-4 border-b border-gray-300 dark:border-gray-700">
                            <h3 className="text-sm font-semibold text-gray-900 dark:text-white">
                                {bulk.type === 'approve' ? 'Approve' : bulk.type === 'deny' ? 'Deny' : 'Issue'} {bulk.rows.length} {bulk.type === 'issue' ? 'certificate' : 'request'}{bulk.rows.length === 1 ? '' : 's'}
                            </h3>
                        </div>
                        <div className="px-5 py-4 space-y-3">
                            <p className="text-xs text-gray-600 dark:text-gray-400">
                                {bulk.type === 'approve'
                                    ? 'This records your approval on each selected request. Requests needing more approvers stay pending.'
                                    : bulk.type === 'deny'
                                        ? 'This rejects every selected request. This cannot be undone.'
                                        : "This issues a certificate for each selected approved request. Validity defaults to each request's cert profile; optionally set an earlier valid-until per certificate below."}
                            </p>
                            {bulk.type !== 'issue' && (
                                <div>
                                    <label className="block text-xs font-semibold text-gray-600 dark:text-gray-400 mb-1">
                                        {bulk.type === 'approve' ? 'Approval comment (optional)' : 'Rejection reason *'}
                                    </label>
                                    <textarea value={bulkMessage} onChange={(e) => setBulkMessage(e.target.value)} rows={3}
                                        placeholder={bulk.type === 'approve' ? 'Applied to every approval…' : 'Applied to every rejection…'}
                                        className="w-full px-3 py-2 bg-gray-50 dark:bg-gray-900 border border-gray-300 dark:border-gray-700 rounded text-sm text-gray-900 dark:text-white placeholder-gray-400 dark:placeholder-gray-500 resize-none focus:outline-none focus:border-blue-500" />
                                </div>
                            )}
                            {bulk.type === 'issue' && (
                                <div className="space-y-1.5">
                                    <div className="flex items-center justify-between px-1">
                                        <label className="text-xs font-semibold text-gray-600 dark:text-gray-400">Valid until (optional)</label>
                                        <span className="text-[10px] text-gray-500">blank = profile default</span>
                                    </div>
                                    <div className="max-h-60 overflow-y-auto border border-gray-300 dark:border-gray-700 rounded divide-y divide-gray-200 dark:divide-gray-700/60">
                                        {bulk.rows.map((c) => {
                                            const cid = csrId(c);
                                            const max = csrProfileMaxDate(c);
                                            return (
                                                <div key={cid} className="flex items-center gap-2 px-3 py-2">
                                                    <span className="flex-1 min-w-0 truncate text-xs text-gray-800 dark:text-gray-200" title={c.subjectName || c.subject}>{c.subjectName || c.subject}</span>
                                                    <input type="date" value={issueValidity[cid] || ''} min={today} max={max}
                                                        onChange={(e) => setIssueValidity((prev) => ({ ...prev, [cid]: e.target.value }))}
                                                        className="px-2 py-1 text-xs bg-gray-50 dark:bg-gray-900 border border-gray-300 dark:border-gray-700 rounded text-gray-900 dark:text-white focus:outline-none focus:border-blue-500" />
                                                </div>
                                            );
                                        })}
                                    </div>
                                    <p className="text-[10px] text-gray-500 px-1">Capped at each certificate's profile maximum; the server also clamps to the issuing CA and rejects anything below the profile minimum.</p>
                                </div>
                            )}
                        </div>
                        <div className="px-5 py-4 border-t border-gray-300 dark:border-gray-700 flex gap-2 justify-end">
                            <button onClick={() => setBulk(null)} disabled={bulkBusy} className="px-4 py-2 text-xs bg-gray-200 dark:bg-gray-700 text-gray-700 dark:text-gray-300 rounded hover:bg-gray-300 dark:hover:bg-gray-600 transition-colors disabled:opacity-50">Cancel</button>
                            <button onClick={runBulk} disabled={bulkBusy || (bulk.type === 'deny' && !bulkMessage.trim())}
                                className={`px-4 py-2 text-xs text-white rounded transition-colors disabled:opacity-50 ${bulk.type === 'deny' ? 'bg-red-600 hover:bg-red-700' : bulk.type === 'issue' ? 'bg-blue-600 hover:bg-blue-700' : 'bg-green-600 hover:bg-green-700'}`}>
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
