import { useToast } from '@shared/context/ToastContext';
import type { NoticeInput } from '@shared/notifications/notice';
import { InlineNotice } from '@shared/components/InlineNotice';
import { errorNotice } from '@shared-auth/api/notices';
import React, { useEffect, useState, useMemo } from 'react';
import { apiGet, apiPost, apiDelete } from '../api/client';
import { recordTableProps } from '../components/RecordDrawer';
import type { RecordDescriptor } from '@shared/records';
import { useScope } from '../context/ScopeContext';
import { scopeLabel } from '../scope';
import { StatusBadge } from '@shared/components/cards/StatusBadge';
import { DetailField } from '@shared/components/cards/DetailField';
import ConfirmModal from '../components/ConfirmModal';
import { DataTable, DataTableColumn, DataTableBulkAction } from '@shared/components/DataTable';
import { generateQrSvg } from '@shared-auth/utils/qrcode';
import {
    buildOpensslCmpCommand, drawerTitle, isCmpCredentialRow, signingProfileLabel,
    tokenColumnLabel, validateReferenceValue,
} from '../components/cmpCredential';
import {
    buildCmpRequest, buildTokenRequest, ENROLLMENT_PROTOCOLS, emptyEnrollmentForm,
    enrollmentKind, enrollmentProtocolMeta, EnrollmentFormState, showsQrResult,
    validateEnrollmentForm,
} from '../components/enrollmentForm';

function formatDate(d: string | null) {
    if (!d) return '-';
    return new Date(d).toLocaleDateString('en-US', { year: 'numeric', month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' });
}

const inputClass = 'w-full bg-sunken border border-line-strong text-ink rounded px-2 py-1 text-sm';

interface CreatedToken {
    token: string;
    showQr: boolean;
}
interface CreatedCmp {
    referenceValue: string;
    sharedSecret: string;
    expiresAt: string | null;
    caLabel: string | null;
}

const EnrollmentManagement: React.FC = () => {
    const { caId: scopeCaId, inScope, scope } = useScope();
    const [tokens, setTokens] = useState<any[]>([]);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState<NoticeInput | null>(null);
    const [signingProfiles, setSigningProfiles] = useState<any[]>([]);

    // One form, one button. The selected protocol decides which fields show and which endpoint
    // the Generate button calls; see components/enrollmentForm for the branching.
    const [showCreate, setShowCreate] = useState(false);
    const [form, setForm] = useState<EnrollmentFormState>(emptyEnrollmentForm());
    const [formError, setFormError] = useState<NoticeInput | null>(null);
    const [submitting, setSubmitting] = useState(false);

    // Exactly one of these is set after a successful create, matching the selected protocol's kind.
    const [newToken, setNewToken] = useState<CreatedToken | null>(null);
    const [newCmp, setNewCmp] = useState<CreatedCmp | null>(null);

    const [confirmBulk, setConfirmBulk] = useState<any[] | null>(null);
    const [confirmLoading, setConfirmLoading] = useState(false);

    const loadTokens = async () => {
        setLoading(true);
        setError(null);
        try {
            const data = await apiGet<any[]>('/api/v1/admin/enrollment-tokens');
            const all: any[] = Array.isArray(data) ? data : ((data as any).items || []);
            // Under a CA scope, only the credentials bound to that CA.
            setTokens(scopeCaId ? all.filter((t) => inScope(t.certificateAuthorityId || t.caId)) : all);
        } catch (err: any) {
            setError(errorNotice(err, 'Failed to load tokens'));
        }
        setLoading(false);
    };

    useEffect(() => {
        loadTokens();
        apiGet<any>('/api/v1/admin/signing-profiles')
            .then(data => setSigningProfiles(Array.isArray(data) ? data : (data?.items || [])))
            .catch(() => setSigningProfiles([]));
    }, [scopeCaId]); // eslint-disable-line react-hooks/exhaustive-deps

    const openCreate = () => {
        setForm(emptyEnrollmentForm());
        setFormError(null);
        setNewToken(null);
        setNewCmp(null);
        setShowCreate(true);
    };

    // Selecting CMP moves the default expiry to 30 days: a shared secret provisioned into a fleet
    // outlives a one-shot enrollment link. Switching back to a token protocol restores a day.
    const selectProtocol = (protocol: string) => {
        setFormError(null);
        setForm(prev => ({
            ...prev,
            protocol,
            expiresInHours: enrollmentKind(protocol) === 'cmp' ? 720 : 24,
        }));
    };

    const handleGenerate = async () => {
        const problem = validateEnrollmentForm(form, validateReferenceValue);
        if (problem) { setFormError(problem); return; }
        setFormError(null);
        setSubmitting(true);
        try {
            if (enrollmentKind(form.protocol) === 'cmp') {
                const result = await apiPost<any>('/api/v1/admin/enrollment-tokens/cmp-secret', buildCmpRequest(form));
                // The created row carries the CA id; the authorities list carries labels. Best
                // effort for the example command — the placeholder shows if the lookup misses.
                let caLabel: string | null = null;
                try {
                    const cas = await apiGet<any[]>('/api/v1/admin/authorities');
                    const rows = Array.isArray(cas) ? cas : ((cas as any)?.items || []);
                    const tokensNow = await apiGet<any[]>('/api/v1/admin/enrollment-tokens');
                    const created = (Array.isArray(tokensNow) ? tokensNow : ((tokensNow as any)?.items || [])).find((x: any) => x.id === result.id);
                    const ca = created?.certificateAuthorityId ? rows.find((c: any) => c.id === created.certificateAuthorityId) : null;
                    caLabel = ca?.label || null;
                } catch { /* label is cosmetic */ }
                setNewCmp({ referenceValue: result.cmpReferenceValue, sharedSecret: result.sharedSecret, expiresAt: result.expiresAt || null, caLabel });
            } else {
                const result = await apiPost<any>('/api/v1/admin/enrollment-tokens', buildTokenRequest(form));
                setNewToken({ token: result.token, showQr: showsQrResult(form.protocol) });
            }
            setShowCreate(false);
            loadTokens();
        } catch (err: any) {
            setFormError(errorNotice(err, 'Failed to create the enrollment credential'));
        } finally {
            setSubmitting(false);
        }
    };

    const { showToast } = useToast();
    const performBulkRevoke = async () => {
        if (!confirmBulk) return;
        setConfirmLoading(true);
        try {
            // One failure must not stop the rest, and it must not pass unnoticed either: a
            // credential the operator believes revoked and that is still live is the worst outcome.
            let ok = 0;
            const failed: string[] = [];
            for (const t of confirmBulk) {
                if (t.isRevoked) continue;
                try { await apiDelete(`/api/v1/admin/enrollment-tokens/${t.id}`); ok++; }
                catch (err: any) { failed.push(`${t.name || t.id}: ${err?.message || 'failed'}`); }
            }
            if (failed.length === 0) showToast('success', `Revoked ${ok} credential${ok !== 1 ? 's' : ''}.`);
            else showToast('error', `Revoked ${ok}, failed ${failed.length}. Still live: ${failed.join('; ')}`);
            loadTokens();
        } finally {
            setConfirmLoading(false);
            setConfirmBulk(null);
        }
    };

    const record: RecordDescriptor<any> = useMemo(() => ({
        kind: 'enrollment-token',
        key: (t) => t.id,
        title: drawerTitle,
        status: (t) => ({ label: t.isRevoked ? 'Revoked' : 'Active', tone: t.isRevoked ? 'bad' : 'ok' }),
        columns: [
            { key: 'status', header: 'Status', defaultWidth: 90, truncate: false, sortable: true, sortValue: (t) => !!t.isRevoked, exportValue: (t) => (t.isRevoked ? 'Revoked' : 'Active'),
                render: (t) => <StatusBadge status={t.isRevoked ? 'revoked' : 'active'} /> },
            { key: 'token', header: 'Token / Reference', defaultWidth: 220, exportValue: (t) => (isCmpCredentialRow(t) ? `CMP ${t.cmpReferenceValue || ''}` : `Token ${t.id}`),
                render: (t) => <span className="data-mono">{tokenColumnLabel(t)}</span> },
            { key: 'uses', header: 'Uses', defaultWidth: 110, exportValue: (t) => `${t.usesRemaining}/${t.maxUses || 'unlimited'}`,
                render: (t) => <span className="text-ink-muted">{t.usesRemaining}/{t.maxUses || '∞'}</span> },
            { key: 'protocol', header: 'Protocol', defaultWidth: 100, truncate: false, sortable: true, exportValue: (t) => t.protocol || '',
                render: (t) => (t.protocol ? <StatusBadge status="pending" label={t.protocol} /> : <span className="text-ink-muted">Any</span>) },
            { key: 'created', header: 'Created', defaultWidth: 150, sortable: true, sortValue: (t) => t.createdAt ? new Date(t.createdAt) : null, exportValue: (t) => t.createdAt, render: (t) => formatDate(t.createdAt) },
            { key: 'expires', header: 'Expires', defaultWidth: 150, sortable: true, sortValue: (t) => t.expiresAt ? new Date(t.expiresAt) : null, exportValue: (t) => t.expiresAt, render: (t) => formatDate(t.expiresAt) },
        ],
        sections: [
            { fields: [
                { label: 'Type', value: (t) => (isCmpCredentialRow(t) ? 'CMP shared-secret credential' : 'Enrollment token') },
                { label: 'Reference Value', value: (t) => (isCmpCredentialRow(t) ? t.cmpReferenceValue : null), mono: true, copyable: true },
                { label: 'Secret', value: (t) => (isCmpCredentialRow(t) ? 'Shown once at creation; not stored in a form that can be shown again.' : null) },
                { label: 'Token', value: (t) => (isCmpCredentialRow(t) ? null : 'Shown once at creation; only a hash is stored, so it cannot be shown again.') },
                { label: 'Token ID', value: (t) => t.id, mono: true, copyable: true },
                { label: 'Uses Remaining', value: (t) => `${t.usesRemaining}/${t.maxUses || '∞'}` },
                { label: 'Protocol', value: (t) => t.protocol || 'Any' },
            ] },
            { title: 'Validity', fields: [
                { label: 'Created', value: (t) => formatDate(t.createdAt) },
                { label: 'Expires', value: (t) => formatDate(t.expiresAt) },
            ] },
            { title: 'Restrictions', fields: [
                { label: 'Subject Restriction', value: (t) => t.subjectRestriction },
                { label: 'SAN Restriction', value: (t) => t.sanRestriction },
            ] },
        ],
        audit: { tab: 'General', target: (t) => ({ type: 'EnrollmentToken', id: t.id }) },
        actions: [
            { label: 'Revoke', tone: 'danger', enabled: (t) => !t.isRevoked, run: (t) => { setConfirmBulk([t]); } },
        ],
        // eslint-disable-next-line react-hooks/exhaustive-deps
    }), []);

    const bulkActions: DataTableBulkAction<any>[] = [
        { label: 'Revoke', variant: 'danger', enabledFor: (t) => !t.isRevoked, onClick: (rows) => setConfirmBulk(rows) },
    ];

    const meta = enrollmentProtocolMeta(form.protocol);
    const kind = enrollmentKind(form.protocol);

    return (
        <div className="p-3 sm:p-6 space-y-4 sm:space-y-6">
            <div className="flex items-center justify-between">
                <h1 className="text-xl font-semibold text-ink">Enrollment Management</h1>
                <button onClick={() => (showCreate ? setShowCreate(false) : openCreate())} className="px-4 py-2 bg-accent text-on-accent rounded hover:bg-accent-hover text-sm">
                    {showCreate ? 'Cancel' : 'Generate Enrollment Credential'}
                </button>
            </div>

            {showCreate && (
                <div className="bg-raised border border-line rounded-lg p-4 space-y-3">
                    <h3 className="text-ink text-sm font-semibold">Generate Enrollment Credential</h3>

                    <div>
                        <label className="text-xs text-ink-muted">Protocol</label>
                        <select value={form.protocol} onChange={e => selectProtocol(e.target.value)} className={inputClass}>
                            <option value="">Choose a protocol…</option>
                            {ENROLLMENT_PROTOCOLS.map(p => (
                                <option key={p.value} value={p.value}>{p.label}</option>
                            ))}
                        </select>
                        {meta && <p className="text-[11px] text-ink-muted mt-1">{meta.description}</p>}
                    </div>

                    {kind !== null && (
                        <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                            {kind === 'cmp' && (
                                <>
                                    <div>
                                        <label className="text-xs text-ink-muted">Reference value (senderKID)</label>
                                        <input type="text" value={form.referenceValue} onChange={e => setForm({ ...form, referenceValue: e.target.value })}
                                            className={`${inputClass} font-mono`} placeholder="e.g., printer-fleet" />
                                    </div>
                                    <div>
                                        <label className="text-xs text-ink-muted">Signing profile (decides the CA)</label>
                                        <select value={form.signingProfileId} onChange={e => setForm({ ...form, signingProfileId: e.target.value })} className={inputClass}>
                                            <option value="">Choose…</option>
                                            {signingProfiles.map((p: any) => (
                                                <option key={p.id} value={p.id}>{signingProfileLabel(p)}</option>
                                            ))}
                                        </select>
                                    </div>
                                </>
                            )}

                            <div>
                                <label className="text-xs text-ink-muted">Expires In (hours)</label>
                                <input type="text" inputMode="numeric" value={form.expiresInHours} onChange={e => { const v = e.target.value.replace(/\D/g, ''); setForm({ ...form, expiresInHours: v === '' ? '' : +v }); }}
                                    className={inputClass} />
                            </div>
                            <div>
                                <label className="text-xs text-ink-muted">Max Uses (0 = unlimited)</label>
                                <input type="text" inputMode="numeric" value={form.maxUses} onChange={e => { const v = e.target.value.replace(/\D/g, ''); setForm({ ...form, maxUses: v === '' ? '' : +v }); }}
                                    className={inputClass} />
                            </div>

                            {kind === 'token' && (
                                <>
                                    <div>
                                        <label className="text-xs text-ink-muted">Subject Restriction (optional)</label>
                                        <input type="text" value={form.subjectRestriction} onChange={e => setForm({ ...form, subjectRestriction: e.target.value })}
                                            className={inputClass} placeholder="e.g., example.com or O=Acme" />
                                    </div>
                                    <div>
                                        <label className="text-xs text-ink-muted">SAN Restriction (optional)</label>
                                        <input type="text" value={form.sanRestriction} onChange={e => setForm({ ...form, sanRestriction: e.target.value })}
                                            className={inputClass} placeholder="e.g., example.com, example.org" />
                                    </div>
                                </>
                            )}
                        </div>
                    )}

                    {kind === 'cmp' && (
                        <p className="text-[11px] text-ink-muted">
                            The shared secret is shown once, after Generate. A CMP credential can enroll any name the request profile permits; it cannot revoke.
                        </p>
                    )}

                    {formError && <InlineNotice notice={formError} variant="line" />}
                    <button onClick={handleGenerate} disabled={submitting || kind === null}
                        className="px-4 py-1.5 bg-ok text-on-accent rounded text-sm hover:bg-ok-hover disabled:opacity-50 disabled:cursor-not-allowed">
                        {submitting ? 'Generating…' : 'Generate'}
                    </button>
                </div>
            )}

            {newCmp && (
                <div className="bg-ok-soft border border-ok/40 rounded p-4 space-y-3">
                    <p className="text-ok text-sm font-semibold">CMP credential created (copy the secret now — it is shown only once)</p>
                    <div className="grid grid-cols-1 sm:grid-cols-[auto_1fr] gap-x-4 gap-y-2 text-xs">
                        <span className="text-ink font-semibold">Reference value</span>
                        <code className="text-ok font-mono bg-sunken p-2 rounded break-all">{newCmp.referenceValue}</code>
                        <span className="text-ink font-semibold">Shared secret</span>
                        <code className="text-ok font-mono bg-sunken p-2 rounded break-all">{newCmp.sharedSecret}</code>
                        {newCmp.expiresAt && (<>
                            <span className="text-ink font-semibold">Expires</span>
                            <span className="text-ink">{formatDate(newCmp.expiresAt)}</span>
                        </>)}
                    </div>
                    <div className="flex gap-2">
                        <button onClick={() => { navigator.clipboard.writeText(newCmp.sharedSecret); }} className="text-xs text-ok hover:text-ok">Copy secret</button>
                        <button onClick={() => { navigator.clipboard.writeText(newCmp.referenceValue); }} className="text-xs text-accent-ink hover:underline">Copy reference</button>
                        <button onClick={() => setNewCmp(null)} className="text-xs text-ink-muted hover:text-ink ml-auto">Dismiss</button>
                    </div>
                    <div className="p-3 bg-ground rounded-lg">
                        <p className="text-ink text-xs font-semibold mb-2">Initial request with OpenSSL (substitute the secret)</p>
                        <pre className="text-ink data-mono whitespace-pre overflow-x-auto">{buildOpensslCmpCommand(window.location.origin, newCmp.caLabel, newCmp.referenceValue)}</pre>
                    </div>
                </div>
            )}

            {newToken && (() => {
                const enrollUrl = `${window.location.origin}/api/v1/public/enroll/${newToken.token}/page`;
                const qrSvg = newToken.showQr ? generateQrSvg(enrollUrl, 4, 4) : '';
                return (
                    <div className="bg-ok-soft border border-ok/40 rounded p-4">
                        <div className="flex items-start justify-between gap-2">
                            <p className="text-ok text-sm font-semibold mb-1">Token generated (copy now — shown only once):</p>
                            <button onClick={() => setNewToken(null)} className="text-xs text-ink-muted hover:text-ink">Dismiss</button>
                        </div>
                        <code className="text-ok data-mono bg-sunken p-2 rounded block break-all">{newToken.token}</code>
                        {newToken.showQr && (
                            <>
                                <div className="mt-4 p-3 bg-ground rounded-lg">
                                    <p className="text-ink text-xs font-semibold mb-2">Enrollment URL</p>
                                    <div className="flex items-center gap-2">
                                        <code className="text-ink data-mono bg-sunken px-2 py-1 rounded flex-1 break-all">{enrollUrl}</code>
                                        <button onClick={() => { navigator.clipboard.writeText(enrollUrl); }}
                                            className="px-3 py-1 bg-accent text-on-accent text-xs rounded hover:bg-accent-hover whitespace-nowrap">Copy URL</button>
                                    </div>
                                </div>
                                <div className="mt-4 flex flex-col items-center">
                                    <p className="text-ink text-xs font-semibold mb-2">Scan to Enroll</p>
                                    <div className="bg-white p-2 rounded-lg inline-block" dangerouslySetInnerHTML={{ __html: qrSvg }} />
                                    <p className="text-ink-muted text-xs mt-1">Scan with a mobile device to open the enrollment page</p>
                                </div>
                            </>
                        )}
                        <div className="mt-3 flex gap-2">
                            <button onClick={() => { navigator.clipboard.writeText(newToken.token); }} className="text-xs text-ok hover:text-ok">Copy Token</button>
                            {newToken.showQr && (
                                <button onClick={() => { navigator.clipboard.writeText(enrollUrl); }} className="text-xs text-accent-ink hover:underline">Copy Enrollment URL</button>
                            )}
                        </div>
                    </div>
                );
            })()}

            <DataTable<any>
                tableId="enrollment-tokens"
                title="Enrollment Tokens"
                rows={tokens}
                loading={loading}
                error={error}
                empty={scopeCaId ? `No active tokens in ${scopeLabel(scope)}. Change the scope in the sidebar to see others.` : 'No active tokens'}
                {...recordTableProps(record)}
                selectable
                bulkActions={bulkActions}
                exportFileName="enrollment-tokens"
            />

            <ConfirmModal
                isOpen={!!confirmBulk}
                title="Revoke Tokens"
                message={confirmBulk ? `Revoke ${confirmBulk.filter((t) => !t.isRevoked).length} token(s)? Revoked tokens can no longer be used to enroll.` : ''}
                confirmLabel="Revoke"
                loading={confirmLoading}
                onConfirm={performBulkRevoke}
                onCancel={() => setConfirmBulk(null)}
            />
        </div>
    );
};

export default EnrollmentManagement;
