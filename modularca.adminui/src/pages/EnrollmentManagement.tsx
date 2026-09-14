import React, { useEffect, useState, useMemo } from 'react';
import { apiGet, apiPost, apiDelete } from '../api/client';
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

const inputClass = 'w-full bg-gray-200 dark:bg-gray-700 border border-gray-400 dark:border-gray-600 text-gray-900 dark:text-white rounded px-2 py-1 text-sm';

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
    const [tokens, setTokens] = useState<any[]>([]);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState<string | null>(null);
    const [signingProfiles, setSigningProfiles] = useState<any[]>([]);

    // One form, one button. The selected protocol decides which fields show and which endpoint
    // the Generate button calls; see components/enrollmentForm for the branching.
    const [showCreate, setShowCreate] = useState(false);
    const [form, setForm] = useState<EnrollmentFormState>(emptyEnrollmentForm());
    const [formError, setFormError] = useState<string | null>(null);
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
            setTokens(Array.isArray(data) ? data : ((data as any).items || []));
        } catch (err: any) {
            setError(err.message || 'Failed to load tokens');
        }
        setLoading(false);
    };

    useEffect(() => {
        loadTokens();
        apiGet<any>('/api/v1/admin/signing-profiles')
            .then(data => setSigningProfiles(Array.isArray(data) ? data : (data?.items || [])))
            .catch(() => setSigningProfiles([]));
    }, []);

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
            setFormError(err?.message || 'Failed to create the enrollment credential');
        } finally {
            setSubmitting(false);
        }
    };

    const performBulkRevoke = async () => {
        if (!confirmBulk) return;
        setConfirmLoading(true);
        try {
            for (const t of confirmBulk) {
                if (t.isRevoked) continue;
                try { await apiDelete(`/api/v1/admin/enrollment-tokens/${t.id}`); }
                catch { /* one failure should not stop the rest */ }
            }
            loadTokens();
        } finally {
            setConfirmLoading(false);
            setConfirmBulk(null);
        }
    };

    const columns: DataTableColumn<any>[] = useMemo(() => [
        { key: 'status', header: 'Status', defaultWidth: 90, truncate: false, exportValue: (t) => (t.isRevoked ? 'Revoked' : 'Active'),
            render: (t) => <StatusBadge status={t.isRevoked ? 'revoked' : 'active'} /> },
        { key: 'token', header: 'Token / Reference', defaultWidth: 220, exportValue: (t) => (isCmpCredentialRow(t) ? `CMP ${t.cmpReferenceValue || ''}` : t.token),
            render: (t) => <span className="font-mono text-xs">{tokenColumnLabel(t)}</span> },
        { key: 'uses', header: 'Uses', defaultWidth: 110, exportValue: (t) => `${t.usesRemaining}/${t.maxUses || 'unlimited'}`,
            render: (t) => <span className="text-gray-600 dark:text-gray-400">{t.usesRemaining}/{t.maxUses || '∞'}</span> },
        { key: 'protocol', header: 'Protocol', defaultWidth: 100, truncate: false, exportValue: (t) => t.protocol || '',
            render: (t) => (t.protocol ? <StatusBadge status="pending" label={t.protocol} /> : <span className="text-gray-500">Any</span>) },
        { key: 'created', header: 'Created', defaultWidth: 150, exportValue: (t) => t.createdAt, render: (t) => formatDate(t.createdAt) },
        { key: 'expires', header: 'Expires', defaultWidth: 150, exportValue: (t) => t.expiresAt, render: (t) => formatDate(t.expiresAt) },
    ], []);

    const bulkActions: DataTableBulkAction<any>[] = [
        { label: 'Revoke', variant: 'danger', enabledFor: (t) => !t.isRevoked, onClick: (rows) => setConfirmBulk(rows) },
    ];

    const renderDrawer = (t: any) => (
        <div className="text-sm">
            {isCmpCredentialRow(t) ? (
                <>
                    <DetailField label="Type" value="CMP shared-secret credential" />
                    <DetailField label="Reference Value" value={t.cmpReferenceValue} mono />
                    <DetailField label="Secret" value="Shown once at creation; not stored in a form that can be shown again." />
                </>
            ) : (
                <DetailField label="Token" value={t.token} mono />
            )}
            <DetailField label="Status" value={<StatusBadge status={t.isRevoked ? 'revoked' : 'active'} />} />
            <DetailField label="Uses Remaining" value={`${t.usesRemaining}/${t.maxUses || '∞'}`} />
            <DetailField label="Created" value={formatDate(t.createdAt)} />
            <DetailField label="Expires" value={formatDate(t.expiresAt)} />
            <DetailField label="Subject Restriction" value={t.subjectRestriction} />
            <DetailField label="SAN Restriction" value={t.sanRestriction} />
            <DetailField label="Protocol" value={t.protocol || 'Any'} />
            <p className="text-[11px] text-gray-500 pt-2">Select rows in the table to revoke.</p>
        </div>
    );

    const meta = enrollmentProtocolMeta(form.protocol);
    const kind = enrollmentKind(form.protocol);

    return (
        <div className="p-3 sm:p-6 space-y-4 sm:space-y-6">
            <div className="flex items-center justify-between">
                <h1 className="text-2xl font-bold text-gray-900 dark:text-white">Enrollment Management</h1>
                <button onClick={() => (showCreate ? setShowCreate(false) : openCreate())} className="px-4 py-2 bg-blue-600 text-white rounded hover:bg-blue-700 text-sm">
                    {showCreate ? 'Cancel' : 'Generate Enrollment Credential'}
                </button>
            </div>

            {showCreate && (
                <div className="bg-gray-100 dark:bg-gray-800 border border-gray-300 dark:border-gray-700 rounded-lg p-4 space-y-3">
                    <h3 className="text-gray-900 dark:text-white text-sm font-semibold">Generate Enrollment Credential</h3>

                    <div>
                        <label className="text-xs text-gray-600 dark:text-gray-400">Protocol</label>
                        <select value={form.protocol} onChange={e => selectProtocol(e.target.value)} className={inputClass}>
                            <option value="">Choose a protocol…</option>
                            {ENROLLMENT_PROTOCOLS.map(p => (
                                <option key={p.value} value={p.value}>{p.label}</option>
                            ))}
                        </select>
                        {meta && <p className="text-[11px] text-gray-500 dark:text-gray-400 mt-1">{meta.description}</p>}
                    </div>

                    {kind !== null && (
                        <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                            {kind === 'cmp' && (
                                <>
                                    <div>
                                        <label className="text-xs text-gray-600 dark:text-gray-400">Reference value (senderKID)</label>
                                        <input type="text" value={form.referenceValue} onChange={e => setForm({ ...form, referenceValue: e.target.value })}
                                            className={`${inputClass} font-mono`} placeholder="e.g., printer-fleet" />
                                    </div>
                                    <div>
                                        <label className="text-xs text-gray-600 dark:text-gray-400">Signing profile (decides the CA)</label>
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
                                <label className="text-xs text-gray-600 dark:text-gray-400">Expires In (hours)</label>
                                <input type="text" inputMode="numeric" value={form.expiresInHours} onChange={e => { const v = e.target.value.replace(/\D/g, ''); setForm({ ...form, expiresInHours: v === '' ? '' : +v }); }}
                                    className={inputClass} />
                            </div>
                            <div>
                                <label className="text-xs text-gray-600 dark:text-gray-400">Max Uses (0 = unlimited)</label>
                                <input type="text" inputMode="numeric" value={form.maxUses} onChange={e => { const v = e.target.value.replace(/\D/g, ''); setForm({ ...form, maxUses: v === '' ? '' : +v }); }}
                                    className={inputClass} />
                            </div>

                            {kind === 'token' && (
                                <>
                                    <div>
                                        <label className="text-xs text-gray-600 dark:text-gray-400">Subject Restriction (optional)</label>
                                        <input type="text" value={form.subjectRestriction} onChange={e => setForm({ ...form, subjectRestriction: e.target.value })}
                                            className={inputClass} placeholder="e.g., example.com or O=Acme" />
                                    </div>
                                    <div>
                                        <label className="text-xs text-gray-600 dark:text-gray-400">SAN Restriction (optional)</label>
                                        <input type="text" value={form.sanRestriction} onChange={e => setForm({ ...form, sanRestriction: e.target.value })}
                                            className={inputClass} placeholder="e.g., example.com, example.org" />
                                    </div>
                                </>
                            )}
                        </div>
                    )}

                    {kind === 'cmp' && (
                        <p className="text-[11px] text-gray-500 dark:text-gray-400">
                            The shared secret is shown once, after Generate. A CMP credential can enroll any name the request profile permits; it cannot revoke.
                        </p>
                    )}

                    {formError && <p className="text-xs text-red-700 dark:text-red-400">{formError}</p>}
                    <button onClick={handleGenerate} disabled={submitting || kind === null}
                        className="px-4 py-1.5 bg-green-600 text-white rounded text-sm hover:bg-green-700 disabled:opacity-50 disabled:cursor-not-allowed">
                        {submitting ? 'Generating…' : 'Generate'}
                    </button>
                </div>
            )}

            {newCmp && (
                <div className="bg-green-50 dark:bg-green-900/30 border border-green-300 dark:border-green-700 rounded p-4 space-y-3">
                    <p className="text-green-800 dark:text-green-300 text-sm font-semibold">CMP credential created (copy the secret now — it is shown only once)</p>
                    <div className="grid grid-cols-1 sm:grid-cols-[auto_1fr] gap-x-4 gap-y-2 text-xs">
                        <span className="text-gray-700 dark:text-gray-300 font-semibold">Reference value</span>
                        <code className="text-green-800 dark:text-green-200 font-mono bg-gray-50 dark:bg-gray-900 p-2 rounded break-all">{newCmp.referenceValue}</code>
                        <span className="text-gray-700 dark:text-gray-300 font-semibold">Shared secret</span>
                        <code className="text-green-800 dark:text-green-200 font-mono bg-gray-50 dark:bg-gray-900 p-2 rounded break-all">{newCmp.sharedSecret}</code>
                        {newCmp.expiresAt && (<>
                            <span className="text-gray-700 dark:text-gray-300 font-semibold">Expires</span>
                            <span className="text-gray-800 dark:text-gray-200">{formatDate(newCmp.expiresAt)}</span>
                        </>)}
                    </div>
                    <div className="flex gap-2">
                        <button onClick={() => { navigator.clipboard.writeText(newCmp.sharedSecret); }} className="text-xs text-green-800 dark:text-green-400 hover:text-green-300">Copy secret</button>
                        <button onClick={() => { navigator.clipboard.writeText(newCmp.referenceValue); }} className="text-xs text-blue-800 dark:text-blue-400 hover:text-blue-300">Copy reference</button>
                        <button onClick={() => setNewCmp(null)} className="text-xs text-gray-600 dark:text-gray-400 hover:text-gray-300 ml-auto">Dismiss</button>
                    </div>
                    <div className="p-3 bg-gray-50 dark:bg-gray-900 rounded-lg">
                        <p className="text-gray-700 dark:text-gray-300 text-xs font-semibold mb-2">Initial request with OpenSSL (substitute the secret)</p>
                        <pre className="text-blue-800 dark:text-blue-300 text-xs font-mono whitespace-pre overflow-x-auto">{buildOpensslCmpCommand(window.location.origin, newCmp.caLabel, newCmp.referenceValue)}</pre>
                    </div>
                </div>
            )}

            {newToken && (() => {
                const enrollUrl = `${window.location.origin}/api/v1/public/enroll/${newToken.token}/page`;
                const qrSvg = newToken.showQr ? generateQrSvg(enrollUrl, 4, 4) : '';
                return (
                    <div className="bg-green-50 dark:bg-green-900/30 border border-green-300 dark:border-green-700 rounded p-4">
                        <div className="flex items-start justify-between gap-2">
                            <p className="text-green-800 dark:text-green-300 text-sm font-semibold mb-1">Token generated (copy now — shown only once):</p>
                            <button onClick={() => setNewToken(null)} className="text-xs text-gray-600 dark:text-gray-400 hover:text-gray-300">Dismiss</button>
                        </div>
                        <code className="text-green-800 dark:text-green-200 text-xs font-mono bg-gray-50 dark:bg-gray-900 p-2 rounded block break-all">{newToken.token}</code>
                        {newToken.showQr && (
                            <>
                                <div className="mt-4 p-3 bg-gray-50 dark:bg-gray-900 rounded-lg">
                                    <p className="text-gray-700 dark:text-gray-300 text-xs font-semibold mb-2">Enrollment URL</p>
                                    <div className="flex items-center gap-2">
                                        <code className="text-blue-800 dark:text-blue-300 text-xs font-mono bg-gray-100 dark:bg-gray-800 px-2 py-1 rounded flex-1 break-all">{enrollUrl}</code>
                                        <button onClick={() => { navigator.clipboard.writeText(enrollUrl); }}
                                            className="px-3 py-1 bg-blue-600 text-white text-xs rounded hover:bg-blue-700 whitespace-nowrap">Copy URL</button>
                                    </div>
                                </div>
                                <div className="mt-4 flex flex-col items-center">
                                    <p className="text-gray-700 dark:text-gray-300 text-xs font-semibold mb-2">Scan to Enroll</p>
                                    <div className="bg-white p-2 rounded-lg inline-block" dangerouslySetInnerHTML={{ __html: qrSvg }} />
                                    <p className="text-gray-600 text-xs mt-1">Scan with a mobile device to open the enrollment page</p>
                                </div>
                            </>
                        )}
                        <div className="mt-3 flex gap-2">
                            <button onClick={() => { navigator.clipboard.writeText(newToken.token); }} className="text-xs text-green-800 dark:text-green-400 hover:text-green-300">Copy Token</button>
                            {newToken.showQr && (
                                <button onClick={() => { navigator.clipboard.writeText(enrollUrl); }} className="text-xs text-blue-800 dark:text-blue-400 hover:text-blue-300">Copy Enrollment URL</button>
                            )}
                        </div>
                    </div>
                );
            })()}

            <DataTable<any>
                tableId="enrollment-tokens"
                title="Enrollment Tokens"
                rows={tokens}
                rowKey={(t) => t.id}
                loading={loading}
                error={error}
                empty="No active tokens"
                columns={columns}
                selectable
                bulkActions={bulkActions}
                exportFileName="enrollment-tokens"
                renderDrawer={renderDrawer}
                drawerTitle={drawerTitle}
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
