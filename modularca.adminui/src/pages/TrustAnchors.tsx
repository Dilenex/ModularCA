import React, { useState, useEffect, useMemo } from 'react';
import type { NoticeInput } from '@shared/notifications/notice';
import { errorNotice } from '@shared-auth/api/notices';
import { Chevron } from '@shared/components/Chevron';
import { apiGet, apiPut, apiDelete, apiPostWithMfa } from '../api/client';
import { useToast } from '@shared/context/ToastContext';
import { StatusBadge } from '@shared/components/cards/StatusBadge';
import { DetailField } from '@shared/components/cards/DetailField';
import ConfirmModal from '../components/ConfirmModal';
import { DataTable, DataTableColumn, DataTableBulkAction } from '@shared/components/DataTable';
import { FieldHint } from '@shared/components/forms';
import { StepUpOps } from '@shared/generated';
import { runWithOneStepUp } from '@shared-auth/api/stepUpBatch';
import { useStepUp } from '../components/StepUpMfaContext';

interface TrustAnchor {
    id: string;
    subjectDN: string;
    issuer: string;
    serialNumber: string;
    notBefore: string;
    notAfter: string;
    label: string;
    description: string;
    isEnabled: boolean;
    importedByUsername: string;
    importedAt: string;
    thumbprints: string;
}

function formatDate(d: string | null) {
    if (!d) return '-';
    return new Date(d).toLocaleDateString('en-US', { year: 'numeric', month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' });
}

function parseThumbprints(raw: string | null | undefined): Record<string, string> {
    if (!raw) return {};
    try {
        const parsed = JSON.parse(raw);
        if (typeof parsed === 'object' && parsed !== null) return parsed;
    } catch {
        // not JSON, return as single entry
    }
    return { thumbprint: raw };
}

/** The SHA-256 thumbprint out of the stored thumbprint set, whichever key spelling the server used. */
function sha256Thumbprint(raw: string | null | undefined): string | null {
    const all = parseThumbprints(raw);
    const key = Object.keys(all).find((k) => /sha[-_]?256/i.test(k));
    return key ? all[key] : null;
}

/* --- Expanded detail panel (accordion) --- */
const AnchorDetail: React.FC<{ anchor: TrustAnchor }> = ({ anchor }) => {
    const thumbprints = parseThumbprints(anchor.thumbprints);
    return (
        <div className="space-y-1">
            <div className="grid grid-cols-1 md:grid-cols-2 gap-x-6">
                <DetailField label="Label" value={anchor.label} />
                <DetailField label="Description" value={anchor.description} />
                <DetailField label="Subject DN" value={anchor.subjectDN} mono />
                <DetailField label="Issuer" value={anchor.issuer} mono />
                <DetailField label="Serial Number" value={anchor.serialNumber} mono />
                <DetailField label="Status" value={<StatusBadge status={anchor.isEnabled ? 'enabled' : 'disabled'} />} />
                <DetailField label="Not Before" value={formatDate(anchor.notBefore)} />
                <DetailField label="Not After" value={formatDate(anchor.notAfter)} />
                <DetailField label="Imported By" value={anchor.importedByUsername} />
                <DetailField label="Imported At" value={formatDate(anchor.importedAt)} />
            </div>
            {Object.keys(thumbprints).length > 0 && (
                <div className="pt-2">
                    <span className="text-ink-muted text-xs font-semibold uppercase">Thumbprints</span>
                    {Object.entries(thumbprints).map(([algo, value]) => (
                        <DetailField key={algo} label={algo} value={value} mono />
                    ))}
                </div>
            )}
            <p className="text-[11px] text-ink-muted pt-2">Select rows in the table to enable, disable, or delete.</p>
        </div>
    );
};

/* --- Import Form --- */
const ImportForm: React.FC<{ onImported: () => void }> = ({ onImported }) => {
    const [expanded, setExpanded] = useState(false);
    const [certificate, setCertificate] = useState('');
    const [label, setLabel] = useState('');
    const [description, setDescription] = useState('');
    const [importing, setImporting] = useState(false);
    const [message, setMessage] = useState<{ type: 'success' | 'error'; text: string; subject?: string; thumbprint?: string | null } | null>(null);

    const { requireStepUp } = useStepUp();
    const handleImport = async () => {
        setImporting(true);
        setMessage(null);
        try {
            const result = await apiPostWithMfa<TrustAnchor>('/api/v1/admin/trust-anchors', { certificate, label, description }, requireStepUp, StepUpOps.ManageTrustAnchor);
            // Echo what was just trusted so the thumbprint can be checked against the one obtained
            // out of band; a bare "imported successfully" gives nothing to compare.
            setMessage({
                type: 'success',
                text: 'Trust anchor imported. Compare this SHA-256 thumbprint with the one you obtained out of band; if they differ, disable or delete the anchor now.',
                subject: result?.subjectDN,
                thumbprint: sha256Thumbprint(result?.thumbprints) ?? Object.values(parseThumbprints(result?.thumbprints))[0] ?? null,
            });
            setCertificate(''); setLabel(''); setDescription('');
            onImported();
        } catch (err: any) {
            setMessage({ type: 'error', text: err.message || 'Failed to import trust anchor.' });
        } finally {
            setImporting(false);
        }
    };

    return (
        <div className="bg-raised border border-line rounded-lg">
            <button onClick={() => setExpanded(!expanded)}
                className="w-full px-4 py-3 flex items-center gap-2 text-left hover:bg-hover bg-sunken transition-colors rounded-lg">
                <span className="text-ink-muted text-xs"><Chevron open={expanded} className="w-3 h-3" /></span>
                <span className="text-sm font-semibold text-ink">Import Trust Anchor</span>
            </button>
            {expanded && (
                <div className="px-4 pb-4 space-y-3">
                    <FieldHint tone="warn">
                        Importing makes this certificate an authority the whole system trusts: every certificate chaining to it is accepted wherever trust anchors are consulted. Verify its SHA-256 thumbprint against a copy obtained out of band (from the issuing organisation directly, not from the same channel the PEM came through) before importing. The thumbprint is shown again after import.
                    </FieldHint>
                    <div>
                        <label className="block text-xs text-ink-muted mb-1">PEM Certificate</label>
                        <textarea value={certificate} onChange={(e) => setCertificate(e.target.value)} rows={8}
                            autoComplete="off" data-1p-ignore data-lpignore="true" data-bwignore data-form-type="other"
                            placeholder={"-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----"}
                            className="w-full px-3 py-2 bg-raised border border-line-strong rounded text-ink data-mono focus:outline-none focus:border-accent resize-y" />
                    </div>
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                        <div>
                            <label className="block text-xs text-ink-muted mb-1">Label</label>
                            <input type="text" value={label} onChange={(e) => setLabel(e.target.value)} autoComplete="off" data-1p-ignore data-lpignore="true" data-bwignore
                                placeholder="e.g. External Root CA"
                                className="w-full px-3 py-2 bg-raised border border-line-strong rounded text-sm text-ink focus:outline-none focus:border-accent" />
                        </div>
                        <div>
                            <label className="block text-xs text-ink-muted mb-1">Description</label>
                            <input type="text" value={description} onChange={(e) => setDescription(e.target.value)} autoComplete="off" data-1p-ignore data-lpignore="true" data-bwignore
                                placeholder="Optional description"
                                className="w-full px-3 py-2 bg-raised border border-line-strong rounded text-sm text-ink focus:outline-none focus:border-accent" />
                        </div>
                    </div>
                    {message && (
                        <div className={`text-xs px-3 py-2 rounded border space-y-1 ${message.type === 'success'
                            ? 'bg-ok-soft text-ok border-ok/40'
                            : 'bg-crit-soft text-crit border-crit/40'}`}>
                            <div>{message.text}</div>
                            {message.subject && <div>Subject: <span className="font-mono break-all">{message.subject}</span></div>}
                            {message.type === 'success' && (
                                <div>SHA-256: <span className="font-mono break-all">{message.thumbprint || 'not returned by the server; open the anchor in the list to read it'}</span></div>
                            )}
                        </div>
                    )}
                    <button onClick={handleImport} disabled={importing || !certificate.trim()}
                        className="px-4 py-2 text-sm bg-accent text-on-accent rounded hover:bg-accent-hover disabled:opacity-50 transition-colors">
                        {importing ? 'Importing...' : 'Import'}
                    </button>
                </div>
            )}
        </div>
    );
};

/* --- Trust Anchors Page --- */
const TrustAnchors: React.FC = () => {
    const { showToast } = useToast();
    const { requireStepUp } = useStepUp();
    const [anchors, setAnchors] = useState<TrustAnchor[]>([]);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState<NoticeInput | null>(null);

    const [confirmBulk, setConfirmBulk] = useState<TrustAnchor[] | null>(null);
    const [confirmLoading, setConfirmLoading] = useState(false);

    const load = () => {
        setLoading(true);
        setError(null);
        apiGet<any>('/api/v1/admin/trust-anchors')
            .then((data) => setAnchors(Array.isArray(data) ? data : (data.items || data.trustAnchors || [])))
            .catch((err) => setError(errorNotice(err, 'The request failed.')))
            .finally(() => setLoading(false));
    };

    useEffect(() => { load(); }, []);

    const bulkSetEnabled = async (rows: TrustAnchor[], enabled: boolean) => {
        const targets = rows.filter((a) => a.isEnabled !== enabled);
        if (targets.length === 0) { showToast('info', `All selected are already ${enabled ? 'enabled' : 'disabled'}.`); return; }
        const result = await runWithOneStepUp(targets, (a) => String(a.id), requireStepUp, StepUpOps.ManageTrustAnchor,
            (a, headers) => apiPut(`/api/v1/admin/trust-anchors/${a.id}/toggle`, { enabled }, { toast: false, headers }));
        const ok = result.ok, failed = result.failures.length;
        if (ok) showToast('success', `${enabled ? 'Enabled' : 'Disabled'} ${ok} anchor${ok !== 1 ? 's' : ''}.`);
        if (failed) showToast('error', `${failed} failed.`);
        load();
    };

    const performBulkDelete = async () => {
        if (!confirmBulk) return;
        setConfirmLoading(true);
        let ok = 0, failed = 0;
        try {
            const result = await runWithOneStepUp(confirmBulk, (a) => String(a.id), requireStepUp, StepUpOps.ManageTrustAnchor,
                (a, headers) => apiDelete(`/api/v1/admin/trust-anchors/${a.id}`, { toast: false, headers }));
            ok = result.ok;
            failed = result.failures.length;
            if (ok) showToast('success', `Deleted ${ok} anchor${ok !== 1 ? 's' : ''}.`);
            if (failed) showToast('error', `${failed} failed to delete.`);
            load();
        } finally {
            setConfirmLoading(false);
            setConfirmBulk(null);
        }
    };

    const columns: DataTableColumn<TrustAnchor>[] = useMemo(() => [
        {
            key: 'labelSubject', header: 'Label / Subject', defaultWidth: 280, minWidth: 180, truncate: false,
            exportValue: (a) => a.label || a.subjectDN,
            render: (a) => (
                <div className="min-w-0">
                    <div className="text-ink font-medium truncate">{a.label || '-'}</div>
                    <div className="text-ink-muted data-mono truncate">{a.subjectDN}</div>
                </div>
            ),
        },
        { key: 'issuer', header: 'Issuer', defaultWidth: 220, exportValue: (a) => a.issuer,
            render: (a) => <span className="data-mono text-ink">{a.issuer}</span> },
        { key: 'expiry', header: 'Expiry', defaultWidth: 160, exportValue: (a) => a.notAfter, render: (a) => formatDate(a.notAfter) },
        { key: 'status', header: 'Status', defaultWidth: 110, truncate: false, exportValue: (a) => (a.isEnabled ? 'Enabled' : 'Disabled'),
            render: (a) => <StatusBadge status={a.isEnabled ? 'enabled' : 'disabled'} /> },
        { key: 'importedBy', header: 'Imported By', defaultWidth: 150, exportValue: (a) => a.importedByUsername, render: (a) => a.importedByUsername || '-' },
    ], []);

    const bulkActions: DataTableBulkAction<TrustAnchor>[] = [
        { label: 'Enable', onClick: (rows) => bulkSetEnabled(rows, true) },
        { label: 'Disable', onClick: (rows) => bulkSetEnabled(rows, false) },
        { label: 'Delete', variant: 'danger', onClick: (rows) => setConfirmBulk(rows) },
    ];

    return (
        <div className="p-3 sm:p-6 space-y-4 sm:space-y-6">
            <h1 className="text-xl font-semibold text-ink">Trust Anchors</h1>

            <ImportForm onImported={load} />

            <DataTable<TrustAnchor>
                tableId="trust-anchors"
                title="Trust Anchors"
                rows={anchors}
                rowKey={(a) => a.id}
                loading={loading}
                error={error}
                empty="No trust anchors imported"
                columns={columns}
                selectable
                bulkActions={bulkActions}
                exportFileName="trust-anchors"
                renderDrawer={(a) => <AnchorDetail anchor={a} />}
                drawerTitle={(a) => a.label || a.subjectDN}
            />

            <ConfirmModal
                isOpen={!!confirmBulk}
                title="Delete Trust Anchors"
                message={confirmBulk ? `Delete ${confirmBulk.length} trust anchor${confirmBulk.length !== 1 ? 's' : ''}? This cannot be undone.` : ''}
                confirmLabel="Delete"
                loading={confirmLoading}
                onConfirm={performBulkDelete}
                onCancel={() => setConfirmBulk(null)}
            />
        </div>
    );
};

export default TrustAnchors;
