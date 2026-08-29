import React, { useState, useEffect, useMemo } from 'react';
import { Chevron } from '@shared/components/Chevron';
import { apiGet, apiPost, apiPut, apiDelete } from '../api/client';
import { useToast } from '@shared/context/ToastContext';
import { StatusBadge } from '@shared/components/cards/StatusBadge';
import { DetailField } from '@shared/components/cards/DetailField';
import ConfirmModal from '../components/ConfirmModal';
import { DataTable, DataTableColumn, DataTableBulkAction } from '@shared/components/DataTable';

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
                    <span className="text-gray-600 text-xs font-semibold uppercase">Thumbprints</span>
                    {Object.entries(thumbprints).map(([algo, value]) => (
                        <DetailField key={algo} label={algo} value={value} mono />
                    ))}
                </div>
            )}
            <p className="text-[11px] text-gray-500 pt-2">Select rows in the table to enable, disable, or delete.</p>
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
    const [message, setMessage] = useState<{ type: 'success' | 'error'; text: string } | null>(null);

    const handleImport = async () => {
        setImporting(true);
        setMessage(null);
        try {
            await apiPost('/api/v1/admin/trust-anchors', { certificate, label, description });
            setMessage({ type: 'success', text: 'Trust anchor imported successfully.' });
            setCertificate(''); setLabel(''); setDescription('');
            onImported();
        } catch (err: any) {
            setMessage({ type: 'error', text: err.message || 'Failed to import trust anchor.' });
        } finally {
            setImporting(false);
        }
    };

    return (
        <div className="bg-gray-100 dark:bg-gray-800 border border-gray-300 dark:border-gray-700 rounded-lg">
            <button onClick={() => setExpanded(!expanded)}
                className="w-full px-4 py-3 flex items-center gap-2 text-left hover:bg-gray-200/50 dark:bg-gray-700/50 transition-colors rounded-lg">
                <span className="text-gray-600 text-xs"><Chevron open={expanded} className="w-3 h-3" /></span>
                <span className="text-sm font-semibold text-gray-900 dark:text-white">Import Trust Anchor</span>
            </button>
            {expanded && (
                <div className="px-4 pb-4 space-y-3">
                    <div>
                        <label className="block text-xs text-gray-600 dark:text-gray-400 mb-1">PEM Certificate</label>
                        <textarea value={certificate} onChange={(e) => setCertificate(e.target.value)} rows={8}
                            autoComplete="off" data-1p-ignore data-lpignore="true" data-bwignore data-form-type="other"
                            placeholder={"-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----"}
                            className="w-full px-3 py-2 bg-gray-50 dark:bg-gray-900 border border-gray-300 dark:border-gray-700 rounded text-sm text-gray-900 dark:text-white font-mono focus:outline-none focus:border-blue-500 resize-y" />
                    </div>
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                        <div>
                            <label className="block text-xs text-gray-600 dark:text-gray-400 mb-1">Label</label>
                            <input type="text" value={label} onChange={(e) => setLabel(e.target.value)} autoComplete="off" data-1p-ignore data-lpignore="true" data-bwignore
                                placeholder="e.g. External Root CA"
                                className="w-full px-3 py-2 bg-gray-50 dark:bg-gray-900 border border-gray-300 dark:border-gray-700 rounded text-sm text-gray-900 dark:text-white focus:outline-none focus:border-blue-500" />
                        </div>
                        <div>
                            <label className="block text-xs text-gray-600 dark:text-gray-400 mb-1">Description</label>
                            <input type="text" value={description} onChange={(e) => setDescription(e.target.value)} autoComplete="off" data-1p-ignore data-lpignore="true" data-bwignore
                                placeholder="Optional description"
                                className="w-full px-3 py-2 bg-gray-50 dark:bg-gray-900 border border-gray-300 dark:border-gray-700 rounded text-sm text-gray-900 dark:text-white focus:outline-none focus:border-blue-500" />
                        </div>
                    </div>
                    {message && (
                        <div className={`text-xs px-3 py-2 rounded border ${message.type === 'success'
                            ? 'bg-green-50 dark:bg-green-900/50 text-green-800 dark:text-green-300 border-green-300 dark:border-green-700'
                            : 'bg-red-50 dark:bg-red-900/50 text-red-800 dark:text-red-300 border-red-300 dark:border-red-700'}`}>
                            {message.text}
                        </div>
                    )}
                    <button onClick={handleImport} disabled={importing || !certificate.trim()}
                        className="px-4 py-2 text-sm bg-blue-600 text-white rounded hover:bg-blue-700 disabled:opacity-50 transition-colors">
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
    const [anchors, setAnchors] = useState<TrustAnchor[]>([]);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState<string | null>(null);

    const [confirmBulk, setConfirmBulk] = useState<TrustAnchor[] | null>(null);
    const [confirmLoading, setConfirmLoading] = useState(false);

    const load = () => {
        setLoading(true);
        setError(null);
        apiGet<any>('/api/v1/admin/trust-anchors')
            .then((data) => setAnchors(Array.isArray(data) ? data : (data.items || data.trustAnchors || [])))
            .catch((err) => setError(err.message))
            .finally(() => setLoading(false));
    };

    useEffect(() => { load(); }, []);

    const bulkSetEnabled = async (rows: TrustAnchor[], enabled: boolean) => {
        const targets = rows.filter((a) => a.isEnabled !== enabled);
        if (targets.length === 0) { showToast('info', `All selected are already ${enabled ? 'enabled' : 'disabled'}.`); return; }
        let ok = 0, failed = 0;
        for (const a of targets) {
            try { await apiPut(`/api/v1/admin/trust-anchors/${a.id}/toggle`, { enabled }); ok++; }
            catch { failed++; }
        }
        if (ok) showToast('success', `${enabled ? 'Enabled' : 'Disabled'} ${ok} anchor${ok !== 1 ? 's' : ''}.`);
        if (failed) showToast('error', `${failed} failed.`);
        load();
    };

    const performBulkDelete = async () => {
        if (!confirmBulk) return;
        setConfirmLoading(true);
        let ok = 0, failed = 0;
        try {
            for (const a of confirmBulk) {
                try { await apiDelete(`/api/v1/admin/trust-anchors/${a.id}`); ok++; }
                catch { failed++; }
            }
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
                    <div className="text-gray-900 dark:text-white font-medium truncate">{a.label || '-'}</div>
                    <div className="text-xs text-gray-600 dark:text-gray-400 font-mono truncate">{a.subjectDN}</div>
                </div>
            ),
        },
        { key: 'issuer', header: 'Issuer', defaultWidth: 220, exportValue: (a) => a.issuer,
            render: (a) => <span className="font-mono text-xs text-gray-700 dark:text-gray-300">{a.issuer}</span> },
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
            <h1 className="text-2xl font-bold text-gray-900 dark:text-white">Trust Anchors</h1>

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
