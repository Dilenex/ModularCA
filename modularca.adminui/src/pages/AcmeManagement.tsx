import React, { useState, useEffect, useCallback } from 'react';
import { apiGet, apiPost, apiDeleteWithMfa, API_BASE } from '../api/client';
import { useScope } from '../context/ScopeContext';
import { useStepUp } from '../components/StepUpMfaContext';
import { StatusBadge } from '@shared/components/cards/StatusBadge';
import { DetailField } from '@shared/components/cards/DetailField';
import ConfirmModal from '../components/ConfirmModal';
import { DataTable, DataTableColumn, DataTableBulkAction } from '@shared/components/DataTable';
import { StepUpOps } from '@shared/generated';

function formatDate(d: string | null) {
    if (!d) return '-';
    return new Date(d).toLocaleDateString('en-US', { year: 'numeric', month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' });
}

/* ─── EAB Key Management Section ─── */
interface EabKey {
    id: string;
    keyId: string;
    description: string | null;
    isUsed: boolean;
    usedAt: string | null;
    usedByAccountId: string | null;
    createdAt: string;
    expiresAt: string | null;
}

interface NewEabKey {
    id: string;
    keyId: string;
    hmacKey: string;
    description: string | null;
    createdAt: string;
    expiresAt: string | null;
}

const EabKeyManagementSection: React.FC = () => {
    const { requireStepUp } = useStepUp();
    const [keys, setKeys] = useState<EabKey[]>([]);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState<string | null>(null);
    const [generating, setGenerating] = useState(false);
    const [newKey, setNewKey] = useState<NewEabKey | null>(null);
    const [description, setDescription] = useState('');
    const [showCreateForm, setShowCreateForm] = useState(false);
    const [confirmDelete, setConfirmDelete] = useState<EabKey | null>(null);
    const [deleting, setDeleting] = useState(false);
    const [actionError, setActionError] = useState<string | null>(null);
    const [copiedField, setCopiedField] = useState<string | null>(null);

    const loadKeys = useCallback(() => {
        setLoading(true);
        apiGet<EabKey[]>('/api/v1/admin/acme/eab-keys')
            .then(setKeys)
            .catch((err) => setError(err.message))
            .finally(() => setLoading(false));
    }, []);

    useEffect(() => { loadKeys(); }, [loadKeys]);

    const handleGenerate = async () => {
        setGenerating(true);
        setActionError(null);
        try {
            const result = await apiPost<NewEabKey>('/api/v1/admin/acme/eab-keys', {
                description: description || undefined,
            });
            setNewKey(result);
            setDescription('');
            setShowCreateForm(false);
            loadKeys();
        } catch (err: any) {
            setActionError(err.message);
        } finally {
            setGenerating(false);
        }
    };

    const handleDelete = async (id: string) => {
        setActionError(null);
        setDeleting(true);
        try {
            await apiDeleteWithMfa(`/api/v1/admin/acme/eab-keys/${id}`, requireStepUp, StepUpOps.DeleteEabKey, id);
            loadKeys();
        } catch (err: any) {
            if (err.message !== 'Step-up MFA cancelled') setActionError(err.message);
        } finally {
            setDeleting(false);
            setConfirmDelete(null);
        }
    };

    const copyToClipboard = (text: string, field: string) => {
        navigator.clipboard.writeText(text).then(() => {
            setCopiedField(field);
            setTimeout(() => setCopiedField(null), 2000);
        });
    };

    const getKeyStatus = (key: EabKey): { status: 'active' | 'revoked' | 'pending'; label: string } => {
        if (key.isUsed) return { status: 'pending', label: 'Used' };
        if (key.expiresAt && new Date(key.expiresAt) < new Date()) return { status: 'revoked', label: 'Expired' };
        return { status: 'active', label: 'Active' };
    };

    const maskKey = () => '••••••••••••••••';

    const columns: DataTableColumn<EabKey>[] = [
        { key: 'keyId', header: 'Key ID', defaultWidth: 200, minWidth: 140, truncate: false, exportValue: (k) => k.keyId, render: (k) => <span className="font-mono text-xs text-gray-900 dark:text-white truncate">{k.keyId}</span> },
        { key: 'mac', header: 'MAC Key', defaultWidth: 120, exportValue: () => '(hidden)', render: () => <span className="font-mono text-xs text-gray-500">{maskKey()}</span> },
        { key: 'status', header: 'Status', defaultWidth: 100, truncate: false, exportValue: (k) => getKeyStatus(k).label, render: (k) => { const s = getKeyStatus(k); return <StatusBadge status={s.status} label={s.label} />; } },
        { key: 'description', header: 'Description', defaultWidth: 200, exportValue: (k) => k.description || '', render: (k) => <span className="text-xs text-gray-700 dark:text-gray-300 truncate">{k.description || '-'}</span> },
        { key: 'created', header: 'Created', defaultWidth: 160, exportValue: (k) => formatDate(k.createdAt), render: (k) => <span className="text-xs text-gray-600 dark:text-gray-400">{formatDate(k.createdAt)}</span> },
        { key: 'usedBy', header: 'Used By', defaultWidth: 150, exportValue: (k) => k.usedByAccountId || '', render: (k) => <span className="font-mono text-xs text-gray-600 dark:text-gray-400 truncate">{k.usedByAccountId || '-'}</span> },
    ];

    // EAB delete is step-up MFA gated with no bulk endpoint, so Delete is single-select.
    const bulkActions: DataTableBulkAction<EabKey>[] = [
        { label: 'Delete', single: true, variant: 'danger', onClick: (rows) => setConfirmDelete(rows[0]) },
    ];

    const drawer = (k: EabKey) => {
        const s = getKeyStatus(k);
        return (
            <div className="text-sm">
                <DetailField label="Key ID" value={k.keyId} mono />
                <DetailField label="Status" value={s.label} />
                <DetailField label="Description" value={k.description || '-'} />
                <DetailField label="Created" value={formatDate(k.createdAt)} />
                <DetailField label="Expires" value={k.expiresAt ? formatDate(k.expiresAt) : 'Never'} />
                <DetailField label="Used" value={k.isUsed ? 'Yes' : 'No'} />
                {k.usedAt && <DetailField label="Used At" value={formatDate(k.usedAt)} />}
                {k.usedByAccountId && <DetailField label="Used By Account" value={k.usedByAccountId} mono />}
                <p className="text-[11px] text-gray-500 pt-3">The MAC key is shown only once, at creation time.</p>
            </div>
        );
    };

    return (
        <div className="space-y-3">
            <div className="flex items-center justify-between">
                <h2 className="text-sm font-semibold text-gray-900 dark:text-white">EAB Key Management</h2>
                <button
                    onClick={() => { setShowCreateForm(!showCreateForm); setNewKey(null); }}
                    className="px-3 py-1.5 bg-blue-600 hover:bg-blue-700 text-white text-xs font-medium rounded transition-colors"
                >
                    + Generate EAB Key
                </button>
            </div>

            {/* New key creation form */}
            {showCreateForm && (
                <div className="bg-gray-100 dark:bg-gray-800 border border-gray-300 dark:border-gray-700 rounded-lg px-4 py-3">
                    <div className="flex items-end gap-3">
                        <div className="flex-1">
                            <label className="block text-xs text-gray-600 dark:text-gray-400 mb-1">Description (optional)</label>
                            <input
                                type="text"
                                value={description}
                                onChange={(e) => setDescription(e.target.value)}
                                placeholder="e.g., For staging server"
                                className="w-full px-3 py-1.5 bg-gray-50 dark:bg-gray-900 border border-gray-400 dark:border-gray-600 rounded text-sm text-gray-900 dark:text-white placeholder-gray-400 dark:placeholder-gray-500 focus:outline-none focus:border-blue-500"
                            />
                        </div>
                        <button
                            onClick={handleGenerate}
                            disabled={generating}
                            className="px-4 py-1.5 bg-green-600 hover:bg-green-700 disabled:bg-gray-600 text-white text-xs font-medium rounded transition-colors"
                        >
                            {generating ? 'Generating...' : 'Generate'}
                        </button>
                        <button
                            onClick={() => setShowCreateForm(false)}
                            className="px-3 py-1.5 bg-gray-200 dark:bg-gray-700 hover:bg-gray-300 dark:hover:bg-gray-600 text-gray-700 dark:text-gray-300 text-xs font-medium rounded transition-colors"
                        >
                            Cancel
                        </button>
                    </div>
                </div>
            )}

            {/* Newly generated key display */}
            {newKey && (
                <div className="bg-green-50 dark:bg-green-900/20 border border-gray-300 dark:border-gray-700 border-l-4 border-l-green-500 rounded-lg px-4 py-3">
                    <div className="flex items-center gap-2 mb-2">
                        <span className="text-green-800 dark:text-green-400 text-sm font-semibold">New EAB Key Generated</span>
                        <span className="text-xs text-yellow-800 dark:text-yellow-400">(Copy now -- the MAC key will not be shown again)</span>
                    </div>
                    <div className="space-y-2">
                        <div className="flex items-center gap-2">
                            <span className="text-xs text-gray-600 dark:text-gray-400 w-20">Key ID:</span>
                            <code className="text-sm text-gray-900 dark:text-white font-mono bg-gray-50 dark:bg-gray-900 px-2 py-0.5 rounded flex-1">{newKey.keyId}</code>
                            <button
                                onClick={() => copyToClipboard(newKey.keyId, 'keyId')}
                                className="px-2 py-0.5 bg-gray-200 dark:bg-gray-700 hover:bg-gray-300 dark:hover:bg-gray-600 text-gray-700 dark:text-gray-300 text-xs rounded transition-colors"
                            >
                                {copiedField === 'keyId' ? 'Copied!' : 'Copy'}
                            </button>
                        </div>
                        <div className="flex items-center gap-2">
                            <span className="text-xs text-gray-600 dark:text-gray-400 w-20">MAC Key:</span>
                            <code className="text-sm text-gray-900 dark:text-white font-mono bg-gray-50 dark:bg-gray-900 px-2 py-0.5 rounded flex-1">{newKey.hmacKey}</code>
                            <button
                                onClick={() => copyToClipboard(newKey.hmacKey, 'hmacKey')}
                                className="px-2 py-0.5 bg-gray-200 dark:bg-gray-700 hover:bg-gray-300 dark:hover:bg-gray-600 text-gray-700 dark:text-gray-300 text-xs rounded transition-colors"
                            >
                                {copiedField === 'hmacKey' ? 'Copied!' : 'Copy'}
                            </button>
                        </div>
                    </div>
                    <button
                        onClick={() => setNewKey(null)}
                        className="mt-2 text-xs text-gray-600 dark:text-gray-400 hover:text-gray-800 dark:hover:text-gray-200 transition-colors"
                    >
                        Dismiss
                    </button>
                </div>
            )}

            {actionError && (
                <div className="px-4 py-2 bg-red-50 dark:bg-red-900/30 border border-red-300 dark:border-red-700 rounded text-red-800 dark:text-red-300 text-sm">
                    {actionError}
                </div>
            )}

            <DataTable<EabKey>
                tableId="acme-eab-keys"
                title="EAB Keys"
                rows={keys}
                rowKey={(k) => k.id}
                loading={loading}
                error={error}
                empty="No EAB keys found. Generate one to get started."
                columns={columns}
                selectable
                bulkActions={bulkActions}
                exportFileName="acme-eab-keys"
                renderDrawer={drawer}
                drawerTitle={(k) => k.keyId}
            />

            <ConfirmModal
                isOpen={!!confirmDelete}
                title="Delete EAB Key"
                message={confirmDelete ? `Delete EAB key "${confirmDelete.keyId}"? This cannot be undone.` : ''}
                confirmLabel="Delete"
                loading={deleting}
                onConfirm={() => confirmDelete && handleDelete(confirmDelete.id)}
                onCancel={() => setConfirmDelete(null)}
            />
        </div>
    );
};

/* ─── ACME Accounts Section ─── */
const AcmeEndpointsSection: React.FC = () => {
    const { caId: scopeCaId } = useScope();
    const [cas, setCas] = useState<any[]>([]);
    const [selectedCa, setSelectedCa] = useState<string>('');
    const [directory, setDirectory] = useState<any>(null);
    const [loading, setLoading] = useState(true);
    const [dirLoading, setDirLoading] = useState(false);
    const [error, setError] = useState<string | null>(null);

    useEffect(() => {
        apiGet<any>('/api/v1/admin/authorities/hierarchy')
            .then((data) => {
                const flat: any[] = [];
                const flatten = (items: any[]) => {
                    for (const ca of items) {
                        flat.push(ca);
                        if (ca.children) flatten(ca.children);
                    }
                };
                flatten(Array.isArray(data) ? data : []);
                // Hide the System Signing CA — it never serves enrollment protocols.
                // Under a CA scope, only that CA; it never serves protocols for another one.
                const visible = flat
                    .filter(ca => (ca.label || '').toLowerCase() !== 'system-signing-ca')
                    .filter(ca => !scopeCaId || (ca.id || ca.caId) === scopeCaId);
                setCas(visible);
                if (visible.length > 0) setSelectedCa(visible[0].label || '');
                else setSelectedCa('');
            })
            .catch((err) => setError(err.message))
            .finally(() => setLoading(false));
    }, [scopeCaId]); // eslint-disable-line react-hooks/exhaustive-deps

    useEffect(() => {
        if (!selectedCa) return;
        setDirLoading(true);
        setDirectory(null);
        apiGet<any>(`/api/v1/acme/${selectedCa}/directory`)
            .then(setDirectory)
            .catch(() => setDirectory(null))
            .finally(() => setDirLoading(false));
    }, [selectedCa]);

    const directoryUrl = selectedCa
        ? `${API_BASE}/acme/${selectedCa}/directory`
        : `${API_BASE}/acme/directory`;

    return (
        <div className="bg-gray-100 dark:bg-gray-800 border border-gray-300 dark:border-gray-700 rounded-lg p-4 space-y-4">
            <h2 className="text-sm font-semibold text-gray-900 dark:text-white">ACME Endpoints</h2>

            {/* CA Selector */}
            {loading && <div className="text-sm text-gray-600 dark:text-gray-400">Loading CAs...</div>}
            {error && <div className="text-sm text-red-800 dark:text-red-400">{error}</div>}
            {!loading && cas.length > 0 && (
                <div>
                    <label className="block text-xs font-medium text-gray-600 dark:text-gray-400 mb-1">Certificate Authority</label>
                    <select
                        value={selectedCa}
                        onChange={(e) => setSelectedCa(e.target.value)}
                        className="w-full px-3 py-2 bg-white dark:bg-gray-900 border border-gray-300 dark:border-gray-700 rounded text-sm text-gray-900 dark:text-white"
                    >
                        {cas.map((ca) => (
                            <option key={ca.id} value={ca.label}>{ca.name} ({ca.label})</option>
                        ))}
                    </select>
                </div>
            )}

            {/* Directory URL */}
            <div className="bg-gray-50/50 dark:bg-gray-900/50 border border-gray-300 dark:border-gray-700 rounded p-3 space-y-2">
                <p className="text-sm text-gray-700 dark:text-gray-300">
                    Point your ACME client (certbot, acme.sh, win-acme) at the directory URL below.
                </p>
                <DetailField label="Directory URL" value={directoryUrl} mono />
            </div>

            {/* Directory Info */}
            {dirLoading && <div className="text-sm text-gray-600 dark:text-gray-400">Loading directory...</div>}
            {!dirLoading && directory && (
                <div className="space-y-1">
                    <h3 className="text-xs font-semibold text-gray-600 dark:text-gray-400">Directory Response</h3>
                    {Object.entries(directory).map(([key, value]) => {
                        if (typeof value === 'object' && value !== null) {
                            return (
                                <div key={key}>
                                    <span className="text-xs text-gray-600 dark:text-gray-400 font-medium">{key}:</span>
                                    <div className="ml-4">
                                        {Object.entries(value as Record<string, unknown>).map(([subKey, subValue]) => (
                                            <DetailField key={subKey} label={subKey} value={String(subValue)} mono />
                                        ))}
                                    </div>
                                </div>
                            );
                        }
                        return <DetailField key={key} label={key} value={String(value)} mono />;
                    })}
                </div>
            )}
            {!dirLoading && !directory && selectedCa && (
                <div className="text-sm text-gray-600">ACME is not configured for this CA, or the endpoint is not reachable.</div>
            )}
        </div>
    );
};

/* ─── ACME Audit Section ─── */
const acmeAuditAction = (e: any): string => e.action || e.operation || e.eventType || '-';
const acmeAuditIp = (e: any): string => e.clientIp || e.remoteAddress || '';

const AcmeAuditSection: React.FC = () => {
    const [entries, setEntries] = useState<any[]>([]);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState<string | null>(null);

    useEffect(() => {
        apiGet<any>('/api/v1/admin/audit/acme?pageSize=20')
            .then((data) => setEntries(Array.isArray(data) ? data : (data.items || data.entries || data.logs || [])))
            .catch((err) => setError(err.message))
            .finally(() => setLoading(false));
    }, []);

    const columns: DataTableColumn<any>[] = [
        { key: 'time', header: 'Time', defaultWidth: 180, minWidth: 140, exportValue: (e) => formatDate(e.timestamp || e.createdAt), render: (e) => <span className="text-xs text-gray-600 dark:text-gray-400">{formatDate(e.timestamp || e.createdAt)}</span> },
        { key: 'status', header: 'Status', defaultWidth: 90, truncate: false, exportValue: (e) => (e.success !== false ? 'OK' : 'FAIL'), render: (e) => <StatusBadge status={e.success !== false ? 'active' : 'revoked'} label={e.success !== false ? 'OK' : 'FAIL'} /> },
        { key: 'action', header: 'Action', defaultWidth: 200, exportValue: (e) => acmeAuditAction(e), render: (e) => <span className="text-sm text-gray-900 dark:text-white truncate">{acmeAuditAction(e)}</span> },
        { key: 'clientIp', header: 'Client IP', defaultWidth: 160, exportValue: (e) => acmeAuditIp(e), render: (e) => <span className="font-mono text-xs text-gray-600 dark:text-gray-400 truncate">{acmeAuditIp(e) || '-'}</span> },
    ];

    const drawer = (entry: any) => (
        <div className="text-sm">
            {Object.entries(entry).map(([k, v]) => (
                <DetailField key={k} label={k} value={typeof v === 'object' ? JSON.stringify(v, null, 2) : String(v ?? '-')} mono={typeof v === 'object'} />
            ))}
        </div>
    );

    return (
        <div className="space-y-3">
            <h2 className="text-sm font-semibold text-gray-900 dark:text-white">Protocol Audit - ACME</h2>
            <DataTable<any>
                tableId="acme-audit"
                title="ACME Audit"
                rows={entries}
                rowKey={(e) => e.id || e.auditId || `${e.timestamp || e.createdAt}-${acmeAuditAction(e)}`}
                loading={loading}
                error={error}
                empty="No ACME audit entries found"
                columns={columns}
                selectable
                exportFileName="acme-audit"
                renderDrawer={drawer}
                drawerTitle={(e) => acmeAuditAction(e)}
            />
        </div>
    );
};

/* ─── ACME Management Page ─── */
const AcmeManagement: React.FC = () => {
    return (
        <div className="p-3 sm:p-6 space-y-4 sm:space-y-6">
            <h1 className="text-2xl font-bold text-gray-900 dark:text-white">ACME Management</h1>
            <AcmeEndpointsSection />
            <EabKeyManagementSection />
            <AcmeAuditSection />
        </div>
    );
};

export default AcmeManagement;
