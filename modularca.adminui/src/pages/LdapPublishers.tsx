import React, { useState, useEffect } from 'react';
import { apiGet, apiPost, apiPostWithMfa } from '../api/client';
import { useToast } from '../context/ToastContext';
import { useStepUp } from '../components/StepUpMfaContext';
import StatusBadge from '../components/cards/StatusBadge';
import DetailField from '../components/cards/DetailField';
import ConfirmModal from '../components/ConfirmModal';
import { DataTable, DataTableColumn, DataTableBulkAction } from '../components/DataTable';

function formatDate(d: string | null) {
    if (!d) return '-';
    return new Date(d).toLocaleDateString('en-US', { year: 'numeric', month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' });
}

interface LdapPublisher {
    id: string;
    name: string;
    host: string;
    port: number;
    useSsl: boolean;
    username: string;
    baseDn: string;
    userDnTemplate: string;
    updateInterval: string;
    enabled: boolean;
    publishCaCertificate: boolean;
    publishCrl: boolean;
    publishDeltaCrl: boolean;
    publishUserCertificates: boolean;
    lastUpdated: string | null;
    nextUpdate: string | null;
}

const defaultForm = {
    name: '',
    host: '',
    port: '389',
    useSsl: false,
    username: '',
    password: '',
    baseDn: '',
    userDnTemplate: '',
    updateInterval: '',
    enabled: true,
    publishCaCertificate: true,
    publishCrl: true,
    publishDeltaCrl: false,
    publishUserCertificates: false,
};

function publishFlags(p: LdapPublisher): string {
    const flags: string[] = [];
    if (p.publishCaCertificate) flags.push('CA Cert');
    // See LdapPublisherDetail: the wire name is publishCRL, not publishCrl.
    if ((p as any).publishCRL ?? p.publishCrl) flags.push('CRL');
    if (p.publishDeltaCrl) flags.push('Delta');
    if (p.publishUserCertificates) flags.push('User Certs');
    return flags.length > 0 ? flags.join(', ') : 'None';
}

/* ─── read-only drawer for a publisher ─── */
const LdapPublisherDrawer: React.FC<{ publisher: LdapPublisher }> = ({ publisher: p }) => (
    <div className="text-sm">
        <DetailField label="Name" value={p.name} />
        <DetailField label="Host" value={`${p.host}:${p.port}`} mono />
        <DetailField label="Status" value={p.enabled ? 'Enabled' : 'Disabled'} />
        <DetailField label="Use SSL" value={p.useSsl ? 'Yes' : 'No'} />
        <DetailField label="Username" value={p.username || '-'} />
        <DetailField label="Base DN" value={p.baseDn} mono />
        <DetailField label="User DN Template" value={p.userDnTemplate || '-'} mono />
        <DetailField label="Update Interval" value={p.updateInterval || '-'} mono />
        <DetailField label="Publish" value={publishFlags(p)} />
        <DetailField label="Last Updated" value={formatDate(p.lastUpdated)} />
        <DetailField label="Next Update" value={formatDate(p.nextUpdate)} />
        <p className="text-[11px] text-gray-500 pt-3">Open the full page to edit settings.</p>
    </div>
);

/// <summary>
/// Reusable, CA-scoped LDAP publisher manager. Takes the CA id as a prop (rather than
/// reading the route) so it can be embedded under a CA selector on the Distribution page
/// as well as launched per-CA. Owns full CRUD: create/edit/delete/test/enable publishers.
/// </summary>
export const LdapPublisherManager: React.FC<{ caId: string }> = ({ caId }) => {
    const { showToast } = useToast();
    const { requireStepUp } = useStepUp();

    const [publishers, setPublishers] = useState<LdapPublisher[]>([]);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState<string | null>(null);

    // Create form
    const [showCreate, setShowCreate] = useState(false);
    const [creating, setCreating] = useState(false);
    const [form, setForm] = useState({ ...defaultForm });

    // Test connection state
    const [testingId, setTestingId] = useState<string | null>(null);

    // Bulk delete confirm
    const [confirmBulk, setConfirmBulk] = useState<LdapPublisher[] | null>(null);
    const [confirmLoading, setConfirmLoading] = useState(false);

    const basePath = `/api/v1/admin/authorities/${caId}/ldap-publishers`;

    const load = () => {
        setLoading(true);
        setError(null);
        apiGet<any>(basePath)
            .then((data) => setPublishers(Array.isArray(data) ? data : (data.items || data.publishers || [])))
            .catch((err) => setError(err.message))
            .finally(() => setLoading(false));
    };

    useEffect(() => {
        if (!caId) return;
        load();
        setShowCreate(false);
        // eslint-disable-next-line react-hooks/exhaustive-deps
    }, [caId]);

    const handleCreate = async () => {
        if (!form.name.trim() || !form.host.trim() || !form.baseDn.trim()) {
            showToast('error', 'Name, Host, and Base DN are required');
            return;
        }
        setCreating(true);
        try {
            await apiPost(basePath, {
                name: form.name,
                host: form.host,
                port: parseInt(form.port, 10) || 389,
                useSsl: form.useSsl,
                username: form.username || undefined,
                password: form.password || undefined,
                baseDn: form.baseDn,
                userDnTemplate: form.userDnTemplate || undefined,
                updateInterval: form.updateInterval || undefined,
                enabled: form.enabled,
                publishCaCertificate: form.publishCaCertificate,
                publishCrl: form.publishCrl,
                publishDeltaCrl: form.publishDeltaCrl,
                publishUserCertificates: form.publishUserCertificates,
            });
            showToast('success', 'LDAP publisher created');
            setShowCreate(false);
            setForm({ ...defaultForm });
            load();
        } catch (err: any) {
            showToast('error', err.message || 'Failed to create publisher');
        } finally {
            setCreating(false);
        }
    };

    const handleTest = async (p: LdapPublisher) => {
        setTestingId(p.id);
        try {
            const result = await apiPost<any>(`${basePath}/${p.id}/test`, {});
            if (result?.success) {
                showToast('success', result.message || 'Connection successful');
            } else {
                showToast('error', result?.message || 'Connection test failed');
            }
        } catch (err: any) {
            showToast('error', err.message || 'Connection test failed');
        } finally {
            setTestingId(null);
        }
    };

    const performBulkDelete = async () => {
        if (!confirmBulk) return;
        setConfirmLoading(true);
        // One step-up token (bound to this CA) authorizes the whole batch of deletes instead of
        // prompting once per publisher.
        const actions = confirmBulk.map((p) => ({ id: p.id, action: 'delete' }));
        try {
            const res: any = await apiPostWithMfa(`${basePath}/bulk`, { actions }, requireStepUp, 'bulk-ldap-publisher', caId);
            const okCount = res?.ok ?? 0, skipped = res?.skipped ?? 0, failed = res?.failed ?? 0;
            if (okCount) showToast('success', `Deleted ${okCount} publisher${okCount !== 1 ? 's' : ''}.`);
            if (skipped) showToast('warning', `${skipped} skipped (not found).`);
            if (failed) showToast('error', `${failed} failed to delete.`);
            load();
        } catch (err: any) {
            if (err.message !== 'Step-up MFA cancelled') showToast('error', err.message || 'Bulk delete failed.');
        } finally {
            setConfirmLoading(false);
            setConfirmBulk(null);
        }
    };

    const inputClass = 'w-full px-3 py-2 bg-gray-50 dark:bg-gray-900 border border-gray-300 dark:border-gray-700 rounded text-sm text-gray-900 dark:text-white placeholder-gray-400 dark:placeholder-gray-500 focus:outline-none focus:border-blue-500';
    const labelClass = 'block text-xs text-gray-600 dark:text-gray-400 mb-1';

    /// <summary>
    /// Renders a toggle checkbox used in both create and edit forms for LDAP publisher configuration.
    /// </summary>
    const ToggleField: React.FC<{ label: string; checked: boolean; onChange: (v: boolean) => void }> = ({ label, checked, onChange }) => (
        <label className="flex items-center gap-2 cursor-pointer text-sm">
            <div
                onClick={() => onChange(!checked)}
                className={`relative w-8 h-4 rounded-full transition-colors cursor-pointer ${checked ? 'bg-blue-600' : 'bg-gray-400 dark:bg-gray-600'}`}
            >
                <div className={`absolute top-0.5 left-0.5 w-3 h-3 rounded-full bg-white transition-transform ${checked ? 'translate-x-4' : ''}`} />
            </div>
            <span className="text-gray-700 dark:text-gray-300">{label}</span>
        </label>
    );

    /// <summary>
    /// Renders the create/edit form fields for an LDAP publisher using the provided state and setter.
    /// </summary>
    const renderFormFields = (f: typeof defaultForm, setF: (v: typeof defaultForm) => void, isEdit: boolean) => (
        <div className="space-y-3">
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
                <div>
                    <label className={labelClass}>Name *</label>
                    <input type="text" value={f.name} onChange={(e) => setF({ ...f, name: e.target.value })}
                        placeholder="Production LDAP" className={inputClass} />
                </div>
                <div>
                    <label className={labelClass}>Host *</label>
                    <input type="text" value={f.host} onChange={(e) => setF({ ...f, host: e.target.value })}
                        placeholder="ldap.example.com" className={inputClass} />
                </div>
                <div>
                    <label className={labelClass}>Port</label>
                    <input type="text" inputMode="numeric" value={f.port}
                        onChange={(e) => setF({ ...f, port: e.target.value.replace(/\D/g, '') })}
                        placeholder="389" className={inputClass} />
                </div>
                <div>
                    <label className={labelClass}>Username</label>
                    <input type="text" value={f.username} onChange={(e) => setF({ ...f, username: e.target.value })}
                        placeholder="cn=admin,dc=example,dc=com" className={inputClass} />
                </div>
                <div>
                    <label className={labelClass}>Password</label>
                    <input type="password" value={f.password} onChange={(e) => setF({ ...f, password: e.target.value })}
                        placeholder={isEdit ? '(unchanged)' : ''} className={inputClass} />
                </div>
                <div>
                    <label className={labelClass}>Base DN *</label>
                    <input type="text" value={f.baseDn} onChange={(e) => setF({ ...f, baseDn: e.target.value })}
                        placeholder="dc=example,dc=com" className={inputClass} />
                </div>
                <div className="md:col-span-2">
                    <label className={labelClass}>User DN Template</label>
                    <input type="text" value={f.userDnTemplate} onChange={(e) => setF({ ...f, userDnTemplate: e.target.value })}
                        placeholder="uid={email},ou=People,{baseDn}" className={inputClass} />
                </div>
                <div>
                    <label className={labelClass}>Update Interval (cron)</label>
                    <input type="text" value={f.updateInterval} onChange={(e) => setF({ ...f, updateInterval: e.target.value })}
                        placeholder="0 */6 * * *" className={`${inputClass} font-mono`} />
                </div>
            </div>
            <div className="flex flex-wrap gap-4 pt-2">
                <ToggleField label="Use SSL" checked={f.useSsl} onChange={(v) => setF({ ...f, useSsl: v })} />
                <ToggleField label="Enabled" checked={f.enabled} onChange={(v) => setF({ ...f, enabled: v })} />
            </div>
            <div className="pt-2">
                <span className={`${labelClass} mb-2`}>Publish Options</span>
                <div className="flex flex-wrap gap-4">
                    <label className="flex items-center gap-1.5 text-sm text-gray-700 dark:text-gray-300 cursor-pointer">
                        <input type="checkbox" checked={f.publishCaCertificate} onChange={(e) => setF({ ...f, publishCaCertificate: e.target.checked })}
                            className="rounded border-gray-400 dark:border-gray-600 text-blue-600 focus:ring-blue-500" />
                        CA Certificate
                    </label>
                    <label className="flex items-center gap-1.5 text-sm text-gray-700 dark:text-gray-300 cursor-pointer">
                        <input type="checkbox" checked={f.publishCrl} onChange={(e) => setF({ ...f, publishCrl: e.target.checked })}
                            className="rounded border-gray-400 dark:border-gray-600 text-blue-600 focus:ring-blue-500" />
                        CRL
                    </label>
                    <label className="flex items-center gap-1.5 text-sm text-gray-700 dark:text-gray-300 cursor-pointer">
                        <input type="checkbox" checked={f.publishDeltaCrl} onChange={(e) => setF({ ...f, publishDeltaCrl: e.target.checked })}
                            className="rounded border-gray-400 dark:border-gray-600 text-blue-600 focus:ring-blue-500" />
                        Delta CRL
                    </label>
                    <label className="flex items-center gap-1.5 text-sm text-gray-700 dark:text-gray-300 cursor-pointer">
                        <input type="checkbox" checked={f.publishUserCertificates} onChange={(e) => setF({ ...f, publishUserCertificates: e.target.checked })}
                            className="rounded border-gray-400 dark:border-gray-600 text-blue-600 focus:ring-blue-500" />
                        User Certificates
                    </label>
                </div>
            </div>
        </div>
    );

    const columns: DataTableColumn<LdapPublisher>[] = [
        { key: 'name', header: 'Name', defaultWidth: 170, minWidth: 130, truncate: false, exportValue: (p) => p.name, render: (p) => <span className="text-gray-900 dark:text-white truncate">{p.name}</span> },
        { key: 'status', header: 'Status', defaultWidth: 100, truncate: false, exportValue: (p) => (p.enabled ? 'enabled' : 'disabled'), render: (p) => <StatusBadge status={p.enabled ? 'enabled' : 'disabled'} /> },
        { key: 'host', header: 'Host', defaultWidth: 180, exportValue: (p) => `${p.host}:${p.port}`, render: (p) => <span className="font-mono text-xs text-gray-700 dark:text-gray-300 truncate">{p.host}:{p.port}</span> },
        { key: 'publishes', header: 'Publishes', defaultWidth: 180, exportValue: (p) => publishFlags(p), render: (p) => <span className="text-xs text-gray-700 dark:text-gray-300 truncate">{publishFlags(p)}</span> },
        { key: 'update', header: 'Update', defaultWidth: 110, exportValue: (p) => p.updateInterval || '', render: (p) => <span className="font-mono text-xs text-gray-700 dark:text-gray-300">{p.updateInterval || '-'}</span> },
        { key: 'lastUpdated', header: 'Last Updated', defaultWidth: 160, exportValue: (p) => formatDate(p.lastUpdated), render: (p) => <span className="text-xs text-gray-700 dark:text-gray-300">{formatDate(p.lastUpdated)}</span> },
    ];

    const bulkActions: DataTableBulkAction<LdapPublisher>[] = [
        { label: 'Test Connection', single: true, enabledFor: (p) => testingId !== p.id, onClick: (rows) => handleTest(rows[0]) },
        { label: 'Delete', variant: 'danger', onClick: (rows) => setConfirmBulk(rows) },
    ];

    return (
        <div className="space-y-4">
            <div className="flex items-center justify-between">
                <h2 className="text-lg font-semibold text-gray-900 dark:text-white">Publishers</h2>
                <button onClick={() => setShowCreate(!showCreate)}
                    className="px-4 py-2 text-sm bg-blue-600 text-white rounded hover:bg-blue-700 transition-colors">
                    {showCreate ? 'Cancel' : 'Add Publisher'}
                </button>
            </div>

            {showCreate && (
                <div className="bg-gray-100 dark:bg-gray-800 border border-gray-300 dark:border-gray-700 rounded-lg p-4 space-y-3">
                    <h4 className="text-sm font-semibold text-gray-900 dark:text-white">New LDAP Publisher</h4>
                    {renderFormFields(form, setForm, false)}
                    <button onClick={handleCreate} disabled={creating || !form.name.trim() || !form.host.trim() || !form.baseDn.trim()}
                        className="px-4 py-2 text-sm bg-blue-600 text-white rounded hover:bg-blue-700 disabled:opacity-50 transition-colors">
                        {creating ? 'Creating...' : 'Create'}
                    </button>
                </div>
            )}

            <DataTable<LdapPublisher>
                tableId="distribution-ldap-publishers"
                title="Publishers"
                rows={publishers}
                rowKey={(p) => p.id}
                loading={loading}
                error={error}
                empty="No LDAP publishers configured for this CA"
                columns={columns}
                selectable
                bulkActions={bulkActions}
                exportFileName="ldap-publishers"
                renderDrawer={(p) => <LdapPublisherDrawer publisher={p} />}
                drawerTitle={(p) => p.name}
                detailPath={(p) => `/distribution/ldap/${p.id}?caId=${caId}`}
            />

            <ConfirmModal
                isOpen={!!confirmBulk}
                title="Delete LDAP Publishers"
                message={confirmBulk ? `Delete ${confirmBulk.length} publisher${confirmBulk.length !== 1 ? 's' : ''}? This cannot be undone.` : ''}
                confirmLabel="Delete"
                loading={confirmLoading}
                onConfirm={performBulkDelete}
                onCancel={() => setConfirmBulk(null)}
            />
        </div>
    );
};

export default LdapPublisherManager;
