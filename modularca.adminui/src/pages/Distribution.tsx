import React, { useState, useEffect } from 'react';
import { useSearchParams } from 'react-router-dom';
import { apiGet, apiPost, apiPostWithMfa, apiPutWithMfa, API_BASE } from '../api/client';
import { useStepUp } from '../components/StepUpMfaContext';
import { useToast } from '../context/ToastContext';
import { useAuth } from '../context/AuthContext';
import StatusBadge from '../components/cards/StatusBadge';
import DetailField from '../components/cards/DetailField';
import ConfirmModal from '../components/ConfirmModal';
import { DataTable, DataTableColumn, DataTableBulkAction } from '../components/DataTable';
import { LdapPublisherManager } from './LdapPublishers';

function formatDate(d: string | null) {
    if (!d) return '-';
    return new Date(d).toLocaleDateString('en-US', { year: 'numeric', month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' });
}

const crlId = (s: any): string => s.id || s.scheduleId || s.name;

/* ─── read-only drawer for a CRL schedule ─── */
const CrlScheduleDrawer: React.FC<{ schedule: any }> = ({ schedule: s }) => (
    <div className="text-sm">
        <DetailField label="Name" value={s.name} />
        <DetailField label="CA" value={s.caName || s.caId || '-'} />
        <DetailField label="Status" value={s.enabled ? 'Enabled' : 'Disabled'} />
        <DetailField label="Update Interval" value={s.updateInterval || s.cronExpression} mono />
        <DetailField label="Delta Interval" value={s.deltaInterval || '-'} mono />
        <DetailField label="Overlap Period" value={s.overlapPeriod ? String(s.overlapPeriod) : '-'} />
        <DetailField label="Description" value={s.description || '-'} />
        <DetailField label="Last Generated" value={formatDate(s.lastGenerated || s.lastRun)} />
        <DetailField label="Next Update" value={formatDate(s.nextUpdateUtc || s.nextUpdate)} />
        <p className="text-[11px] text-gray-500 pt-3">Open the full page to edit intervals.</p>
    </div>
);

/* ─── CRL Schedules Section ─── */
const CrlSchedulesSection: React.FC = () => {
    const { showToast } = useToast();
    const { requireStepUp } = useStepUp();
    const [schedules, setSchedules] = useState<any[]>([]);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState<string | null>(null);
    const [showCreate, setShowCreate] = useState(false);
    const [creating, setCreating] = useState(false);
    const [cas, setCas] = useState<any[]>([]);
    // Bulk delete confirm
    const [confirmBulk, setConfirmBulk] = useState<any[] | null>(null);
    const [confirmLoading, setConfirmLoading] = useState(false);

    const [form, setForm] = useState({
        name: '',
        cronExpression: '',
        caId: '',
        overlapPeriod: '',
    });

    const load = () => {
        setLoading(true);
        setError(null);
        apiGet<any>('/api/v1/admin/crl-schedules')
            .then((data) => setSchedules(Array.isArray(data) ? data : (data.items || data.schedules || [])))
            .catch((err) => setError(err.message))
            .finally(() => setLoading(false));
    };

    useEffect(() => {
        load();
        apiGet<any>('/api/v1/admin/authorities')
            .then((data) => setCas(Array.isArray(data) ? data : (data.items || data.authorities || [])))
            .catch(() => {});
    }, []);

    const handleCreate = async () => {
        setCreating(true);
        try {
            await apiPostWithMfa('/api/v1/admin/crl-schedules', form, requireStepUp, 'create-crl-schedule');
            setShowCreate(false);
            setForm({ name: '', cronExpression: '', caId: '', overlapPeriod: '' });
            load();
        } catch (err: any) {
            showToast('error', err.message || 'Failed to create schedule');
        } finally {
            setCreating(false);
        }
    };

    // Enable/disable/delete go through the bulk endpoint so the whole multi-row selection
    // is authorized by ONE step-up prompt (batch-scoped 'bulk-crl-schedule' token) instead
    // of one prompt per row.
    const bulkSetEnabled = async (rows: any[], enabled: boolean) => {
        const actions = rows
            .filter((s) => !!s.enabled !== enabled)
            .map((s) => ({ id: crlId(s), action: enabled ? 'enable' : 'disable' }));
        if (actions.length === 0) { showToast('info', `All selected schedules already ${enabled ? 'enabled' : 'disabled'}.`); return; }
        try {
            const res: any = await apiPostWithMfa('/api/v1/admin/crl-schedules/bulk', { actions }, requireStepUp, 'bulk-crl-schedule');
            const okCount = res?.ok ?? 0, skipped = res?.skipped ?? 0, failed = res?.failed ?? 0;
            if (okCount) showToast('success', `${enabled ? 'Enabled' : 'Disabled'} ${okCount} schedule${okCount !== 1 ? 's' : ''}.`);
            if (skipped) showToast('warning', `${skipped} skipped (not found or not permitted).`);
            if (failed) showToast('error', `${failed} failed.`);
        } catch (err: any) {
            if (err.message !== 'Step-up MFA cancelled') showToast('error', err.message || 'Bulk update failed.');
        } finally {
            load();
        }
    };

    const performBulkDelete = async () => {
        if (!confirmBulk) return;
        setConfirmLoading(true);
        const actions = confirmBulk.map((s) => ({ id: crlId(s), action: 'delete' }));
        try {
            const res: any = await apiPostWithMfa('/api/v1/admin/crl-schedules/bulk', { actions }, requireStepUp, 'bulk-crl-schedule');
            const okCount = res?.ok ?? 0, skipped = res?.skipped ?? 0, failed = res?.failed ?? 0;
            if (okCount) showToast('success', `Deleted ${okCount} schedule${okCount !== 1 ? 's' : ''}.`);
            if (skipped) showToast('warning', `${skipped} skipped (not found or not permitted).`);
            if (failed) showToast('error', `${failed} failed to delete.`);
            load();
        } catch (err: any) {
            if (err.message !== 'Step-up MFA cancelled') showToast('error', err.message || 'Bulk delete failed.');
        } finally {
            setConfirmLoading(false);
            setConfirmBulk(null);
        }
    };

    const columns: DataTableColumn<any>[] = [
        { key: 'name', header: 'Name', defaultWidth: 180, minWidth: 140, truncate: false, exportValue: (s) => s.name, render: (s) => <span className="text-gray-900 dark:text-white truncate">{s.name}</span> },
        { key: 'status', header: 'Status', defaultWidth: 100, truncate: false, exportValue: (s) => (s.enabled ? 'enabled' : 'disabled'), render: (s) => <StatusBadge status={s.enabled ? 'enabled' : 'disabled'} /> },
        { key: 'cron', header: 'Cron', defaultWidth: 140, exportValue: (s) => s.cronExpression || s.updateInterval, render: (s) => <span className="font-mono text-xs text-gray-700 dark:text-gray-300">{s.cronExpression || s.updateInterval}</span> },
        { key: 'ca', header: 'CA', defaultWidth: 160, exportValue: (s) => s.caName || s.caId || '', render: (s) => <span className="text-gray-700 dark:text-gray-300 truncate">{s.caName || s.caId || '-'}</span> },
        { key: 'last', header: 'Last Generated', defaultWidth: 160, exportValue: (s) => formatDate(s.lastGenerated || s.lastRun), render: (s) => <span className="text-xs text-gray-700 dark:text-gray-300">{formatDate(s.lastGenerated || s.lastRun)}</span> },
        { key: 'next', header: 'Next Update', defaultWidth: 160, exportValue: (s) => formatDate(s.nextUpdateUtc || s.nextUpdate), render: (s) => <span className="text-xs text-gray-700 dark:text-gray-300">{formatDate(s.nextUpdateUtc || s.nextUpdate)}</span> },
    ];

    const bulkActions: DataTableBulkAction<any>[] = [
        { label: 'Enable', onClick: (rows) => bulkSetEnabled(rows, true) },
        { label: 'Disable', onClick: (rows) => bulkSetEnabled(rows, false) },
        { label: 'Delete', variant: 'danger', onClick: (rows) => setConfirmBulk(rows) },
    ];

    return (
        <div className="space-y-4">
            <div className="flex items-center justify-between">
                <h2 className="text-lg font-semibold text-gray-900 dark:text-white">CRL Schedules</h2>
                <button onClick={() => setShowCreate(!showCreate)}
                    className="px-4 py-2 text-sm bg-blue-600 text-white rounded hover:bg-blue-700 transition-colors">
                    {showCreate ? 'Cancel' : 'Create Schedule'}
                </button>
            </div>

            {showCreate && (
                <div className="bg-gray-100 dark:bg-gray-800 border border-gray-300 dark:border-gray-700 rounded-lg p-4 space-y-3">
                    <h4 className="text-sm font-semibold text-gray-900 dark:text-white">New CRL Schedule</h4>
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                        <div>
                            <label className="block text-xs text-gray-600 dark:text-gray-400 mb-1">Name</label>
                            <input type="text" value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })}
                                className="w-full px-3 py-2 bg-gray-50 dark:bg-gray-900 border border-gray-300 dark:border-gray-700 rounded text-sm text-gray-900 dark:text-white focus:outline-none focus:border-blue-500" />
                        </div>
                        <div>
                            <label className="block text-xs text-gray-600 dark:text-gray-400 mb-1">Cron Expression</label>
                            <input type="text" placeholder="e.g. 0 */6 * * *" value={form.cronExpression} onChange={(e) => setForm({ ...form, cronExpression: e.target.value })}
                                className="w-full px-3 py-2 bg-gray-50 dark:bg-gray-900 border border-gray-300 dark:border-gray-700 rounded text-sm text-gray-900 dark:text-white focus:outline-none focus:border-blue-500" />
                        </div>
                        <div>
                            <label className="block text-xs text-gray-600 dark:text-gray-400 mb-1">Certificate Authority</label>
                            <select value={form.caId} onChange={(e) => setForm({ ...form, caId: e.target.value })}
                                className="w-full px-3 py-2 bg-gray-50 dark:bg-gray-900 border border-gray-300 dark:border-gray-700 rounded text-sm text-gray-900 dark:text-white focus:outline-none focus:border-blue-500">
                                <option value="">Select CA...</option>
                                {cas.map((ca) => (
                                    <option key={ca.id || ca.caId} value={ca.id || ca.caId}>{ca.name || ca.subjectDN}</option>
                                ))}
                            </select>
                        </div>
                        <div>
                            <label className="block text-xs text-gray-600 dark:text-gray-400 mb-1">Overlap Period</label>
                            <input type="text" placeholder="e.g. 1h, 30m" value={form.overlapPeriod} onChange={(e) => setForm({ ...form, overlapPeriod: e.target.value })}
                                className="w-full px-3 py-2 bg-gray-50 dark:bg-gray-900 border border-gray-300 dark:border-gray-700 rounded text-sm text-gray-900 dark:text-white focus:outline-none focus:border-blue-500" />
                        </div>
                    </div>
                    <button onClick={handleCreate} disabled={creating || !form.name || !form.cronExpression}
                        className="px-4 py-2 text-sm bg-blue-600 text-white rounded hover:bg-blue-700 disabled:opacity-50 transition-colors">
                        {creating ? 'Creating...' : 'Create'}
                    </button>
                </div>
            )}

            <DataTable<any>
                tableId="distribution-crl-schedules"
                title="CRL Schedules"
                rows={schedules}
                rowKey={crlId}
                loading={loading}
                error={error}
                empty="No CRL schedules configured"
                columns={columns}
                selectable
                bulkActions={bulkActions}
                exportFileName="crl-schedules"
                renderDrawer={(s) => <CrlScheduleDrawer schedule={s} />}
                drawerTitle={(s) => s.name}
                detailPath={(s) => `/distribution/crl/${crlId(s)}`}
            />

            <ConfirmModal
                isOpen={!!confirmBulk}
                title="Delete CRL Schedules"
                message={confirmBulk ? `Delete ${confirmBulk.length} schedule${confirmBulk.length !== 1 ? 's' : ''}? This cannot be undone.` : ''}
                confirmLabel="Delete"
                loading={confirmLoading}
                onConfirm={performBulkDelete}
                onCancel={() => setConfirmBulk(null)}
            />
        </div>
    );
};

/* ─── Current CRLs Section ─── */
const CurrentCrlsSection: React.FC = () => {
    const [cas, setCas] = useState<any[]>([]);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState<string | null>(null);

    useEffect(() => {
        apiGet<any>('/api/v1/admin/authorities')
            .then((data) => setCas(Array.isArray(data) ? data : (data.items || data.authorities || [])))
            .catch((err) => setError(err.message))
            .finally(() => setLoading(false));
    }, []);

    return (
        <div className="space-y-4">
            <h2 className="text-lg font-semibold text-gray-900 dark:text-white">Current CRLs</h2>

            {loading && <div className="p-4 text-sm text-gray-600 dark:text-gray-400">Loading...</div>}
            {error && <div className="p-4 text-sm text-red-800 dark:text-red-400">{error}</div>}
            {!loading && !error && cas.length === 0 && (
                <div className="p-4 text-sm text-gray-600">No certificate authorities found</div>
            )}

            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                {!loading && !error && cas.map((ca) => {
                    const caId = ca.id || ca.caId;
                    const serial = ca.certificateSerial || ca.serialNumber || ca.certificate?.serialNumber || caId;
                    return (
                        <div key={caId} className="bg-gray-100 dark:bg-gray-800 border border-gray-300 dark:border-gray-700 rounded-lg p-4">
                            <h3 className="text-sm font-semibold text-gray-900 dark:text-white mb-2">{ca.name || ca.subjectDN}</h3>
                            <DetailField label="Serial" value={serial} mono />
                            {ca.crlNumber != null && <DetailField label="CRL Number" value={String(ca.crlNumber)} />}
                            {ca.lastCrlGenerated && <DetailField label="Last Generated" value={formatDate(ca.lastCrlGenerated)} />}
                            {ca.crlEntryCount != null && <DetailField label="Entry Count" value={String(ca.crlEntryCount)} />}
                            <div className="flex gap-2 mt-3">
                                <a href={`${API_BASE}/crl/${serial}`} target="_blank" rel="noopener noreferrer"
                                    className="px-3 py-1 text-xs bg-blue-50 dark:bg-blue-900/50 text-blue-800 dark:text-blue-300 border border-blue-300 dark:border-blue-700 rounded hover:bg-blue-900 transition-colors inline-block">
                                    Download Full CRL
                                </a>
                                <a href={`${API_BASE}/crl/${serial}/delta`} target="_blank" rel="noopener noreferrer"
                                    className="px-3 py-1 text-xs bg-blue-50 dark:bg-blue-900/50 text-blue-800 dark:text-blue-300 border border-blue-300 dark:border-blue-700 rounded hover:bg-blue-900 transition-colors inline-block">
                                    Download Delta CRL
                                </a>
                            </div>
                        </div>
                    );
                })}
            </div>
        </div>
    );
};

/* ─── LDAP Tab — CA selector + per-CA publisher manager (admin only) ─── */
const LdapTab: React.FC<{ initialCaId?: string }> = ({ initialCaId }) => {
    const [cas, setCas] = useState<any[]>([]);
    const [selectedCa, setSelectedCa] = useState<string>(initialCaId || '');

    useEffect(() => {
        apiGet<any>('/api/v1/admin/authorities')
            .then((data) => {
                const list = Array.isArray(data) ? data : (data.items || data.authorities || []);
                setCas(list);
                // Default to the deep-linked CA, else the first CA so the manager has a target.
                setSelectedCa((cur) => cur || (list[0] ? (list[0].id || list[0].caId) : ''));
            })
            .catch(() => {});
        // eslint-disable-next-line react-hooks/exhaustive-deps
    }, []);

    return (
        <div className="space-y-4">
            <div className="flex items-center gap-3 flex-wrap">
                <label className="text-sm text-gray-700 dark:text-gray-300">Certificate Authority</label>
                <select value={selectedCa} onChange={(e) => setSelectedCa(e.target.value)}
                    className="px-3 py-2 bg-gray-50 dark:bg-gray-900 border border-gray-300 dark:border-gray-700 rounded text-sm text-gray-900 dark:text-white focus:outline-none focus:border-blue-500 min-w-[240px]">
                    <option value="">Select CA...</option>
                    {cas.map((ca) => (
                        <option key={ca.id || ca.caId} value={ca.id || ca.caId}>{ca.name || ca.subjectDN}</option>
                    ))}
                </select>
            </div>
            {selectedCa
                ? <LdapPublisherManager caId={selectedCa} />
                : <div className="text-sm text-gray-600 dark:text-gray-400">Select a CA to manage its LDAP publishers.</div>}
        </div>
    );
};

/* ─── Service URLs Tab — per-CA public base URL → CDP/OCSP/AIA (admin only) ─── */
interface ServiceUrlRow { caCertId: string; name: string; label: string; publicBaseUrl: string }

const ServiceUrlsTab: React.FC = () => {
    const { showToast } = useToast();
    const { requireStepUp } = useStepUp();
    const [rows, setRows] = useState<ServiceUrlRow[]>([]);
    const [loading, setLoading] = useState(true);
    const [saving, setSaving] = useState<string | null>(null);

    const flatten = (list: any[]): any[] => {
        const out: any[] = [];
        for (const ca of list) { out.push(ca); if (ca.children?.length) out.push(...flatten(ca.children)); }
        return out;
    };

    useEffect(() => {
        Promise.all([
            apiGet<any>('/api/v1/admin/authorities/hierarchy').catch(() => []),
            apiGet<any>('/api/v1/admin/ca-service-urls').catch(() => []),
        ]).then(([h, su]) => {
            const flat = flatten(Array.isArray(h) ? h : (h.items || h.authorities || []));
            const list = Array.isArray(su) ? su : (su.items || []);
            const byKey: Record<string, string> = {};
            for (const s of list) { const k = s.caCertificateId || s.caId; if (k) byKey[k] = s.publicBaseUrl || ''; }
            const next = flat
                .map((ca: any): ServiceUrlRow | null => {
                    const caCertId = ca.certificateId || ca.certificate?.certificateId;
                    if (!caCertId) return null;
                    return {
                        caCertId,
                        name: ca.label || ca.name || ca.subjectDN || caCertId,
                        label: ca.label || ca.serialNumber || ca.certificate?.serialNumber || '',
                        publicBaseUrl: byKey[caCertId] ?? (ca.serviceUrls?.publicBaseUrl || ''),
                    };
                })
                .filter((r): r is ServiceUrlRow => r !== null);
            setRows(next);
        }).finally(() => setLoading(false));
    }, []);

    const update = (caCertId: string, value: string) =>
        setRows((prev) => prev.map((r) => (r.caCertId === caCertId ? { ...r, publicBaseUrl: value } : r)));

    const save = async (row: ServiceUrlRow) => {
        setSaving(row.caCertId);
        try {
            // Mutating a CA's public base URL is step-up-gated (update-ca-service-url) — it can
            // silently redirect CDP/AIA/OCSP lookups, so the write requires MFA re-verification.
            await apiPutWithMfa(`/api/v1/admin/ca-service-urls/${row.caCertId}`, { publicBaseUrl: row.publicBaseUrl || null }, requireStepUp, 'update-ca-service-url', row.caCertId);
            showToast('success', 'Public base URL saved');
        } catch (err: any) {
            if (err.message !== 'Step-up MFA cancelled') showToast('error', err.message || 'Failed to save public base URL');
        } finally {
            setSaving(null);
        }
    };

    return (
        <div className="space-y-4">
            <div className="bg-blue-50 dark:bg-blue-900/20 border border-blue-300 dark:border-blue-800 rounded-lg p-3 text-xs text-blue-800 dark:text-blue-300">
                The public base URL drives the <strong>CDP, OCSP, and AIA</strong> endpoints embedded in every certificate a CA
                issues — the program appends <code className="mono">/crl/{'{label}'}</code>, <code className="mono">/ocsp</code>,
                and <code className="mono">/ca/{'{label}'}</code> at issue time. Use plain <strong>HTTP</strong> so relying parties
                can fetch CRLs/OCSP without a TLS chicken-and-egg. Leave empty to issue without CDP/AIA extensions.
            </div>
            {loading && <div className="text-sm text-gray-600 dark:text-gray-400">Loading...</div>}
            {!loading && rows.length === 0 && <div className="text-sm text-gray-600 dark:text-gray-400">No certificate authorities found.</div>}
            {rows.map((row) => (
                <div key={row.caCertId} className="bg-gray-100 dark:bg-gray-800 border border-gray-300 dark:border-gray-700 rounded-lg p-4 space-y-3">
                    <h3 className="text-sm font-semibold text-gray-900 dark:text-white">{row.name}</h3>
                    <div>
                        <label className="block text-xs text-gray-600 dark:text-gray-400 mb-1">Public Base URL</label>
                        <input type="text" value={row.publicBaseUrl} onChange={(e) => update(row.caCertId, e.target.value)}
                            placeholder="http://path2.ca.example.com"
                            className="w-full px-3 py-2 bg-gray-50 dark:bg-gray-900 border border-gray-300 dark:border-gray-700 rounded text-sm text-gray-900 dark:text-white placeholder-gray-400 dark:placeholder-gray-500 focus:outline-none focus:border-blue-500 font-mono" />
                    </div>
                    {row.publicBaseUrl && (
                        <div className="text-xs text-gray-600 dark:text-gray-400 space-y-0.5">
                            <div>CDP: <span className="font-mono">{row.publicBaseUrl}/crl/{row.label}</span></div>
                            <div>OCSP: <span className="font-mono">{row.publicBaseUrl}/ocsp</span></div>
                            <div>CA Issuer: <span className="font-mono">{row.publicBaseUrl}/ca/{row.label}</span></div>
                        </div>
                    )}
                    <button onClick={() => save(row)} disabled={saving === row.caCertId}
                        className="px-4 py-1.5 text-xs font-semibold bg-blue-600 text-white rounded hover:bg-blue-700 disabled:opacity-40 transition-colors">
                        {saving === row.caCertId ? 'Saving...' : 'Save'}
                    </button>
                </div>
            ))}
        </div>
    );
};

/* ─── CA Distribution Page ─── */
const Distribution: React.FC = () => {
    const { hasAnyRole } = useAuth();
    const isAdmin = hasAnyRole(['Administrator']);
    const [searchParams, setSearchParams] = useSearchParams();
    const caIdParam = searchParams.get('caId') || undefined;
    type Tab = 'crl' | 'ldap' | 'serviceurls';
    const requestedTab = searchParams.get('tab');
    const [tab, setTab] = useState<Tab>(
        (requestedTab === 'ldap' || requestedTab === 'serviceurls') && isAdmin ? requestedTab : 'crl');

    const selectTab = (t: Tab) => {
        setTab(t);
        const next = new URLSearchParams(searchParams);
        next.set('tab', t);
        setSearchParams(next, { replace: true });
    };

    const tabs: { key: Tab; label: string }[] = [
        { key: 'crl', label: 'CRL' },
        ...(isAdmin ? [{ key: 'ldap' as const, label: 'LDAP' }, { key: 'serviceurls' as const, label: 'Service URLs' }] : []),
    ];

    return (
        <div className="p-3 sm:p-6 space-y-6">
            <h1 className="text-2xl font-bold text-gray-900 dark:text-white">CA Distribution</h1>

            <div className="flex gap-1 border-b border-gray-300 dark:border-gray-700">
                {tabs.map((t) => (
                    <button key={t.key} onClick={() => selectTab(t.key)}
                        className={`px-4 py-2 text-sm font-medium transition-colors border-b-2 ${tab === t.key
                            ? 'text-blue-800 dark:text-blue-400 border-blue-400'
                            : 'text-gray-600 dark:text-gray-400 border-transparent hover:text-gray-700 dark:hover:text-gray-300'}`}>
                        {t.label}
                    </button>
                ))}
            </div>

            {tab === 'crl' && (
                <div className="space-y-8">
                    <CrlSchedulesSection />
                    <CurrentCrlsSection />
                </div>
            )}
            {tab === 'ldap' && isAdmin && <LdapTab initialCaId={caIdParam} />}
            {tab === 'serviceurls' && isAdmin && <ServiceUrlsTab />}
        </div>
    );
};

export default Distribution;
