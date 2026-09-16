import React, { useState, useEffect } from 'react';
import type { NoticeInput } from '@shared/notifications/notice';
import { InlineNotice } from '@shared/components/InlineNotice';
import { errorNotice } from '@shared-auth/api/notices';
import { useSearchParams } from 'react-router-dom';
import { apiGet, apiPost, apiPostWithMfa, apiPutWithMfa, API_BASE } from '../api/client';
import { useScope } from '../context/ScopeContext';
import { scopeLabel } from '../scope';
import { FieldHint } from '@shared/components/forms';
import { useStepUp } from '../components/StepUpMfaContext';
import { useToast } from '@shared/context/ToastContext';
import { useAuth } from '../context/AuthContext';
import { Capabilities } from '@shared/generated';
import { StatusBadge } from '@shared/components/cards/StatusBadge';
import { DetailField } from '@shared/components/cards/DetailField';
import ConfirmModal from '../components/ConfirmModal';
import { DataTable, DataTableColumn, DataTableBulkAction } from '@shared/components/DataTable';
import { LdapPublisherManager } from './LdapPublishers';
import { StepUpOps } from '@shared/generated';

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
        <DetailField label="Update interval (cron)" value={s.updateInterval || s.cronExpression} mono />
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
    const [error, setError] = useState<NoticeInput | null>(null);
    const [showCreate, setShowCreate] = useState(false);
    const [creating, setCreating] = useState(false);
    const [cas, setCas] = useState<any[]>([]);
    // The CA list is what the scope filter and the CA selector are built from; when it cannot be
    // loaded the page must say so rather than showing an empty selector and an empty table.
    const [casError, setCasError] = useState<string | null>(null);
    // Bulk delete confirm
    const [confirmBulk, setConfirmBulk] = useState<any[] | null>(null);
    const [confirmLoading, setConfirmLoading] = useState(false);

    const [form, setForm] = useState({
        name: '',
        cronExpression: '',
        caId: '',
        overlapPeriod: '',
    });

    // CRL schedules key on the CA's certificate; under a CA scope keep the scoped CA's only.
    const { caId: scopeCaId, scope } = useScope();
    const scopedCa = scopeCaId ? cas.find((c) => (c.id || c.caId) === scopeCaId) : null;
    const visibleSchedules = scopeCaId
        ? schedules.filter((sch) => {
            const key = sch.caCertificateId || sch.caId;
            return !!scopedCa && (key === scopedCa.certificateId || key === scopedCa.id);
        })
        : schedules;

    const load = () => {
        setLoading(true);
        setError(null);
        apiGet<any>('/api/v1/admin/crl-schedules')
            .then((data) => setSchedules(Array.isArray(data) ? data : (data.items || data.schedules || [])))
            .catch((err) => setError(errorNotice(err, 'The request failed.')))
            .finally(() => setLoading(false));
    };

    useEffect(() => {
        load();
        apiGet<any>('/api/v1/admin/authorities')
            .then((data) => { setCas(Array.isArray(data) ? data : (data.items || data.authorities || [])); setCasError(null); })
            .catch((err) => setCasError(err.message || 'request failed'));
    }, []);

    const handleCreate = async () => {
        // The form's field names are not the API's. CreateCrlConfigurationRequest declares
        // Name / UpdateInterval / OverlapPeriod / CaCertificateId, so posting the form object
        // verbatim sent `cronExpression` and `caId` to fields that do not exist: UpdateInterval
        // arrived empty (and is [Required]) and CaCertificateId arrived as Guid.Empty. The form
        // could never succeed, whatever was typed into it.
        const overlapPeriod = toTimeSpan(form.overlapPeriod);
        if (overlapPeriod === null) {
            showToast('error', "Overlap period must look like '1h', '30m', '1h30m', or 'hh:mm:ss'.");
            return;
        }
        setCreating(true);
        try {
            await apiPostWithMfa('/api/v1/admin/crl-schedules', {
                name: form.name,
                updateInterval: form.cronExpression,
                caCertificateId: form.caId,
                overlapPeriod,
            }, requireStepUp, StepUpOps.CreateCrlSchedule);
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
            const res: any = await apiPostWithMfa('/api/v1/admin/crl-schedules/bulk', { actions }, requireStepUp, StepUpOps.BulkCrlSchedule);
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
            const res: any = await apiPostWithMfa('/api/v1/admin/crl-schedules/bulk', { actions }, requireStepUp, StepUpOps.BulkCrlSchedule);
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
                            <label className="block text-xs text-gray-600 dark:text-gray-400 mb-1">Update interval (cron)</label>
                            <input type="text" placeholder="e.g. 0 */6 * * *" value={form.cronExpression} onChange={(e) => setForm({ ...form, cronExpression: e.target.value })}
                                className="w-full px-3 py-2 bg-gray-50 dark:bg-gray-900 border border-gray-300 dark:border-gray-700 rounded text-sm text-gray-900 dark:text-white focus:outline-none focus:border-blue-500" />
                            <FieldHint>A five-field cron expression saying when a fresh CRL is signed and published.</FieldHint>
                        </div>
                        <div>
                            <label className="block text-xs text-gray-600 dark:text-gray-400 mb-1">Certificate Authority</label>
                            <select value={form.caId} onChange={(e) => setForm({ ...form, caId: e.target.value })}
                                className="w-full px-3 py-2 bg-gray-50 dark:bg-gray-900 border border-gray-300 dark:border-gray-700 rounded text-sm text-gray-900 dark:text-white focus:outline-none focus:border-blue-500">
                                <option value="">Select CA...</option>
                                {/* value is the CA's CERTIFICATE id — CrlConfiguration keys on
                                    CaCertificateId, not on the authority's own id. A CA that has
                                    not issued its certificate yet cannot carry a CRL schedule. */}
                                {cas.filter((ca) => ca.certificateId).map((ca) => (
                                    <option key={ca.certificateId} value={ca.certificateId}>{ca.name || ca.subjectDN}</option>
                                ))}
                            </select>
                            {casError && <FieldHint tone="warn">Unavailable: could not load the CA list ({casError}). Reload the page to try again.</FieldHint>}
                        </div>
                        <div>
                            <label className="block text-xs text-gray-600 dark:text-gray-400 mb-1">Overlap Period</label>
                            <input type="text" placeholder="e.g. 1h, 30m, 1h30m" value={form.overlapPeriod} onChange={(e) => setForm({ ...form, overlapPeriod: e.target.value })}
                                className="w-full px-3 py-2 bg-gray-50 dark:bg-gray-900 border border-gray-300 dark:border-gray-700 rounded text-sm text-gray-900 dark:text-white focus:outline-none focus:border-blue-500" />
                            <FieldHint>{OVERLAP_HINT}</FieldHint>
                        </div>
                    </div>
                    <button onClick={handleCreate} disabled={creating || !form.name || !form.cronExpression || !form.caId}
                        className="px-4 py-2 text-sm bg-blue-600 text-white rounded hover:bg-blue-700 disabled:opacity-50 transition-colors">
                        {creating ? 'Creating...' : 'Create'}
                    </button>
                </div>
            )}

            {scopeCaId && casError && (
                <div className="text-xs text-red-800 dark:text-red-400" role="status">
                    Unavailable: could not load the CA list ({casError}), so the schedules for {scopeLabel(scope)} cannot be picked out. The table below is not a statement that there are none.
                </div>
            )}

            <DataTable<any>
                tableId="distribution-crl-schedules"
                title="CRL Schedules"
                rows={visibleSchedules}
                rowKey={crlId}
                loading={loading}
                error={error}
                empty={scopeCaId ? `No CRL schedules in ${scopeLabel(scope)}. Change the scope in the sidebar to see others.` : 'No CRL schedules configured'}
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
    const [error, setError] = useState<NoticeInput | null>(null);

    useEffect(() => {
        apiGet<any>('/api/v1/admin/authorities')
            .then((data) => setCas(Array.isArray(data) ? data : (data.items || data.authorities || [])))
            .catch((err) => setError(errorNotice(err, 'The request failed.')))
            .finally(() => setLoading(false));
    }, []);

    return (
        <div className="space-y-4">
            <h2 className="text-lg font-semibold text-gray-900 dark:text-white">Current CRLs</h2>

            {loading && <div className="p-4 text-sm text-gray-600 dark:text-gray-400">Loading...</div>}
            {error && <InlineNotice notice={error} />}
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
    const [casError, setCasError] = useState<string | null>(null);
    const [selectedCa, setSelectedCa] = useState<string>(initialCaId || '');

    useEffect(() => {
        apiGet<any>('/api/v1/admin/authorities')
            .then((data) => {
                const list = Array.isArray(data) ? data : (data.items || data.authorities || []);
                setCas(list);
                setCasError(null);
                // Default to the deep-linked CA, else the first CA so the manager has a target.
                setSelectedCa((cur) => cur || (list[0] ? (list[0].id || list[0].caId) : ''));
            })
            .catch((err) => setCasError(err.message || 'request failed'));
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
            {casError && (
                <div className="text-sm text-red-800 dark:text-red-400" role="status">Unavailable: could not load the CA list ({casError}). The selector above is empty because of that, not because there are no CAs.</div>
            )}
            {selectedCa
                ? <LdapPublisherManager caId={selectedCa} />
                : !casError && <div className="text-sm text-gray-600 dark:text-gray-400">Select a CA to manage its LDAP publishers.</div>}
        </div>
    );
};

/* ─── Service URLs Tab — per-CA public base URL → CDP/OCSP/AIA (admin only) ─── */
interface ServiceUrlRow { caCertId: string; name: string; label: string; publicBaseUrl: string }

const ServiceUrlsTab: React.FC = () => {
    const { showToast } = useToast();
    const { requireStepUp } = useStepUp();
    const { inScope, caId: scopeCaId, scope } = useScope();
    const [rows, setRows] = useState<ServiceUrlRow[]>([]);
    const [loading, setLoading] = useState(true);
    // Each source is tracked separately: without the hierarchy there are no rows to show, and
    // without the saved URLs every row would silently present as "unset" and invite a save that
    // clobbers a real value.
    const [hierarchyError, setHierarchyError] = useState<string | null>(null);
    const [urlsError, setUrlsError] = useState<string | null>(null);
    const [saving, setSaving] = useState<string | null>(null);

    const flatten = (list: any[]): any[] => {
        const out: any[] = [];
        for (const ca of list) { out.push(ca); if (ca.children?.length) out.push(...flatten(ca.children)); }
        return out;
    };

    useEffect(() => {
        setHierarchyError(null);
        setUrlsError(null);
        Promise.all([
            apiGet<any>('/api/v1/admin/authorities/hierarchy').catch((err) => { setHierarchyError(err.message || 'request failed'); return []; }),
            apiGet<any>('/api/v1/admin/ca-service-urls').catch((err) => { setUrlsError(err.message || 'request failed'); return []; }),
        ]).then(([h, su]) => {
            const flat = flatten(Array.isArray(h) ? h : (h.items || h.authorities || []))
                .filter((ca: any) => inScope(ca.id || ca.caId));
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
    }, [scopeCaId]); // eslint-disable-line react-hooks/exhaustive-deps

    const update = (caCertId: string, value: string) =>
        setRows((prev) => prev.map((r) => (r.caCertId === caCertId ? { ...r, publicBaseUrl: value } : r)));

    const save = async (row: ServiceUrlRow) => {
        setSaving(row.caCertId);
        try {
            // Mutating a CA's public base URL is step-up-gated (update-ca-service-url) — it can
            // silently redirect CDP/AIA/OCSP lookups, so the write requires MFA re-verification.
            await apiPutWithMfa(`/api/v1/admin/ca-service-urls/${row.caCertId}`, { publicBaseUrl: row.publicBaseUrl || null }, requireStepUp, StepUpOps.UpdateCaServiceUrl, row.caCertId);
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
            {hierarchyError && (
                <div className="text-sm text-red-800 dark:text-red-400" role="status">Unavailable: could not load the CA hierarchy ({hierarchyError}). Nothing is listed because of that, not because there are no CAs.</div>
            )}
            {urlsError && (
                <div className="text-sm text-red-800 dark:text-red-400" role="status">Unavailable: could not load the saved public base URLs ({urlsError}). The fields below may show as empty even where a URL is set; saving now would overwrite it. Reload before editing.</div>
            )}
            {!loading && !hierarchyError && rows.length === 0 && (
                <div className="text-sm text-gray-600 dark:text-gray-400">
                    {scopeCaId ? `No certificate authorities in ${scopeLabel(scope)}. Change the scope in the sidebar to see others.` : 'No certificate authorities found.'}
                </div>
            )}
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

/**
 * What the overlap period is for, worded once and shown on both the create form here and the
 * edit form on `CrlScheduleDetail`, so the two never drift apart again.
 */
export const OVERLAP_HINT =
    "How long the outgoing CRL stays valid after its replacement is published: the CRL's nextUpdate is set to the update interval plus this period. " +
    'Relying parties keep using a cached CRL until its nextUpdate, so the overlap covers publication delay and clock skew. ' +
    'Too short and a client whose cached CRL has expired before the new one reached it has no valid CRL at all, and validation fails. ' +
    "Accepts 1h, 30m, 1h30m, 90s, a bare number of minutes, or hh:mm:ss.";

/**
 * Converts a friendly overlap duration into the `hh:mm:ss` form System.Text.Json binds to a
 * TimeSpan. Accepts `90s`, `30m`, `1h`, `1h30m`, a bare number (minutes), or an already
 * well-formed `hh:mm:ss` (with an optional `d.` day prefix, which is how a TimeSpan of a day or
 * more comes back from the server). Empty means no overlap. Returns null when the text is
 * unparseable, so the caller can say so instead of posting something the API rejects with a 400.
 *
 * Exported so the edit form on `CrlScheduleDetail` normalises exactly what the create form does.
 */
export function toTimeSpan(text: string): string | null {
    const trimmed = text.trim();
    if (trimmed === '') return '00:00:00';
    if (/^(?:\d+\.)?\d{1,3}:[0-5]?\d:[0-5]?\d$/.test(trimmed)) return trimmed;

    let seconds: number;
    if (/^\d+$/.test(trimmed)) {
        seconds = parseInt(trimmed, 10) * 60;
    } else {
        const parts = trimmed.match(/^(?:(\d+)h)?(?:(\d+)m)?(?:(\d+)s)?$/i);
        if (!parts || (!parts[1] && !parts[2] && !parts[3])) return null;
        seconds = Number(parts[1] ?? 0) * 3600 + Number(parts[2] ?? 0) * 60 + Number(parts[3] ?? 0);
    }

    const pad = (n: number) => String(n).padStart(2, '0');
    return `${pad(Math.floor(seconds / 3600))}:${pad(Math.floor((seconds % 3600) / 60))}:${pad(seconds % 60)}`;
}

/* ─── CA Distribution Page ─── */
const Distribution: React.FC = () => {
    const { can } = useAuth();
    const isAdmin = can(Capabilities.SystemManage);
    const [searchParams, setSearchParams] = useSearchParams();
    const { caId: scopeCaId } = useScope();
    const caIdParam = searchParams.get('caId') || scopeCaId || undefined;
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
            {tab === 'ldap' && isAdmin && <LdapTab key={caIdParam ?? 'all'} initialCaId={caIdParam} />}
            {tab === 'serviceurls' && isAdmin && <ServiceUrlsTab />}
        </div>
    );
};

export default Distribution;
