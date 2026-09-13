import React, { useState, useEffect, useCallback } from 'react';
import { apiGet, apiPost } from '../api/client';
import { useToast } from '@shared/context/ToastContext';
import { StatusBadge } from '@shared/components/cards/StatusBadge';
import { DetailField } from '@shared/components/cards/DetailField';
import { SystemQuorumCard } from '../components/UserQuorumPanel';
import { DataTable, DataTableColumn } from '@shared/components/DataTable';
import { labelClass as labelCls } from '@shared/components/forms';
import type { ValidityCeilingBehavior } from '@shared/generated';

/* ── shared helpers (re-used by TenantDetail) ─────────────────────────────── */
export function formatDate(d: string | null) {
    if (!d) return '-';
    return new Date(d).toLocaleDateString('en-US', { year: 'numeric', month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' });
}
export const usagePercent = (used: number, max: number) => (!max || max <= 0 ? 0 : Math.min(100, Math.round((used / max) * 100)));
export const usageBarColor = (p: number) => (p > 80 ? 'bg-red-500' : p >= 60 ? 'bg-yellow-500' : 'bg-green-500');
export const usageTextColor = (p: number) => (p > 80 ? 'text-red-800 dark:text-red-400' : p >= 60 ? 'text-yellow-800 dark:text-yellow-400' : 'text-green-800 dark:text-green-400');
// 0 = unlimited by convention across tenant and CA quotas.
export const fmtLimit = (used: number, max: number) => (max > 0 ? `${used} / ${max}` : `${used} / ∞`);

export const numInput = 'w-full px-3 py-2 bg-gray-50 dark:bg-gray-900 border border-gray-300 dark:border-gray-700 rounded text-sm text-gray-900 dark:text-white focus:outline-none focus:border-blue-500';

export interface Quota {
    groupId: string | null;
    maxCertificates: number;
    maxPendingRequests: number;
    issuedCount: number;
    pendingCount: number;
    remainingCount: number;
    usagePercent: number;
    isExceeded: boolean;
}
export interface Ca {
    id: string;
    name: string;
    label?: string;
    type: string;
    isEnabled: boolean;
    isSshCa: boolean;
    quota: Quota | null;
}
export interface Tenant {
    id: string;
    name: string;
    slug?: string;
    description?: string;
    isEnabled: boolean;
    isSystemTenant: boolean;
    createdAt: string;
    maxCertificateAuthorities: number;
    maxCertificatesTotal: number;
    maxUsers: number;
    maxValidityDays: number;
    validityCeilingBehavior: ValidityCeilingBehavior;
    requireKeyCeremony: boolean;
    ceremonyRequiredApprovals: number;
    caCount: number;
    userCount: number;
    issuedCertificates: number;
    certificateAuthorities: Ca[];
}

/* ── per-CA quota row (used in the tenant detail Per-CA Issuance Quotas table) ──
   Fully controlled: the parent owns the edited values and the (page-level) save. `readOnly` shows
   values; otherwise the maxCerts/maxPending inputs are bound to `value`/`onChange`. */
export const CaQuotaRow: React.FC<{
    ca: Ca;
    readOnly?: boolean;
    value?: { maxCertificates: number; maxPendingRequests: number };
    onChange?: (next: { maxCertificates: number; maxPendingRequests: number }) => void;
}> = ({ ca, readOnly, value, onChange }) => {
    const q = ca.quota;
    const issued = q?.issuedCount ?? 0;
    const pending = q?.pendingCount ?? 0;
    const maxCerts = value?.maxCertificates ?? (q?.maxCertificates ?? 0);
    const maxPending = value?.maxPendingRequests ?? (q?.maxPendingRequests ?? 0);
    const liveMax = readOnly ? (q?.maxCertificates ?? 0) : maxCerts;
    const pct = usagePercent(issued, liveMax);

    return (
        <div className="px-3 py-2 grid grid-cols-[1fr_70px_70px_70px_150px_70px_70px] gap-2 items-center border-b border-gray-200 dark:border-gray-700/60 last:border-b-0 text-xs">
            <div className="min-w-0">
                <span className="text-gray-900 dark:text-white truncate block">{ca.label || ca.name}</span>
                <span className="text-[10px] text-gray-500">{ca.type}{ca.isSshCa ? ' · SSH' : ''}{!ca.isEnabled ? ' · disabled' : ''}</span>
            </div>

            {!q ? (
                <span className="col-span-6 text-gray-500 italic">{ca.isSshCa ? 'Quota not applicable to SSH CA' : 'No admin group / quota'}</span>
            ) : readOnly ? (
                <>
                    <span className="text-gray-600 dark:text-gray-400">{q.maxCertificates || 'Unlimited'}</span>
                    <span className="text-gray-600 dark:text-gray-400">{issued}</span>
                    <span className="text-gray-600 dark:text-gray-400">{q.maxCertificates ? q.remainingCount : '-'}</span>
                    <div className="flex items-center gap-1">
                        <div className="flex-1 bg-gray-200 dark:bg-gray-700 rounded-full h-2 overflow-hidden">
                            <div className={`h-full rounded-full ${usageBarColor(pct)}`} style={{ width: `${pct}%` }} />
                        </div>
                        <span className={`font-mono w-9 text-right ${usageTextColor(pct)}`}>{q.maxCertificates ? `${pct}%` : '-'}</span>
                    </div>
                    <span className="text-gray-600 dark:text-gray-400">{pending}</span>
                    <span className="text-gray-600 dark:text-gray-400">{q.maxPendingRequests || '-'}</span>
                </>
            ) : (
                <>
                    <input inputMode="numeric" value={maxCerts}
                        onChange={(e) => onChange?.({ maxCertificates: parseInt(e.target.value.replace(/\D/g, '') || '0', 10), maxPendingRequests: maxPending })}
                        className="px-2 py-1 bg-gray-50 dark:bg-gray-900 border border-gray-300 dark:border-gray-700 rounded w-full text-gray-900 dark:text-white" />
                    <span className="text-gray-600 dark:text-gray-400">{issued}</span>
                    <span className="text-gray-600 dark:text-gray-400">{Math.max(0, maxCerts - issued)}</span>
                    <div className="flex items-center gap-1">
                        <div className="flex-1 bg-gray-200 dark:bg-gray-700 rounded-full h-2 overflow-hidden">
                            <div className={`h-full rounded-full ${usageBarColor(pct)}`} style={{ width: `${pct}%` }} />
                        </div>
                        <span className={`font-mono w-9 text-right ${usageTextColor(pct)}`}>{maxCerts ? `${pct}%` : '-'}</span>
                    </div>
                    <span className="text-gray-600 dark:text-gray-400">{pending}</span>
                    <input inputMode="numeric" value={maxPending}
                        onChange={(e) => onChange?.({ maxCertificates: maxCerts, maxPendingRequests: parseInt(e.target.value.replace(/\D/g, '') || '0', 10) })}
                        className="px-2 py-1 bg-gray-50 dark:bg-gray-900 border border-gray-300 dark:border-gray-700 rounded w-full text-gray-900 dark:text-white" />
                </>
            )}
        </div>
    );
};

/* ── page: tenants list (DataTable) + create + quorum panel ────────────────── */
const TenantsAndQuotas: React.FC = () => {
    const { showToast } = useToast();
    const [tenants, setTenants] = useState<Tenant[]>([]);
    const [totals, setTotals] = useState<{ totalTenants: number; totalCAs: number; casAtLimit: number; casNearLimit: number } | null>(null);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState<string | null>(null);

    // create-tenant form
    const [showCreate, setShowCreate] = useState(false);
    const [createForm, setCreateForm] = useState({ name: '', description: '', maxCAs: 0, maxCertificates: 0, maxUsers: 0, maxValidityDays: 0, validityCeilingBehavior: 'Shorten' as ValidityCeilingBehavior });
    const [creating, setCreating] = useState(false);

    const load = useCallback(() => {
        setLoading(true);
        apiGet<any>('/api/v1/admin/quotas/by-tenant')
            .then((data) => { setTenants(data.tenants || []); setTotals(data.totals || null); setError(null); })
            .catch((err) => setError(err.message || 'Failed to load'))
            .finally(() => setLoading(false));
    }, []);

    useEffect(() => { load(); }, [load]);

    const handleCreate = async (e: React.FormEvent) => {
        e.preventDefault();
        setCreating(true);
        try {
            await apiPost('/api/v1/admin/tenants', {
                name: createForm.name,
                description: createForm.description,
                maxCertificateAuthorities: createForm.maxCAs,
                maxCertificatesTotal: createForm.maxCertificates,
                maxUsers: createForm.maxUsers,
                maxValidityDays: createForm.maxValidityDays,
                validityCeilingBehavior: createForm.validityCeilingBehavior,
            });
            setShowCreate(false);
            setCreateForm({ name: '', description: '', maxCAs: 0, maxCertificates: 0, maxUsers: 0, maxValidityDays: 0, validityCeilingBehavior: 'Shorten' });
            load();
        } catch (err: any) {
            showToast('error', err.message || 'Failed to create tenant');
        } finally {
            setCreating(false);
        }
    };

    const columns: DataTableColumn<Tenant>[] = [
        { key: 'status', header: 'Status', defaultWidth: 110, truncate: false, exportValue: (t) => (t.isEnabled !== false ? 'Enabled' : 'Disabled'), render: (t) => <StatusBadge status={t.isEnabled !== false ? 'active' : 'disabled'} label={t.isEnabled !== false ? 'Enabled' : 'Disabled'} /> },
        {
            key: 'name', header: 'Name', defaultWidth: 240, minWidth: 140, truncate: false,
            exportValue: (t) => t.name + (t.isSystemTenant ? ' (system)' : ''),
            render: (t) => (
                <span className="text-gray-900 dark:text-white font-medium truncate">
                    {t.name}{t.isSystemTenant && <span className="ml-2 text-[10px] text-gray-500">(system)</span>}
                </span>
            ),
        },
        { key: 'cas', header: 'CAs', defaultWidth: 100, headerTitle: 'CAs / max', exportValue: (t) => fmtLimit(t.caCount, t.maxCertificateAuthorities), render: (t) => <span className="text-xs text-gray-600 dark:text-gray-400">{fmtLimit(t.caCount, t.maxCertificateAuthorities)}</span> },
        { key: 'users', header: 'Users', defaultWidth: 100, headerTitle: 'Users / max', exportValue: (t) => fmtLimit(t.userCount, t.maxUsers), render: (t) => <span className="text-xs text-gray-600 dark:text-gray-400">{fmtLimit(t.userCount, t.maxUsers)}</span> },
        { key: 'certs', header: 'Certs', defaultWidth: 120, headerTitle: 'Active certs / max', exportValue: (t) => fmtLimit(t.issuedCertificates, t.maxCertificatesTotal), render: (t) => <span className="text-xs text-gray-600 dark:text-gray-400">{fmtLimit(t.issuedCertificates, t.maxCertificatesTotal)}</span> },
        { key: 'created', header: 'Created', defaultWidth: 160, exportValue: (t) => formatDate(t.createdAt), render: (t) => <span className="text-xs text-gray-600 dark:text-gray-400">{formatDate(t.createdAt)}</span> },
    ];

    const drawer = (t: Tenant) => (
        <div className="text-sm">
            <DetailField label="Name" value={t.name} />
            <DetailField label="Description" value={t.description || '-'} />
            <DetailField label="System Tenant" value={t.isSystemTenant ? 'Yes' : 'No'} />
            <DetailField label="Status" value={t.isEnabled !== false ? 'Enabled' : 'Disabled'} />
            <DetailField label="CAs" value={fmtLimit(t.caCount, t.maxCertificateAuthorities)} />
            <DetailField label="Users" value={fmtLimit(t.userCount, t.maxUsers)} />
            <DetailField label="Active Certs" value={fmtLimit(t.issuedCertificates, t.maxCertificatesTotal)} />
            <DetailField label="Key Ceremony" value={t.requireKeyCeremony ? `Yes (${t.ceremonyRequiredApprovals} approvals)` : 'No'} />
            <DetailField label="Created" value={formatDate(t.createdAt)} />
            <p className="text-[11px] text-gray-500 pt-3">Open the full page to edit ceilings, toggle status, or set per-CA quotas.</p>
        </div>
    );

    return (
        <div className="p-3 sm:p-6 space-y-4 sm:space-y-6">
            <div className="flex items-start justify-between flex-wrap gap-3">
                <div>
                    <h1 className="text-2xl font-bold text-gray-900 dark:text-white">Tenants &amp; Quotas</h1>
                    <p className="text-sm text-gray-600 dark:text-gray-400 mt-1">Tenant rows are org-level ceilings (max CAs / certs / users). Open a tenant to edit ceilings and set per-CA issuance quotas.</p>
                </div>
                <button onClick={() => setShowCreate(!showCreate)} className="px-4 py-2 text-sm bg-blue-600 text-white rounded hover:bg-blue-700 transition-colors">
                    {showCreate ? 'Cancel' : 'Create Tenant'}
                </button>
            </div>

            {/* summary tiles */}
            {totals && (
                <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
                    {[
                        { label: 'Tenants', value: totals.totalTenants, cls: 'text-gray-900 dark:text-white' },
                        { label: 'Total CAs', value: totals.totalCAs, cls: 'text-gray-900 dark:text-white' },
                        { label: 'CAs at Limit', value: totals.casAtLimit, cls: 'text-red-800 dark:text-red-400' },
                        { label: 'CAs Near Limit (>80%)', value: totals.casNearLimit, cls: 'text-yellow-800 dark:text-yellow-400' },
                    ].map((t) => (
                        <div key={t.label} className="bg-gray-100 dark:bg-gray-800 border border-gray-300 dark:border-gray-700 rounded-lg p-4">
                            <div className="text-xs text-gray-600 uppercase tracking-wider">{t.label}</div>
                            <div className={`text-2xl font-bold mt-1 ${t.cls}`}>{t.value}</div>
                        </div>
                    ))}
                </div>
            )}

            {showCreate && (
                <form onSubmit={handleCreate} className="bg-gray-100 dark:bg-gray-800 border border-gray-300 dark:border-gray-700 rounded-lg p-4 space-y-3">
                    <h3 className="text-sm font-semibold text-gray-900 dark:text-white">New Tenant</h3>
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                        <input type="text" placeholder="Tenant Name" required value={createForm.name}
                            onChange={(e) => setCreateForm({ ...createForm, name: e.target.value })}
                            className="px-3 py-2 bg-gray-50 dark:bg-gray-900 border border-gray-300 dark:border-gray-700 rounded text-sm text-gray-900 dark:text-white placeholder-gray-400 dark:placeholder-gray-500 focus:outline-none focus:border-blue-500" />
                        <input type="text" placeholder="Description" value={createForm.description}
                            onChange={(e) => setCreateForm({ ...createForm, description: e.target.value })}
                            className="px-3 py-2 bg-gray-50 dark:bg-gray-900 border border-gray-300 dark:border-gray-700 rounded text-sm text-gray-900 dark:text-white placeholder-gray-400 dark:placeholder-gray-500 focus:outline-none focus:border-blue-500" />
                        <div><label className={labelCls}>Max CAs</label>
                            <input inputMode="numeric" value={createForm.maxCAs} onChange={(e) => setCreateForm({ ...createForm, maxCAs: parseInt(e.target.value.replace(/\D/g, '') || '0', 10) })} className={numInput} /></div>
                        <div><label className={labelCls}>Max Certificates</label>
                            <input inputMode="numeric" value={createForm.maxCertificates} onChange={(e) => setCreateForm({ ...createForm, maxCertificates: parseInt(e.target.value.replace(/\D/g, '') || '0', 10) })} className={numInput} /></div>
                        <div><label className={labelCls}>Max Users</label>
                            <input inputMode="numeric" value={createForm.maxUsers} onChange={(e) => setCreateForm({ ...createForm, maxUsers: parseInt(e.target.value.replace(/\D/g, '') || '0', 10) })} className={numInput} /></div>
                        <div><label className={labelCls}>Max Cert Validity (days, 0 = unlimited)</label>
                            <input inputMode="numeric" value={createForm.maxValidityDays} onChange={(e) => setCreateForm({ ...createForm, maxValidityDays: parseInt(e.target.value.replace(/[^0-9]/g, '') || '0', 10) })} className={numInput} /></div>
                        <div><label className={labelCls}>Over the ceiling</label>
                            <select value={createForm.validityCeilingBehavior}
                                onChange={(e) => setCreateForm({ ...createForm, validityCeilingBehavior: e.target.value as ValidityCeilingBehavior })}
                                className={numInput}>
                                <option value="Shorten">Shorten to the ceiling</option>
                                <option value="Refuse">Refuse the request</option>
                            </select>
                            <p className="text-[11px] text-gray-500 dark:text-gray-500 mt-1">Refuse applies to admin issuance only; ACME/EST/SCEP/CMP enrollments and automatic renewals always shorten.</p></div>
                    </div>
                    <button type="submit" disabled={creating} className="px-4 py-2 text-sm bg-green-600 text-white rounded hover:bg-green-700 disabled:opacity-50">{creating ? 'Creating…' : 'Create'}</button>
                </form>
            )}

            <DataTable<Tenant>
                tableId="tenants"
                title="All Tenants"
                rows={tenants}
                rowKey={(t) => t.id}
                loading={loading}
                error={error}
                empty="No tenants found"
                columns={columns}
                selectable
                exportFileName="tenants"
                renderDrawer={drawer}
                drawerTitle={(t) => t.name}
                detailPath={(t) => `/tenants/${t.id}`}
            />

            {/* System-scope controlled-user approval quorum — tenant/CA scopes live on each tenant's page. */}
            <SystemQuorumCard />
        </div>
    );
};

export default TenantsAndQuotas;
