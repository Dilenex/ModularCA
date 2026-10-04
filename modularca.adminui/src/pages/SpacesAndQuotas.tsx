import React, { useState, useEffect, useCallback } from 'react';
import type { NoticeInput } from '@shared/notifications/notice';
import { errorNotice } from '@shared-auth/api/notices';
import { apiGet, apiPost } from '../api/client';
import { useToast } from '@shared/context/ToastContext';
import { StatusBadge } from '@shared/components/cards/StatusBadge';
import { DetailField } from '@shared/components/cards/DetailField';
import { SystemQuorumCard } from '../components/UserQuorumPanel';
import KerberosRealmsPanel from '../components/KerberosRealmsPanel';
import { DataTable, DataTableColumn } from '@shared/components/DataTable';
import { labelClass as labelCls } from '@shared/components/forms';
import type { ValidityCeilingBehavior } from '@shared/generated';
import { SPACE_INTERSTITIAL, recommendationBeforeCreate, recommendationFromResponse } from './spaceCreation';
import { INSTANCE_REALMS_ANCHOR } from './msaeRefusals';
import { useScrollToHash } from '../hooks/useScrollToHash';

/** The recommendation the server returned for the last space created in this page load. */
let lastServerRecommendation: string | null = null;

/* ── shared helpers (re-used by SpaceDetail) ─────────────────────────────── */
export function formatDate(d: string | null) {
    if (!d) return '-';
    return new Date(d).toLocaleDateString('en-US', { year: 'numeric', month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' });
}
export const usagePercent = (used: number, max: number) => (!max || max <= 0 ? 0 : Math.min(100, Math.round((used / max) * 100)));
export const usageBarColor = (p: number) => (p > 80 ? 'bg-red-500' : p >= 60 ? 'bg-yellow-500' : 'bg-green-500');
export const usageTextColor = (p: number) => (p > 80 ? 'text-red-800 dark:text-red-400' : p >= 60 ? 'text-yellow-800 dark:text-yellow-400' : 'text-green-800 dark:text-green-400');
// 0 = unlimited by convention across space and CA quotas.

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
export interface Space {
    id: string;
    name: string;
    slug?: string;
    description?: string;
    isEnabled: boolean;
    createdAt: string;
    maxValidityDays: number;
    validityCeilingBehavior: ValidityCeilingBehavior;
    requireKeyCeremony: boolean;
    ceremonyRequiredApprovals: number;
    caCount: number;
    userCount: number;
    issuedCertificates: number;
    certificateAuthorities: Ca[];
}
/** The instance's own CA policy and its CAs (no space: the system signing CA, SSH CAs). */
export interface InstanceSummary {
    requireKeyCeremony: boolean;
    ceremonyRequiredApprovals: number;
    maxValidityDays: number;
    validityCeilingBehavior: ValidityCeilingBehavior;
    caCount: number;
    userCount: number;
    issuedCertificates: number;
    certificateAuthorities: Ca[];
}

/* ── per-CA quota row (used in the space detail Per-CA Issuance Quotas table) ──
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

/* ── page: spaces list (DataTable) + create + quorum panel ────────────────── */
const SpacesAndQuotas: React.FC = () => {
    const { showToast } = useToast();
    const [spaces, setSpaces] = useState<Space[]>([]);
    const [instance, setInstance] = useState<InstanceSummary | null>(null);
    const [totals, setTotals] = useState<{ totalSpaces: number; totalCAs: number; casAtLimit: number; casNearLimit: number } | null>(null);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState<NoticeInput | null>(null);

    // create-space form
    const [showCreate, setShowCreate] = useState(false);
    const [createForm, setCreateForm] = useState({ name: '', description: '', maxValidityDays: 0, validityCeilingBehavior: 'Shorten' as ValidityCeilingBehavior });
    const [creating, setCreating] = useState(false);
    // The licence recommendation the server returned for the space just created.
    const [createdRecommendation, setCreatedRecommendation] = useState<string | null>(null);
    const [serverRecommendation, setServerRecommendation] = useState<string | null>(lastServerRecommendation);

    const load = useCallback(() => {
        setLoading(true);
        apiGet<any>('/api/v1/admin/quotas/by-space')
            .then((data) => {
                setSpaces(data.spaces || []);
                setInstance(data.instance || null);
                setTotals(data.totals || null);
                setError(null);
            })
            .catch((err) => setError(errorNotice(err, 'Failed to load')))
            .finally(() => setLoading(false));
    }, []);

    useEffect(() => { load(); }, [load]);
    useScrollToHash(!!instance);

    const recommendation = recommendationBeforeCreate(spaces.length, serverRecommendation);

    const handleCreate = async (e: React.FormEvent) => {
        e.preventDefault();
        setCreating(true);
        try {
            const created = await apiPost<any>('/api/v1/admin/spaces', {
                name: createForm.name,
                description: createForm.description,
                maxValidityDays: createForm.maxValidityDays,
                validityCeilingBehavior: createForm.validityCeilingBehavior,
            });
            const said = recommendationFromResponse(created);
            lastServerRecommendation = said;
            setServerRecommendation(said);
            setCreatedRecommendation(said);
            showToast('success', `Space '${createForm.name}' created`);
            setShowCreate(false);
            setCreateForm({ name: '', description: '', maxValidityDays: 0, validityCeilingBehavior: 'Shorten' });
            load();
        } catch (err: any) {
            showToast('error', err.message || 'Failed to create space');
        } finally {
            setCreating(false);
        }
    };

    const columns: DataTableColumn<Space>[] = [
        { key: 'status', header: 'Status', defaultWidth: 110, truncate: false, exportValue: (t) => (t.isEnabled !== false ? 'Enabled' : 'Disabled'), render: (t) => <StatusBadge status={t.isEnabled !== false ? 'active' : 'disabled'} label={t.isEnabled !== false ? 'Enabled' : 'Disabled'} /> },
        {
            key: 'name', header: 'Name', defaultWidth: 240, minWidth: 140, truncate: false,
            exportValue: (t) => t.name,
            render: (t) => <span className="text-gray-900 dark:text-white font-medium truncate">{t.name}</span>,
        },
        { key: 'cas', header: 'CAs', defaultWidth: 100, exportValue: (t) => String(t.caCount), render: (t) => <span className="text-xs text-gray-600 dark:text-gray-400">{t.caCount}</span> },
        { key: 'users', header: 'Users', defaultWidth: 100, exportValue: (t) => String(t.userCount), render: (t) => <span className="text-xs text-gray-600 dark:text-gray-400">{t.userCount}</span> },
        { key: 'certs', header: 'Certs', defaultWidth: 120, headerTitle: 'Active certificates', exportValue: (t) => String(t.issuedCertificates), render: (t) => <span className="text-xs text-gray-600 dark:text-gray-400">{t.issuedCertificates}</span> },
        { key: 'created', header: 'Created', defaultWidth: 160, exportValue: (t) => formatDate(t.createdAt), render: (t) => <span className="text-xs text-gray-600 dark:text-gray-400">{formatDate(t.createdAt)}</span> },
    ];

    const drawer = (t: Space) => (
        <div className="text-sm">
            <DetailField label="Name" value={t.name} />
            <DetailField label="Description" value={t.description || '-'} />
            <DetailField label="Status" value={t.isEnabled !== false ? 'Enabled' : 'Disabled'} />
            <DetailField label="CAs" value={t.caCount} />
            <DetailField label="Users" value={t.userCount} />
            <DetailField label="Active Certs" value={t.issuedCertificates} />
            <DetailField label="Key Ceremony" value={t.requireKeyCeremony ? `Yes (${t.ceremonyRequiredApprovals} approval${t.ceremonyRequiredApprovals === 1 ? '' : 's'} from others; the initiator is never counted)` : 'No'} />
            <DetailField label="Created" value={formatDate(t.createdAt)} />
            <p className="text-[11px] text-gray-500 pt-3">Open the full page to edit the validity ceiling, toggle status, or set per-CA quotas.</p>
        </div>
    );

    return (
        <div className="p-3 sm:p-6 space-y-4 sm:space-y-6">
            <div className="flex items-start justify-between flex-wrap gap-3">
                <div>
                    <h1 className="text-2xl font-bold text-gray-900 dark:text-white">Spaces &amp; Quotas</h1>
                    <p className="text-sm text-gray-600 dark:text-gray-400 mt-1">A space groups CAs for delegated administration and carries their ceilings. Open a space to edit its ceilings and set per-CA issuance quotas.</p>
                </div>
                <button onClick={() => setShowCreate(!showCreate)} className="px-4 py-2 text-sm bg-blue-600 text-white rounded hover:bg-blue-700 transition-colors">
                    {showCreate ? 'Cancel' : 'Create Space'}
                </button>
            </div>

            {createdRecommendation && (
                <div role="status" className="flex items-start justify-between gap-3 bg-amber-50 dark:bg-amber-900/20 border border-amber-300 dark:border-amber-700 rounded p-3 text-xs text-amber-900 dark:text-amber-200">
                    <span>The space was created. {createdRecommendation}</span>
                    <button type="button" onClick={() => setCreatedRecommendation(null)} className="text-amber-900 dark:text-amber-200 hover:underline">Dismiss</button>
                </div>
            )}

            {/* summary tiles */}
            {totals && (
                <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
                    {[
                        { label: 'Spaces', value: totals.totalSpaces, cls: 'text-gray-900 dark:text-white' },
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
                    <h3 className="text-sm font-semibold text-gray-900 dark:text-white">New Space</h3>
                    <p className="bg-blue-50 dark:bg-blue-900/20 border border-blue-300 dark:border-blue-800 rounded p-3 text-xs text-blue-900 dark:text-blue-200">{SPACE_INTERSTITIAL}</p>
                    {recommendation && (
                        <p className="bg-amber-50 dark:bg-amber-900/20 border border-amber-300 dark:border-amber-700 rounded p-3 text-xs text-amber-900 dark:text-amber-200">
                            This will be space {spaces.length + 1}. {recommendation} The space is created either way.
                        </p>
                    )}
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                        <input type="text" placeholder="Space Name" required value={createForm.name}
                            onChange={(e) => setCreateForm({ ...createForm, name: e.target.value })}
                            className="px-3 py-2 bg-gray-50 dark:bg-gray-900 border border-gray-300 dark:border-gray-700 rounded text-sm text-gray-900 dark:text-white placeholder-gray-400 dark:placeholder-gray-500 focus:outline-none focus:border-blue-500" />
                        <input type="text" placeholder="Description" value={createForm.description}
                            onChange={(e) => setCreateForm({ ...createForm, description: e.target.value })}
                            className="px-3 py-2 bg-gray-50 dark:bg-gray-900 border border-gray-300 dark:border-gray-700 rounded text-sm text-gray-900 dark:text-white placeholder-gray-400 dark:placeholder-gray-500 focus:outline-none focus:border-blue-500" />
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

            <DataTable<Space>
                tableId="spaces"
                title="All Spaces"
                rows={spaces}
                rowKey={(t) => t.id}
                loading={loading}
                error={error}
                empty="No spaces found"
                columns={columns}
                selectable
                exportFileName="spaces"
                renderDrawer={drawer}
                drawerTitle={(t) => t.name}
                detailPath={(t) => `/spaces/${t.id}`}
            />

            {instance && (
                <div className="bg-gray-100 dark:bg-gray-800 border border-gray-300 dark:border-gray-700 rounded-lg overflow-hidden">
                    <div className="px-4 py-3 border-b border-gray-300 dark:border-gray-700">
                        <h3 className="text-sm font-semibold text-gray-900 dark:text-white">Instance</h3>
                        <p className="text-xs text-gray-600 dark:text-gray-400 mt-1">
                            The instance's own CAs belong to no space. Their policy is the instance's (Settings → Security Policy), independent of every space's.
                        </p>
                    </div>
                    <div className="px-4 py-2 grid grid-cols-2 md:grid-cols-4 gap-x-4 text-sm">
                        <DetailField label="Key Ceremony" value={instance.requireKeyCeremony ? `Yes (${instance.ceremonyRequiredApprovals} approval${instance.ceremonyRequiredApprovals === 1 ? '' : 's'} from others)` : 'No'} />
                        <DetailField label="Max Cert Validity" value={instance.maxValidityDays > 0 ? `${instance.maxValidityDays} days (${instance.validityCeilingBehavior === 'Refuse' ? 'refuse' : 'shorten'})` : 'Unlimited'} />
                        <DetailField label="Users" value={String(instance.userCount)} />
                        <DetailField label="Active Certs" value={String(instance.issuedCertificates)} />
                    </div>
                    {instance.certificateAuthorities.length === 0 ? (
                        <div className="px-4 py-2 text-xs text-gray-500">No instance CAs.</div>
                    ) : instance.certificateAuthorities.map((ca) => <CaQuotaRow key={ca.id} ca={ca} readOnly />)}
                    <div id={INSTANCE_REALMS_ANCHOR} className="scroll-mt-4 px-4 py-3 border-t border-gray-300 dark:border-gray-700">
                        <KerberosRealmsPanel spaceId={null} spaceName="Instance" caLabels={instance.certificateAuthorities.filter((c) => !c.isSshCa && c.label).map((c) => c.label!)} />
                    </div>
                </div>
            )}

            {/* System-scope controlled-user approval quorum — space/CA scopes live on each space's page. */}
            <SystemQuorumCard />
        </div>
    );
};

export default SpacesAndQuotas;
