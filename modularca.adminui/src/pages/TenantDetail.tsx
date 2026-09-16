import React, { useEffect, useState, useCallback } from 'react';
import type { NoticeInput } from '@shared/notifications/notice';
import { InlineNotice } from '@shared/components/InlineNotice';
import { errorNotice } from '@shared-auth/api/notices';
import { useParams, useNavigate } from 'react-router-dom';
import { apiGet, apiPutWithMfa, apiDeleteWithMfa } from '../api/client';
import { useStepUp } from '../components/StepUpMfaContext';
import { useToast } from '@shared/context/ToastContext';
import { StatusBadge } from '@shared/components/cards/StatusBadge';
import { DetailField } from '@shared/components/cards/DetailField';
import ConfirmModal from '../components/ConfirmModal';
import { DetailPage, DetailSection } from '../components/DetailPage';
import { TenantUserQuorumSection, TenantQ, QuorumData } from '../components/UserQuorumPanel';
import KerberosRealmsPanel from '../components/KerberosRealmsPanel';
import { Tenant, CaQuotaRow, formatDate, numInput } from './TenantsAndQuotas';
import { labelClass as labelCls, FieldHint } from '@shared/components/forms';
import { StepUpOps } from '@shared/generated';
import type { ValidityCeilingBehavior } from '@shared/generated';

const num = (s: string) => (s.trim() === '' ? null : parseInt(s, 10));

/// <summary>
/// Detail page for a single tenant. All three editable sections — org-level ceilings, per-CA issuance
/// quotas, and the tenant/CA user-approval quorums — are edited together: the page owns the edit
/// buffers, the action bar shows ONE Save (greyed until something changes) + Cancel, and Save fans the
/// changes out to their respective endpoints. Guarded status actions (enable / disable / soft delete)
/// stay in the action bar. Lowering a security ceiling (key ceremony off / fewer approvals) starts a
/// key ceremony server-side.
/// </summary>
const TenantDetail: React.FC = () => {
    const { id } = useParams<{ id: string }>();
    const navigate = useNavigate();
    const { showToast } = useToast();
    const { requireStepUp } = useStepUp();

    const [tenant, setTenant] = useState<Tenant | null>(null);
    const [quorum, setQuorum] = useState<TenantQ | null>(null);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState<NoticeInput | null>(null);
    const [confirm, setConfirm] = useState<{ title: string; message: string; confirmLabel: string; confirmClass?: string; action: () => Promise<void> } | null>(null);

    // ── edit buffers (seeded from source on load / Cancel) ──
    const blankForm = { description: '', maxCAs: 0, maxCertificates: 0, maxUsers: 0, maxValidityDays: 0, validityCeilingBehavior: 'Shorten' as ValidityCeilingBehavior, requireKeyCeremony: false, ceremonyRequiredApprovals: 1 };
    const [form, setForm] = useState(blankForm);
    const [quotaEdits, setQuotaEdits] = useState<Record<string, { maxCertificates: number; maxPendingRequests: number }>>({});
    const [tenantQuorum, setTenantQuorum] = useState('');                 // '' = inherit
    const [caQuorum, setCaQuorum] = useState<Record<string, string>>({}); // caId → '' | number

    const seed = useCallback((t: Tenant, q: TenantQ | null) => {
        setForm({
            description: t.description || '',
            maxCAs: t.maxCertificateAuthorities ?? 0,
            maxCertificates: t.maxCertificatesTotal ?? 0,
            maxUsers: t.maxUsers ?? 0,
            maxValidityDays: t.maxValidityDays ?? 0,
            validityCeilingBehavior: t.validityCeilingBehavior ?? 'Shorten',
            requireKeyCeremony: t.requireKeyCeremony ?? false,
            ceremonyRequiredApprovals: t.ceremonyRequiredApprovals ?? 1,
        });
        const qe: Record<string, { maxCertificates: number; maxPendingRequests: number }> = {};
        for (const ca of t.certificateAuthorities || []) {
            if (ca.quota?.groupId) qe[ca.quota.groupId] = { maxCertificates: ca.quota.maxCertificates ?? 0, maxPendingRequests: ca.quota.maxPendingRequests ?? 0 };
        }
        setQuotaEdits(qe);
        setTenantQuorum(q?.override != null ? String(q.override) : '');
        const ce: Record<string, string> = {};
        if (q) for (const ca of q.cas) ce[ca.id] = ca.override != null ? String(ca.override) : '';
        setCaQuorum(ce);
    }, []);

    const load = useCallback(() => {
        setLoading(true);
        Promise.all([
            apiGet<any>('/api/v1/admin/quotas/by-tenant'),
            apiGet<QuorumData>('/api/v1/admin/user-quorum').catch(() => null),
        ]).then(([quotaData, quorumData]) => {
            const t: Tenant | null = (quotaData.tenants || []).find((x: Tenant) => x.id === id) || null;
            const q: TenantQ | null = quorumData ? ((quorumData.tenants || []).find((x: TenantQ) => x.id === id) || null) : null;
            setTenant(t); setQuorum(q); setError(null);
            if (t) seed(t, q);
        }).catch((err) => setError(errorNotice(err, 'Failed to load tenant')))
            .finally(() => setLoading(false));
    }, [id, seed]);

    useEffect(() => { load(); }, [load]);

    const resetEdits = useCallback(() => { if (tenant) seed(tenant, quorum); }, [tenant, quorum, seed]);

    if (loading) return <div className="p-6 text-sm text-gray-600 dark:text-gray-400">Loading…</div>;
    if (error) return <InlineNotice notice={error} />;
    if (!tenant) return (
        <div className="p-6 space-y-3">
            <p className="text-sm text-gray-600 dark:text-gray-400">Tenant not found.</p>
            <button onClick={() => navigate('/tenants')} className="px-3 py-1.5 text-sm bg-gray-200 dark:bg-gray-700 rounded">Back to Tenants</button>
        </div>
    );

    const t = tenant;
    const cas = t.certificateAuthorities || [];

    // ── dirty / validity (drive the unified Save button) ──
    const ceilingsDirty =
        form.description !== (t.description || '') ||
        form.maxCAs !== (t.maxCertificateAuthorities ?? 0) ||
        form.maxCertificates !== (t.maxCertificatesTotal ?? 0) ||
        form.maxUsers !== (t.maxUsers ?? 0) ||
        form.maxValidityDays !== (t.maxValidityDays ?? 0) ||
        form.validityCeilingBehavior !== (t.validityCeilingBehavior ?? 'Shorten') ||
        form.requireKeyCeremony !== (t.requireKeyCeremony ?? false) ||
        form.ceremonyRequiredApprovals !== (t.ceremonyRequiredApprovals ?? 1);
    const quotaDirty = cas.some((ca) => {
        const gid = ca.quota?.groupId; if (!gid) return false;
        const v = quotaEdits[gid]; if (!v) return false;
        return v.maxCertificates !== (ca.quota!.maxCertificates ?? 0) || v.maxPendingRequests !== (ca.quota!.maxPendingRequests ?? 0);
    });
    const tenantQuorumDirty = !!quorum && (num(tenantQuorum) ?? null) !== (quorum.override ?? null);
    const caQuorumDirty = !!quorum && quorum.cas.some((ca) => (num(caQuorum[ca.id] ?? '') ?? null) !== (ca.override ?? null));
    const quorumInvalid = !!quorum && quorum.cas.some((ca) => { const p = num(caQuorum[ca.id] ?? ''); return p != null && p > quorum.effective; });

    const anyDirty = ceilingsDirty || quotaDirty || tenantQuorumDirty || caQuorumDirty;

    // A change is a security downgrade when it turns the ceremony off or lowers the approval count.
    const downgrade = (form.requireKeyCeremony === false && t.requireKeyCeremony === true) ||
        (form.ceremonyRequiredApprovals < t.ceremonyRequiredApprovals);

    // ── unified save: ONE atomic request through the combined settings sub-resource, gated by a
    // single step-up MFA prompt (any sensitive field counts). We send the full desired state. ──
    const handleSave = async () => {
        try {
            const body = {
                description: form.description,
                maxCertificateAuthorities: form.maxCAs,
                maxCertificatesTotal: form.maxCertificates,
                maxUsers: form.maxUsers,
                maxValidityDays: form.maxValidityDays,
                validityCeilingBehavior: form.validityCeilingBehavior,
                requireKeyCeremony: form.requireKeyCeremony,
                ceremonyRequiredApprovals: form.ceremonyRequiredApprovals,
                applyUserQuorums: quorum != null,
                userQuorum: quorum ? num(tenantQuorum) : null,
                caQuorums: quorum ? quorum.cas.map((ca) => ({ caId: ca.id, quorum: num(caQuorum[ca.id] ?? '') })) : [],
                caQuotas: cas.filter((ca) => ca.quota?.groupId).map((ca) => ({
                    groupId: ca.quota!.groupId,
                    maxCertificates: quotaEdits[ca.quota!.groupId!]?.maxCertificates ?? (ca.quota!.maxCertificates ?? 0),
                    maxPendingRequests: quotaEdits[ca.quota!.groupId!]?.maxPendingRequests ?? (ca.quota!.maxPendingRequests ?? 0),
                })),
            };
            // 202 + ceremonyId when a key-ceremony downgrade is gated behind a tenant policy ceremony.
            const result = await apiPutWithMfa<any>(`/api/v1/admin/tenants/${t.id}/settings`, body, requireStepUp, StepUpOps.UpdateTenantSettings, t.id);
            if (result?.ceremonyId) showToast('info', 'Policy change ceremony started. Approve at /admin/ceremonies/' + result.ceremonyId);
            else showToast('success', 'Changes saved');
            load();
        } catch (err: any) {
            if (err?.message !== 'Step-up MFA cancelled') showToast('error', err.message || 'Failed to save changes');
            throw err; // keep the page in Edit mode so nothing is lost
        }
    };

    const toggleEnabled = () => {
        const enabling = t.isEnabled === false;
        setConfirm({
            title: enabling ? 'Enable Tenant' : 'Disable Tenant',
            message: `Are you sure you want to ${enabling ? 'enable' : 'disable'} tenant "${t.name}"?`,
            confirmLabel: enabling ? 'Enable' : 'Disable',
            confirmClass: enabling
                ? 'px-4 py-2 text-sm bg-green-600 text-white rounded hover:bg-green-700 transition-colors'
                : 'px-4 py-2 text-sm bg-yellow-600 text-white rounded hover:bg-yellow-700 transition-colors',
            action: async () => {
                if (enabling) await apiPutWithMfa(`/api/v1/admin/tenants/${t.id}`, { isEnabled: true }, requireStepUp, StepUpOps.EnableTenant, t.id);
                else await apiDeleteWithMfa(`/api/v1/admin/tenants/${t.id}`, requireStepUp, StepUpOps.DisableTenant, t.id);
                load();
            },
        });
    };

    const softDelete = () => setConfirm({
        title: 'Soft Delete Tenant',
        message: `Are you sure you want to disable tenant "${t.name}"? This is a soft delete.`,
        confirmLabel: 'Soft Delete',
        confirmClass: 'px-4 py-2 text-sm bg-red-600 text-white rounded hover:bg-red-700 transition-colors',
        action: async () => {
            await apiDeleteWithMfa(`/api/v1/admin/tenants/${t.id}`, requireStepUp, StepUpOps.DisableTenant, t.id);
            load();
        },
    });

    return (
        <DetailPage
            breadcrumbs={[{ label: 'Tenants', to: '/tenants' }, { label: t.name }]}
            title={<>{t.name}{t.isSystemTenant && <span className="ml-2 text-xs font-normal text-gray-500">(system)</span>}</>}
            status={<StatusBadge status={t.isEnabled !== false ? 'active' : 'disabled'} label={t.isEnabled !== false ? 'Enabled' : 'Disabled'} />}
            subtitle={t.description || undefined}
            backTo="/tenants"
            editable
            onSave={handleSave}
            onCancel={resetEdits}
            saveDisabled={!anyDirty || quorumInvalid}
            actions={
                <div className="flex items-center gap-2 flex-wrap">
                    {t.isEnabled !== false
                        ? <button onClick={toggleEnabled} className="px-3 py-1.5 text-xs bg-yellow-50 dark:bg-yellow-900/50 text-yellow-800 dark:text-yellow-300 border border-yellow-300 dark:border-yellow-700 rounded hover:bg-yellow-900 transition-colors">Disable</button>
                        : <button onClick={toggleEnabled} className="px-3 py-1.5 text-xs bg-green-50 dark:bg-green-900/50 text-green-800 dark:text-green-300 border border-green-300 dark:border-green-700 rounded hover:bg-green-900 transition-colors">Enable</button>}
                    {t.isEnabled !== false && !t.isSystemTenant && (
                        <button onClick={softDelete} className="px-3 py-1.5 text-xs bg-red-600 text-white rounded hover:bg-red-700 transition-colors">Soft Delete</button>
                    )}
                </div>
            }
        >
            {(mode) => (<>
                <DetailSection title="Tenant Ceilings">
                    {mode === 'edit' ? (
                        <div className="space-y-3">
                            <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                                <div><label className={labelCls}>Description</label>
                                    <input value={form.description} onChange={(e) => setForm({ ...form, description: e.target.value })} className={numInput} /></div>
                                <div><label className={labelCls}>Max CAs (0 = unlimited)</label>
                                    <input inputMode="numeric" value={form.maxCAs} onChange={(e) => setForm({ ...form, maxCAs: parseInt(e.target.value.replace(/\D/g, '') || '0', 10) })} className={numInput} /></div>
                                <div><label className={labelCls}>Max Certificates (0 = unlimited)</label>
                                    <input inputMode="numeric" value={form.maxCertificates} onChange={(e) => setForm({ ...form, maxCertificates: parseInt(e.target.value.replace(/\D/g, '') || '0', 10) })} className={numInput} /></div>
                                <div><label className={labelCls}>Max Users (0 = unlimited)</label>
                                    <input inputMode="numeric" value={form.maxUsers} onChange={(e) => setForm({ ...form, maxUsers: parseInt(e.target.value.replace(/\D/g, '') || '0', 10) })} className={numInput} /></div>
                                <div>
                                    <label className={labelCls}>Max Cert Validity (days, 0 = unlimited)</label>
                                    <input inputMode="numeric" value={form.maxValidityDays} onChange={(e) => setForm({ ...form, maxValidityDays: parseInt(e.target.value.replace(/[^0-9]/g, '') || '0', 10) })} className={numInput} />
                                    <p className="text-[11px] text-gray-500 dark:text-gray-500 mt-1">Infrastructure and CA certificates are exempt from this ceiling.</p>
                                </div>
                                <div>
                                    <label className={labelCls}>When a request exceeds the ceiling</label>
                                    <select value={form.validityCeilingBehavior}
                                        onChange={(e) => setForm({ ...form, validityCeilingBehavior: e.target.value as ValidityCeilingBehavior })}
                                        className={numInput}>
                                        <option value="Shorten">Shorten it (warn with MCA-ISS-004)</option>
                                        <option value="Refuse">Refuse it (MCA-ISS-005)</option>
                                    </select>
                                    <p className="text-[11px] text-gray-500 dark:text-gray-500 mt-1">
                                        Refuse governs admin and interactive issuance only. ACME, EST, SCEP and CMP enrollments and automatic renewals <strong>always shorten</strong>, whatever this is set to — an enrolling client can neither see this ceiling nor change its own request, so refusing it would fail enrollments nobody at the other end can fix.
                                    </p>
                                </div>
                                <div className="flex items-center gap-2 pt-2">
                                    <input type="checkbox" id={`cer-${t.id}`} checked={form.requireKeyCeremony}
                                        onChange={(e) => setForm({ ...form, requireKeyCeremony: e.target.checked })}
                                        className="h-4 w-4 rounded border-gray-300 dark:border-gray-600 text-blue-600 focus:ring-blue-500" />
                                    <label htmlFor={`cer-${t.id}`} className="text-xs text-gray-600">Require Key Ceremony for CA Creation</label>
                                </div>
                                {form.requireKeyCeremony && (
                                    <div><label className={labelCls}>Required Approvals</label>
                                        <input inputMode="numeric" value={form.ceremonyRequiredApprovals}
                                            onChange={(e) => setForm({ ...form, ceremonyRequiredApprovals: parseInt(e.target.value.replace(/\D/g, '') || '1', 10) || 1 })} className={numInput} />
                                        <FieldHint>Approvals from other tenant admins before a CA key ceremony may execute. The initiator is always excluded, so the effective minimum is 1 other approver.</FieldHint>
                                    </div>
                                )}
                            </div>
                            {downgrade && (
                                <div className="bg-amber-50 dark:bg-amber-900/20 border border-amber-300 dark:border-amber-700 rounded p-3 text-xs text-amber-900 dark:text-amber-200">
                                    This change lowers tenant security policy. Saving will start a key ceremony requiring {t.ceremonyRequiredApprovals} approvals from tenant admins before the change takes effect. System admins can bypass this by using the direct API with step-up MFA.
                                </div>
                            )}
                        </div>
                    ) : (
                        <div className="grid grid-cols-1 md:grid-cols-2 gap-x-8">
                            <DetailField label="ID" value={t.id} mono />
                            <DetailField label="Description" value={t.description || '-'} />
                            <DetailField label="Max CAs" value={t.maxCertificateAuthorities || 'Unlimited'} />
                            <DetailField label="Max Certificates" value={t.maxCertificatesTotal || 'Unlimited'} />
                            <DetailField label="Max Users" value={t.maxUsers || 'Unlimited'} />
                            <DetailField label="Max Cert Validity" value={t.maxValidityDays ? `${t.maxValidityDays} days` : 'Unlimited'} />
                            <DetailField label="Over the ceiling" value={t.maxValidityDays
                                ? (t.validityCeilingBehavior === 'Refuse'
                                    ? 'Refuse admin requests (protocol enrollments still shorten)'
                                    : 'Shorten and warn')
                                : 'n/a — no ceiling set'} />
                            <DetailField label="Key Ceremony Required" value={t.requireKeyCeremony ? `Yes (${t.ceremonyRequiredApprovals} approval${t.ceremonyRequiredApprovals === 1 ? '' : 's'} from others; the initiator is never counted)` : 'No'} />
                            <DetailField label="Created" value={formatDate(t.createdAt)} />
                        </div>
                    )}
                </DetailSection>

                <div className="space-y-3">
                    <div>
                        <h3 className="text-sm font-semibold text-gray-900 dark:text-white">Per-CA Issuance Quotas <span className="text-gray-500 font-normal">({cas.length})</span></h3>
                        <p className="text-xs text-gray-600 dark:text-gray-400 mt-1">
                            Per-CA certificate issuance ceilings (0 = unlimited).{mode === 'view' ? ' Switch to Edit to change.' : ' Edit values and use Save above.'}
                        </p>
                    </div>
                    {cas.length === 0 ? (
                        <div className="py-3 text-xs text-gray-500 text-center border border-gray-300 dark:border-gray-700 rounded-lg">No CAs in this tenant</div>
                    ) : (
                        <div className="border border-gray-300 dark:border-gray-700 rounded-lg overflow-hidden">
                            <div className="px-3 py-2 border-b border-gray-300 dark:border-gray-700 grid grid-cols-[1fr_70px_70px_70px_150px_70px_70px] gap-2 text-[10px] text-gray-500 font-semibold uppercase tracking-wide bg-gray-50/60 dark:bg-gray-900/40">
                                <span>CA</span><span>Max</span><span>Issued</span><span>Left</span><span>Usage</span><span>Pend</span><span>Max Pend</span>
                            </div>
                            {cas.map((ca) => (
                                <CaQuotaRow key={ca.id} ca={ca} readOnly={mode === 'view'}
                                    value={ca.quota?.groupId ? quotaEdits[ca.quota.groupId] : undefined}
                                    onChange={(next) => { const gid = ca.quota?.groupId; if (gid) setQuotaEdits((prev) => ({ ...prev, [gid]: next })); }} />
                            ))}
                        </div>
                    )}
                </div>

                <div className="space-y-3">
                    <div>
                        <h3 className="text-sm font-semibold text-gray-900 dark:text-white">User Approval Quorum</h3>
                        <p className="text-xs text-gray-600 dark:text-gray-400 mt-1">
                            Approvals required to promote/demote/delete a privileged user in this tenant and its CAs. Inherits from the System quorum; a CA may require fewer than its tenant, never more.{mode === 'view' ? ' Switch to Edit to change.' : ''}
                        </p>
                    </div>
                    <TenantUserQuorumSection
                        quorum={quorum} readOnly={mode === 'view'}
                        tenantValue={tenantQuorum} onTenantChange={setTenantQuorum}
                        caValues={caQuorum} onCaChange={(caId, s) => setCaQuorum((prev) => ({ ...prev, [caId]: s }))} />
                    {mode === 'edit' && quorumInvalid && (
                        <p className="text-xs text-red-700 dark:text-red-400">A CA quorum can't exceed its tenant's effective quorum ({quorum?.effective}). Fix the highlighted value to enable Save.</p>
                    )}
                </div>

                <KerberosRealmsPanel tenantId={t.id} tenantName={t.name} caLabels={cas.map((c: any) => c.caLabel || c.label || c.name).filter(Boolean)} />

                <ConfirmModal
                    isOpen={!!confirm}
                    title={confirm?.title || ''}
                    message={confirm?.message || ''}
                    confirmLabel={confirm?.confirmLabel || 'Confirm'}
                    confirmClass={confirm?.confirmClass}
                    onConfirm={async () => {
                        if (!confirm) return;
                        const act = confirm.action;
                        setConfirm(null);
                        try { await act(); }
                        catch (err: any) { if (err?.message !== 'Step-up MFA cancelled') showToast('error', err.message || 'Operation failed'); }
                    }}
                    onCancel={() => setConfirm(null)}
                />
            </>)}
        </DetailPage>
    );
};

export default TenantDetail;
