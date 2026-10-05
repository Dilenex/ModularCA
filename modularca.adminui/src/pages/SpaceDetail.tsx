import React, { useEffect, useState, useCallback } from 'react';
import type { NoticeInput } from '@shared/notifications/notice';
import { InlineNotice } from '@shared/components/InlineNotice';
import { errorNotice } from '@shared-auth/api/notices';
import { Link, useLocation, useParams, useNavigate } from 'react-router-dom';
import { apiGet, apiPutWithMfa, apiDeleteWithMfa } from '../api/client';
import { useStepUp } from '../components/StepUpMfaContext';
import { useToast } from '@shared/context/ToastContext';
import { StatusBadge } from '@shared/components/cards/StatusBadge';
import { DetailField } from '@shared/components/cards/DetailField';
import ConfirmModal from '../components/ConfirmModal';
import { DetailPage, DetailSection } from '../components/DetailPage';
import { SpaceUserQuorumSection, SpaceQ, QuorumData } from '../components/UserQuorumPanel';
import KerberosRealmsPanel from '../components/KerberosRealmsPanel';
import { Space, CaQuotaRow, formatDate, numInput } from './SpacesAndQuotas';
import { labelClass as labelCls, FieldHint } from '@shared/components/forms';
import { StepUpOps } from '@shared/generated';
import type { ValidityCeilingBehavior } from '@shared/generated';
import { SPACE_REALMS_ANCHOR } from './msaeRefusals';
import { useScrollToHash } from '../hooks/useScrollToHash';
import { ceremonyLink } from './ceremonyLinks';
import { INSTANCE_CEREMONY_SETTINGS_PATH, KEY_CEREMONIES_ANCHOR, USERS_PATH, requirementWarning } from './ceremonyRefusal';
import { useAuth } from '../context/AuthContext';

const num = (s: string) => (s.trim() === '' ? null : parseInt(s, 10));

/// <summary>
/// Detail page for a single space. All three editable sections — space ceilings, per-CA issuance
/// quotas, and the space/CA user-approval quorums — are edited together: the page owns the edit
/// buffers, the action bar shows ONE Save (greyed until something changes) + Cancel, and Save fans the
/// changes out to their respective endpoints. Guarded status actions (enable / disable / soft delete)
/// stay in the action bar. Lowering a security ceiling (key ceremony off / fewer approvals) starts a
/// key ceremony server-side.
/// </summary>
const SpaceDetail: React.FC = () => {
    const { id } = useParams<{ id: string }>();
    const navigate = useNavigate();
    const { showToast } = useToast();
    const { requireStepUp } = useStepUp();
    const { user } = useAuth();
    // A link to the key-ceremony switch (#key-ceremonies) opens the page ready to change it.
    const { hash } = useLocation();

    const [space, setSpace] = useState<Space | null>(null);
    /* Accounts other than this one that could approve a key ceremony in this space; null until known. */
    const [approvers, setApprovers] = useState<number | null>(null);
    const [quorum, setQuorum] = useState<SpaceQ | null>(null);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState<NoticeInput | null>(null);
    const [confirm, setConfirm] = useState<{ title: string; message: string; confirmLabel: string; confirmClass?: string; action: () => Promise<void> } | null>(null);

    // ── edit buffers (seeded from source on load / Cancel) ──
    const blankForm = { description: '', maxValidityDays: 0, validityCeilingBehavior: 'Shorten' as ValidityCeilingBehavior, requireKeyCeremony: false, ceremonyRequiredApprovals: 1 };
    const [form, setForm] = useState(blankForm);
    const [quotaEdits, setQuotaEdits] = useState<Record<string, { maxCertificates: number; maxPendingRequests: number }>>({});
    const [spaceQuorum, setSpaceQuorum] = useState('');                 // '' = inherit
    const [caQuorum, setCaQuorum] = useState<Record<string, string>>({}); // caId → '' | number

    const seed = useCallback((t: Space, q: SpaceQ | null) => {
        setForm({
            description: t.description || '',
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
        setSpaceQuorum(q?.override != null ? String(q.override) : '');
        const ce: Record<string, string> = {};
        if (q) for (const ca of q.cas) ce[ca.id] = ca.override != null ? String(ca.override) : '';
        setCaQuorum(ce);
    }, []);

    const load = useCallback(() => {
        setLoading(true);
        Promise.all([
            apiGet<any>('/api/v1/admin/quotas/by-space'),
            apiGet<QuorumData>('/api/v1/admin/user-quorum').catch(() => null),
            apiGet<any>(`/api/v1/admin/ceremonies/approvers/${id}`, { toast: false }).catch(() => null),
        ]).then(([quotaData, quorumData, approverData]) => {
            setApprovers(typeof approverData?.eligibleApprovers === 'number' ? approverData.eligibleApprovers : null);
            const t: Space | null = (quotaData.spaces || []).find((x: Space) => x.id === id) || null;
            const q: SpaceQ | null = quorumData ? ((quorumData.spaces || []).find((x: SpaceQ) => x.id === id) || null) : null;
            setSpace(t); setQuorum(q); setError(null);
            if (t) seed(t, q);
        }).catch((err) => setError(errorNotice(err, 'Failed to load space')))
            .finally(() => setLoading(false));
    }, [id, seed]);

    useEffect(() => { load(); }, [load]);
    useScrollToHash(!loading && !!space);

    const resetEdits = useCallback(() => { if (space) seed(space, quorum); }, [space, quorum, seed]);

    if (loading) return <div className="p-6 text-sm text-ink-muted">Loading…</div>;
    if (error) return <InlineNotice notice={error} />;
    if (!space) return (
        <div className="p-6 space-y-3">
            <p className="text-sm text-ink-muted">Space not found.</p>
            <button onClick={() => navigate('/spaces')} className="px-3 py-1.5 text-sm bg-sunken rounded">Back to Spaces</button>
        </div>
    );

    const t = space;
    const cas = t.certificateAuthorities || [];

    // ── dirty / validity (drive the unified Save button) ──
    const ceilingsDirty =
        form.description !== (t.description || '') ||
        form.maxValidityDays !== (t.maxValidityDays ?? 0) ||
        form.validityCeilingBehavior !== (t.validityCeilingBehavior ?? 'Shorten') ||
        form.requireKeyCeremony !== (t.requireKeyCeremony ?? false) ||
        form.ceremonyRequiredApprovals !== (t.ceremonyRequiredApprovals ?? 1);
    const quotaDirty = cas.some((ca) => {
        const gid = ca.quota?.groupId; if (!gid) return false;
        const v = quotaEdits[gid]; if (!v) return false;
        return v.maxCertificates !== (ca.quota!.maxCertificates ?? 0) || v.maxPendingRequests !== (ca.quota!.maxPendingRequests ?? 0);
    });
    const spaceQuorumDirty = !!quorum && (num(spaceQuorum) ?? null) !== (quorum.override ?? null);
    const caQuorumDirty = !!quorum && quorum.cas.some((ca) => (num(caQuorum[ca.id] ?? '') ?? null) !== (ca.override ?? null));
    const quorumInvalid = !!quorum && quorum.cas.some((ca) => { const p = num(caQuorum[ca.id] ?? ''); return p != null && p > quorum.effective; });

    const anyDirty = ceilingsDirty || quotaDirty || spaceQuorumDirty || caQuorumDirty;

    // A change is a security downgrade when it turns the ceremony off or lowers the approval count.
    const downgrade = (form.requireKeyCeremony === false && t.requireKeyCeremony === true) ||
        (form.ceremonyRequiredApprovals < t.ceremonyRequiredApprovals);
    const ceremonyPolicyDirty = form.requireKeyCeremony !== (t.requireKeyCeremony ?? false) ||
        (form.requireKeyCeremony && form.ceremonyRequiredApprovals !== (t.ceremonyRequiredApprovals ?? 1));
    // Warns, without blocking, when the requirement is (or would be) on and too few others could approve.
    const ceremonyWarning = requirementWarning({
        required: form.requireKeyCeremony,
        wasRequired: t.requireKeyCeremony === true,
        approvals: form.ceremonyRequiredApprovals,
        eligibleApprovers: approvers,
        scope: 'this space',
    });

    // ── unified save: ONE atomic request through the combined settings sub-resource, gated by a
    // single step-up MFA prompt (any sensitive field counts). We send the full desired state. ──
    const handleSave = async () => {
        try {
            const body = {
                description: form.description,
                maxValidityDays: form.maxValidityDays,
                validityCeilingBehavior: form.validityCeilingBehavior,
                requireKeyCeremony: form.requireKeyCeremony,
                ceremonyRequiredApprovals: form.ceremonyRequiredApprovals,
                applyUserQuorums: quorum != null,
                userQuorum: quorum ? num(spaceQuorum) : null,
                caQuorums: quorum ? quorum.cas.map((ca) => ({ caId: ca.id, quorum: num(caQuorum[ca.id] ?? '') })) : [],
                caQuotas: cas.filter((ca) => ca.quota?.groupId).map((ca) => ({
                    groupId: ca.quota!.groupId,
                    maxCertificates: quotaEdits[ca.quota!.groupId!]?.maxCertificates ?? (ca.quota!.maxCertificates ?? 0),
                    maxPendingRequests: quotaEdits[ca.quota!.groupId!]?.maxPendingRequests ?? (ca.quota!.maxPendingRequests ?? 0),
                })),
            };
            // 202 + ceremonyId when a key-ceremony downgrade is gated behind a space policy ceremony.
            const result = await apiPutWithMfa<any>(`/api/v1/admin/spaces/${t.id}/settings`, body, requireStepUp, StepUpOps.UpdateSpaceSettings, t.id);
            if (result?.ceremonyId) showToast('info', `Policy change ceremony started. Approve it at ${ceremonyLink(result.ceremonyId)}`);
            else showToast('success', 'Changes saved');
            load();
        } catch (err: any) {
            if (err?.message !== 'Step-up MFA cancelled') showToast('error', err.message || 'Failed to save changes');
            throw err; // keep the page in Edit mode so nothing is lost
        }
    };

    // The server has no delete for a space: DELETE disables it (keeping its CAs and data), and
    // PUT { isEnabled: true } enables it again.
    const toggleEnabled = () => {
        const enabling = t.isEnabled === false;
        setConfirm({
            title: enabling ? 'Enable Space' : 'Disable Space',
            message: enabling
                ? `Enable space "${t.name}"? Its CAs may issue again.`
                : `Disable space "${t.name}"? Its CAs stop issuing. Nothing is deleted, and the space can be enabled again.`,
            confirmLabel: enabling ? 'Enable' : 'Disable',
            confirmClass: enabling
                ? 'px-4 py-2 text-sm bg-ok text-on-accent rounded hover:bg-ok-hover transition-colors'
                : 'px-4 py-2 text-sm bg-warn text-on-accent rounded hover:bg-warn-hover transition-colors',
            action: async () => {
                if (enabling) await apiPutWithMfa(`/api/v1/admin/spaces/${t.id}`, { isEnabled: true }, requireStepUp, StepUpOps.EnableSpace, t.id);
                else await apiDeleteWithMfa(`/api/v1/admin/spaces/${t.id}`, requireStepUp, StepUpOps.DisableSpace, t.id);
                load();
            },
        });
    };

    return (
        <DetailPage
            breadcrumbs={[{ label: 'Spaces', to: '/spaces' }, { label: t.name }]}
            title={t.name}
            status={<StatusBadge status={t.isEnabled !== false ? 'active' : 'disabled'} label={t.isEnabled !== false ? 'Enabled' : 'Disabled'} />}
            subtitle={t.description || undefined}
            backTo="/spaces"
            editable
            initialMode={hash === `#${KEY_CEREMONIES_ANCHOR}` ? 'edit' : 'view'}
            onSave={handleSave}
            onCancel={resetEdits}
            saveDisabled={!anyDirty || quorumInvalid}
            actions={
                <div className="flex items-center gap-2 flex-wrap">
                    {t.isEnabled !== false
                        ? <button onClick={toggleEnabled} className="px-3 py-1.5 text-xs bg-warn-soft text-warn border border-warn/40 rounded hover:bg-warn/15 hover:text-warn transition-colors">Disable</button>
                        : <button onClick={toggleEnabled} className="px-3 py-1.5 text-xs bg-ok-soft text-ok border border-ok/40 rounded hover:bg-ok/15 hover:text-ok transition-colors">Enable</button>}
                </div>
            }
        >
            {(mode) => (<>
                <DetailSection title="Space Ceilings">
                    {mode === 'edit' ? (
                        <div className="space-y-3">
                            <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                                <div><label className={labelCls}>Description</label>
                                    <input value={form.description} onChange={(e) => setForm({ ...form, description: e.target.value })} className={numInput} /></div>
                                <div>
                                    <label className={labelCls}>Max Cert Validity (days, 0 = unlimited)</label>
                                    <input inputMode="numeric" value={form.maxValidityDays} onChange={(e) => setForm({ ...form, maxValidityDays: parseInt(e.target.value.replace(/[^0-9]/g, '') || '0', 10) })} className={numInput} />
                                    <p className="text-[11px] text-ink-muted mt-1">Infrastructure and CA certificates are exempt from this ceiling.</p>
                                </div>
                                <div>
                                    <label className={labelCls}>When a request exceeds the ceiling</label>
                                    <select value={form.validityCeilingBehavior}
                                        onChange={(e) => setForm({ ...form, validityCeilingBehavior: e.target.value as ValidityCeilingBehavior })}
                                        className={numInput}>
                                        <option value="Shorten">Shorten it (warn with MCA-ISS-004)</option>
                                        <option value="Refuse">Refuse it (MCA-ISS-005)</option>
                                    </select>
                                    <p className="text-[11px] text-ink-muted mt-1">
                                        Refuse governs admin and interactive issuance only. ACME, EST, SCEP and CMP enrollments and automatic renewals <strong>always shorten</strong>, whatever this is set to — an enrolling client can neither see this ceiling nor change its own request, so refusing it would fail enrollments nobody at the other end can fix.
                                    </p>
                                </div>
                            </div>
                        </div>
                    ) : (
                        <div className="grid grid-cols-1 md:grid-cols-2 gap-x-8">
                            <DetailField label="ID" value={t.id} mono />
                            <DetailField label="Description" value={t.description || '-'} />
                            <DetailField label="Max Cert Validity" value={t.maxValidityDays ? `${t.maxValidityDays} days` : 'Unlimited'} />
                            <DetailField label="Over the ceiling" value={t.maxValidityDays
                                ? (t.validityCeilingBehavior === 'Refuse'
                                    ? 'Refuse admin requests (protocol enrollments still shorten)'
                                    : 'Shorten and warn')
                                : 'n/a — no ceiling set'} />
                            <DetailField label="Created" value={formatDate(t.createdAt)} />
                        </div>
                    )}
                </DetailSection>

                <div id={KEY_CEREMONIES_ANCHOR} className="scroll-mt-4">
                    <DetailSection title="Key Ceremonies">
                        <div className="space-y-3">
                            <p className="text-xs text-ink-muted">
                                A key ceremony makes other administrators approve before a CA of this space is created or revoked.
                                Whoever starts one can never approve it, so it needs at least one other administrator who can approve.
                                The instance&apos;s own CAs have a separate switch in <Link to={INSTANCE_CEREMONY_SETTINGS_PATH} className="underline">Settings</Link>.
                            </p>
                            {mode === 'edit' ? (
                                <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                                    <div className="flex items-center gap-2 pt-2">
                                        <input type="checkbox" id={`cer-${t.id}`} checked={form.requireKeyCeremony}
                                            onChange={(e) => setForm({ ...form, requireKeyCeremony: e.target.checked })}
                                            className="h-4 w-4 rounded border-line-strong text-accent-ink focus:ring-accent" />
                                        <label htmlFor={`cer-${t.id}`} className="text-xs text-ink">Require key ceremonies for this space&apos;s CAs</label>
                                    </div>
                                    {form.requireKeyCeremony && (
                                        <div><label className={labelCls}>Approvals required</label>
                                            <input inputMode="numeric" value={form.ceremonyRequiredApprovals}
                                                onChange={(e) => setForm({ ...form, ceremonyRequiredApprovals: parseInt(e.target.value.replace(/\D/g, '') || '1', 10) || 1 })} className={numInput} />
                                            <FieldHint>Approvals from other administrators before a key ceremony may execute. The initiator is always excluded, so the effective minimum is 1 other approver.</FieldHint>
                                        </div>
                                    )}
                                </div>
                            ) : (
                                <DetailField label="Required" value={t.requireKeyCeremony ? `Yes (${t.ceremonyRequiredApprovals} approval${t.ceremonyRequiredApprovals === 1 ? '' : 's'} from others; the initiator is never counted)` : 'No. Switch to Edit to turn it on.'} />
                            )}
                            {ceremonyWarning && (
                                <div role="alert" className="bg-warn-soft border border-warn/40 rounded p-3 text-xs text-warn">
                                    {ceremonyWarning}{' '}
                                    <Link to={USERS_PATH} className="underline font-medium">Add an administrator</Link>
                                </div>
                            )}
                            {mode === 'edit' && ceremonyPolicyDirty && (
                                <div className="bg-warn-soft border border-warn/40 rounded p-3 text-xs text-warn">
                                    {user?.isSuper
                                        ? (downgrade
                                            ? 'This lowers the space’s security policy. As a system super-administrator your change applies directly, after an MFA check.'
                                            : 'As a system super-administrator your change applies directly.')
                                        : `Saving opens a policy-change ceremony that needs ${t.ceremonyRequiredApprovals} approval${t.ceremonyRequiredApprovals === 1 ? '' : 's'} from other administrators of this space before it takes effect.`}
                                </div>
                            )}
                        </div>
                    </DetailSection>
                </div>

                <div className="space-y-3">
                    <div>
                        <h3 className="text-sm font-semibold text-ink">Per-CA Issuance Quotas <span className="text-ink-muted font-normal">({cas.length})</span></h3>
                        <p className="text-xs text-ink-muted mt-1">
                            Per-CA certificate issuance ceilings (0 = unlimited).{mode === 'view' ? ' Switch to Edit to change.' : ' Edit values and use Save above.'}
                        </p>
                    </div>
                    {cas.length === 0 ? (
                        <div className="py-3 text-xs text-ink-muted text-center border border-line rounded-lg">No CAs in this space</div>
                    ) : (
                        <div className="border border-line rounded-lg overflow-hidden">
                            <div className="px-3 py-2 border-b border-line grid grid-cols-[1fr_70px_70px_70px_150px_70px_70px] gap-2 text-[10px] text-ink-muted font-semibold uppercase tracking-wide bg-sunken">
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
                        <h3 className="text-sm font-semibold text-ink">User Approval Quorum</h3>
                        <p className="text-xs text-ink-muted mt-1">
                            Approvals required to promote/demote/delete a privileged user in this space and its CAs. Inherits from the System quorum; a CA may require fewer than its space, never more.{mode === 'view' ? ' Switch to Edit to change.' : ''}
                        </p>
                    </div>
                    <SpaceUserQuorumSection
                        quorum={quorum} readOnly={mode === 'view'}
                        spaceValue={spaceQuorum} onSpaceChange={setSpaceQuorum}
                        caValues={caQuorum} onCaChange={(caId, s) => setCaQuorum((prev) => ({ ...prev, [caId]: s }))} />
                    {mode === 'edit' && quorumInvalid && (
                        <p className="text-xs text-crit">A CA quorum can't exceed its space's effective quorum ({quorum?.effective}). Fix the highlighted value to enable Save.</p>
                    )}
                </div>

                <div id={SPACE_REALMS_ANCHOR} className="scroll-mt-4">
                    <KerberosRealmsPanel spaceId={t.id} spaceName={t.name} caLabels={cas.filter((c) => !c.isSshCa && c.label).map((c) => c.label!)} />
                </div>

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

export default SpaceDetail;
