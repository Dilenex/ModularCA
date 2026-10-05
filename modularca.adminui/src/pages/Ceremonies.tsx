import React, { useState, useEffect, useCallback } from 'react';
import type { NoticeInput } from '@shared/notifications/notice';
import { errorNotice } from '@shared-auth/api/notices';
import { InlineNotice } from '@shared/components/InlineNotice';
import { Drawer } from '@shared/components/Drawer';
import { Link, useLocation, useNavigate, useParams } from 'react-router-dom';
import { CEREMONIES_PATH, ceremonyPath } from './ceremonyLinks';
import { apiGet, apiPostWithMfa, apiDeleteWithMfa } from '../api/client';
import { useStepUp } from '../components/StepUpMfaContext';
import { useToast } from '@shared/context/ToastContext';
import { StatusBadge } from '@shared/components/cards/StatusBadge';
import { DetailField } from '@shared/components/cards/DetailField';
import ConfirmModal from '../components/ConfirmModal';
import TemporaryPasswordModal from '../components/TemporaryPasswordModal';
import { DataTable, DataTableColumn, DataTableBulkAction } from '@shared/components/DataTable';
import { StepUpOps } from '@shared/generated';
import { FieldHint } from '@shared/components/forms';

const APPROVALS_HINT = 'Approvals collected / required. The initiator is never counted.';

function formatDate(d: string | null) {
    if (!d) return '-';
    return new Date(d).toLocaleDateString('en-US', { year: 'numeric', month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' });
}

type CeremonyStatus = 'Pending' | 'Approved' | 'Rejected' | 'Executed' | 'Expired' | 'Cancelled';

function ceremonyBadgeStatus(status: CeremonyStatus): 'expired' | 'active' | 'revoked' | 'pending' | 'disabled' {
    switch (status) {
        case 'Pending': return 'expired';
        case 'Approved': return 'active';
        case 'Rejected': return 'revoked';
        case 'Executed': return 'pending';
        case 'Expired': return 'disabled';
        case 'Cancelled': return 'disabled';
        default: return 'disabled';
    }
}

type Family = 'CaCreation' | 'PolicyChange' | 'ControlledUserChange';

function ceremonyFamily(c: any): Family {
    const ct = c?.ceremonyType;
    // The instance's policy changes (no space) belong to the same family as a space's.
    if (ct === 'SpacePolicyChange' || ct === 'InstancePolicyChange'
        || c?.operationType === 'SpacePolicyChange' || c?.operationType === 'InstancePolicyChange') return 'PolicyChange';
    if (ct === 'ControlledUserChange' || c?.operationType === 'ControlledUserChange') return 'ControlledUserChange';
    return 'CaCreation';
}

const FAMILY_META: Record<Family, { label: string; cls: string }> = {
    CaCreation: { label: 'CA', cls: 'bg-info-soft text-info border-info/40' },
    PolicyChange: { label: 'Policy', cls: 'bg-warn-soft text-warn border-warn/40' },
    ControlledUserChange: { label: 'Controlled User', cls: 'bg-accent-soft text-accent-ink border-accent/40' },
};

const TIER_LABELS: Record<number, string> = {
    2: 'CA Admin', 3: 'System Admin', 4: 'System Super', 5: 'Space Operator', 6: 'Space Admin', 7: 'System Operator',
};

/* the scope of a controlled-user ceremony's affected tier, as the server names it (CA label,
   space name or instance); the raw ids only if the server did not name it */
function tierScope(detail: any, params: any): string {
    if (detail?.tierScope) return detail.tierScope === 'instance' ? ' (instance)' : ` (${detail.tierScope})`;
    const caId = params.mintedTierCaId || params.MintedTierCaId;
    if (caId) return ` (CA ${caId})`;
    const spaceId = params.mintedTierSpaceId || params.MintedTierSpaceId;
    return spaceId ? ` (space ${spaceId})` : ' (instance)';
}

function controlledChangeLabel(changeType: string): string {
    switch (changeType) {
        case 'GrantCapability': return 'Promote — grant capability';
        case 'AssignRole': return 'Promote — assign role';
        case 'AddGroupMember': return 'Promote — add to group';
        case 'RevokeCapability': return 'Demote — revoke capability';
        case 'UnassignRole': return 'Demote — unassign role';
        case 'RemoveGroupMember': return 'Demote — remove from group';
        case 'DeleteUser': return 'Delete user';
        case 'ResetPassword': return 'Account — reset password';
        case 'ResetMfa': return 'Account — reset MFA';
        case 'UpdateIdentity': return 'Account — change identity or state';
        default: return changeType || '-';
    }
}

/* the fields an UpdateIdentity change sets, for the drawer */
function identityChanges(identity: any): { label: string; value: string }[] {
    if (!identity) return [];
    const get = (k: string) => identity[k] ?? identity[k.charAt(0).toUpperCase() + k.slice(1)];
    const yesNo = (v: any) => (v ? 'Yes' : 'No');
    const rows: { label: string; value: string }[] = [];
    const add = (label: string, k: string, fmt: (v: any) => string = String) => { const v = get(k); if (v !== null && v !== undefined) rows.push({ label, value: fmt(v) }); };
    add('Username', 'username');
    add('Email', 'email');
    add('First name', 'firstName');
    add('Last name', 'lastName');
    add('Display name', 'displayName');
    add('Enabled', 'isActive', yesNo);
    add('Locked', 'isLocked', yesNo);
    add('Password never expires', 'passwordNeverExpires', yesNo);
    add('Change password at next logon', 'passwordChangeOnNextLogon', yesNo);
    return rows;
}

const parseJson = (json: string | null): any => { if (!json) return null; try { return JSON.parse(json); } catch { return null; } };

const WARNING_PREFIX = 'WARNING: ';

/* the server leads a description with "WARNING: " lines for approvers, such as a recent password
   or MFA reset of the account a promotion raises; split them from the description itself */
function splitDescription(c: any): { text: string; warnings: string[] } {
    const lines = String(c?.description || '').split('\n');
    const warnings = lines.filter((l) => l.startsWith(WARNING_PREFIX)).map((l) => l.slice(WARNING_PREFIX.length));
    const text = lines.filter((l) => !l.startsWith(WARNING_PREFIX)).join(' ').trim();
    return { text: text || c?.operationType || '', warnings };
}

const CeremonyWarnings: React.FC<{ warnings: string[]; className?: string }> = ({ warnings, className = '' }) => warnings.length === 0 ? null : (
    <div role="alert" className={`bg-warn-soft border border-warn/40 rounded p-3 text-xs text-warn space-y-1 ${className}`}>
        {warnings.map((w, i) => <p key={i} className="font-semibold">{w}</p>)}
    </div>
);

/* ── read-only detail drawer (fetches full ceremony by id) ─────────────────── */
const CeremonyDrawer: React.FC<{ ceremony: any }> = ({ ceremony }) => {
    const [detail, setDetail] = useState<any | null>(null);
    const [loading, setLoading] = useState(true);

    useEffect(() => {
        let cancelled = false;
        setLoading(true);
        apiGet<any>(`/api/v1/admin/ceremonies/${ceremony.id}`)
            .then((d) => { if (!cancelled) setDetail(d); })
            .catch(() => { if (!cancelled) setDetail(null); })
            .finally(() => { if (!cancelled) setLoading(false); });
        return () => { cancelled = true; };
    }, [ceremony.id]);

    const family = ceremonyFamily(ceremony);
    const params = parseJson(detail?.parametersJson);
    const approvalLog = (parseJson(detail?.approvalsJson || ceremony.approvalsJson) as any[]) || [];
    const { text, warnings } = splitDescription(ceremony);
    const approvalRefusal: string | null = ceremony.status === 'Pending' ? (detail?.approvalRefusal ?? ceremony.approvalRefusal ?? null) : null;

    return (
        <div className="text-sm space-y-4">
            <CeremonyWarnings warnings={warnings} />
            {approvalRefusal && (
                <div className="bg-raised border border-line rounded p-3 text-xs text-ink">
                    <span className="font-semibold">You cannot approve this ceremony.</span> {approvalRefusal}
                </div>
            )}
            <div>
                <DetailField label="Type" value={FAMILY_META[family].label} />
                <DetailField label="Operation" value={ceremony.operationType} />
                <DetailField label="Description" value={text} />
                <DetailField label="Status" value={ceremony.status} />
                <DetailField label="Initiator" value={ceremony.initiatedByUsername || '-'} />
                <DetailField label="Approvals" value={`${ceremony.currentApprovals ?? 0} / ${ceremony.requiredApprovals ?? '-'}`} />
                <FieldHint className="-mt-1 mb-1">{APPROVALS_HINT}</FieldHint>
                <DetailField label="Created" value={formatDate(ceremony.createdAt)} />
                <DetailField label="Expires" value={formatDate(ceremony.expiresAt)} />
                {ceremony.executedAt && <DetailField label="Executed" value={formatDate(ceremony.executedAt)} />}
                <DetailField label="ID" value={ceremony.id} mono />
            </div>

            {loading && <div className="text-xs text-ink-muted">Loading details…</div>}

            {params && family === 'ControlledUserChange' && (
                <div>
                    <span className="text-xs font-semibold text-ink-muted">Controlled-User Change</span>
                    <DetailField label="Action" value={controlledChangeLabel(params.changeType || params.ChangeType)} />
                    <DetailField label="Target user" value={params.targetUsername || params.TargetUsername || params.targetUserId || params.TargetUserId || '-'} mono />
                    <DetailField label="Affected tier" value={`${TIER_LABELS[params.mintedTierLevel ?? params.MintedTierLevel] || '-'}` + tierScope(detail, params)} />
                    {(params.capability || params.Capability) && <DetailField label="Capability" value={params.capability || params.Capability} mono />}
                    {(params.roleId || params.RoleId) && <DetailField label="Role" value={params.roleId || params.RoleId} mono />}
                    {(params.groupId || params.GroupId) && <DetailField label="Group" value={params.groupId || params.GroupId} mono />}
                    {identityChanges(params.identity || params.Identity).map((row) => <DetailField key={row.label} label={row.label} value={row.value} />)}
                    {(params.changeType || params.ChangeType) === 'ResetPassword' && (
                        <FieldHint className="mt-1">The temporary password is generated when this is executed and shown once, to whoever executes it.</FieldHint>
                    )}
                </div>
            )}

            {params && family === 'PolicyChange' && (
                <div>
                    <span className="text-xs font-semibold text-ink-muted">Policy Change</span>
                    <DetailField label="Scope" value={params.spaceId || params.SpaceId || 'Instance'} mono={!!(params.spaceId || params.SpaceId)} />
                    {(() => {
                        const pReq = params.proposedRequireKeyCeremony ?? params.ProposedRequireKeyCeremony;
                        const cReq = params.currentRequireKeyCeremony ?? params.CurrentRequireKeyCeremony;
                        return (pReq === null || pReq === undefined) ? null : <DetailField label="Ceremony Required" value={`${cReq} → ${pReq}`} />;
                    })()}
                    {(() => {
                        const pA = params.proposedCeremonyRequiredApprovals ?? params.ProposedCeremonyRequiredApprovals;
                        const cA = params.currentCeremonyRequiredApprovals ?? params.CurrentCeremonyRequiredApprovals;
                        return (pA === null || pA === undefined) ? null : <DetailField label="Required Approvals" value={`${cA} → ${pA}`} />;
                    })()}
                </div>
            )}

            {params && family === 'CaCreation' && (
                <div>
                    <span className="text-xs font-semibold text-ink-muted">CA Parameters</span>
                    <DetailField label="Common Name" value={params.subjectCN || params.SubjectCN || '-'} />
                    <DetailField label="Algorithm" value={params.keyAlgorithm || params.KeyAlgorithm || '-'} />
                    <DetailField label="Key Size" value={params.keySize || params.KeySize || '-'} />
                    <DetailField label="Validity (Years)" value={params.validityYears || params.ValidityYears || '-'} />
                    <DetailField label="Space ID" value={params.spaceId || params.SpaceId || 'Instance'} mono={!!(params.spaceId || params.SpaceId)} />
                    {(params.parentCaId || params.ParentCaId) && <DetailField label="Parent CA ID" value={params.parentCaId || params.ParentCaId} mono />}
                    {(params.label || params.Label) && <DetailField label="Label" value={params.label || params.Label} />}
                </div>
            )}

            {approvalLog.length > 0 && (
                <div>
                    <h4 className="text-xs text-ink-muted font-semibold mb-2">Approval Log</h4>
                    <div className="space-y-1">
                        {approvalLog.map((entry: any, idx: number) => (
                            <div key={idx} className="flex items-center gap-3 py-1 px-2 bg-raised rounded text-xs">
                                <StatusBadge status={entry.action === 'Approved' ? 'active' : entry.action === 'Rejected' ? 'revoked' : 'disabled'} label={entry.action || entry.type} />
                                <span className="text-ink">{entry.Username || entry.userName || entry.user || '-'}</span>
                                <span className="text-ink-muted ml-auto">{formatDate(entry.timestamp || entry.date)}</span>
                            </div>
                        ))}
                    </div>
                </div>
            )}

            <p className="text-[11px] text-ink-muted">Select this ceremony in the table to approve, reject, cancel, or execute.</p>
        </div>
    );
};

const Ceremonies: React.FC = () => {
    const { requireStepUp } = useStepUp();
    const { showToast } = useToast();
    const [ceremonies, setCeremonies] = useState<any[]>([]);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState<NoticeInput | null>(null);
    const [refreshTrigger, setRefreshTrigger] = useState(0);
    // `confirmClass` distinguishes the destructive confirmations (Reject, Cancel: red) from the
    // affirmative ones added for Approve and Execute, which used to fire with no confirmation at
    // all while the harmless actions had one.
    const [confirmAction, setConfirmAction] = useState<{ action: () => Promise<void>; title: string; message: React.ReactNode; confirmLabel: string; confirmClass?: string } | null>(null);
    const [confirmLoading, setConfirmLoading] = useState(false);
    const [currentUserId, setCurrentUserId] = useState<string | null>(null);
    const [temporaryPassword, setTemporaryPassword] = useState<string | null>(null);

    const [filterStatus, setFilterStatus] = useState<'mine' | 'pending' | 'all'>('mine');
    const [filterType, setFilterType] = useState<'all' | Family>('all');

    // `/ceremonies/:id` opens that ceremony's drawer; closing it returns to `/ceremonies`.
    const { id: openId } = useParams<{ id?: string }>();
    const navigate = useNavigate();
    const location = useLocation();
    const [linked, setLinked] = useState<any | null>(null);
    const [linkedError, setLinkedError] = useState<NoticeInput | null>(null);
    const openRow = (c: any) => navigate({ pathname: ceremonyPath(c.id), search: location.search });
    const closeDrawer = () => navigate({ pathname: CEREMONIES_PATH, search: location.search });

    const fetchCeremonies = useCallback(async () => {
        try {
            const data = await apiGet<any>('/api/v1/admin/ceremonies');
            setCeremonies(Array.isArray(data) ? data : (data.items || data.ceremonies || []));
        } catch (err: any) {
            setError(errorNotice(err, 'Failed to load ceremonies'));
        } finally {
            setLoading(false);
        }
    }, []);

    useEffect(() => {
        setLoading(true);
        setError(null);
        fetchCeremonies();
        apiGet<any>('/api/v1/account').then((me) => setCurrentUserId(me?.id || me?.userId || null)).catch(() => {});
    }, [refreshTrigger, fetchCeremonies]);

    useEffect(() => {
        const hasPending = ceremonies.some((c) => c.status === 'Pending');
        if (!hasPending) return;
        const interval = setInterval(() => fetchCeremonies(), 30000);
        return () => clearInterval(interval);
    }, [ceremonies, fetchCeremonies]);

    const primaryConfirmClass = 'px-4 py-2 text-sm bg-accent text-on-accent rounded hover:bg-accent-hover transition-colors';
    const executeConfirmClass = 'px-4 py-2 text-sm bg-ok text-on-accent rounded hover:bg-ok-hover transition-colors';

    const handleApprove = (ceremony: any) => {
        const { text, warnings } = splitDescription(ceremony);
        setConfirmAction({
            title: 'Approve Ceremony',
            message: (
                <>
                    <CeremonyWarnings warnings={warnings} className="mb-2" />
                    <p>Approve &ldquo;{text}&rdquo;?</p>
                    <p className="mt-2">You are one of the approvers of record for this ceremony; your approval is audited under your name.</p>
                </>
            ),
            confirmLabel: 'Approve',
            confirmClass: primaryConfirmClass,
            action: async () => {
                await apiPostWithMfa(`/api/v1/admin/ceremonies/${ceremony.id}/approve`, {}, requireStepUp, StepUpOps.ApproveCeremony, ceremony.id);
                showToast('success', 'Ceremony approved.');
                setRefreshTrigger((t) => t + 1);
            },
        });
    };

    const handleReject = (ceremony: any) => {
        setConfirmAction({
            title: 'Reject Ceremony',
            message: `Reject "${splitDescription(ceremony).text}"? This is permanent.`,
            confirmLabel: 'Reject',
            action: async () => {
                await apiPostWithMfa(`/api/v1/admin/ceremonies/${ceremony.id}/reject`, {}, requireStepUp, StepUpOps.RejectCeremony, ceremony.id);
                showToast('success', 'Ceremony rejected.');
                setRefreshTrigger((t) => t + 1);
            },
        });
    };

    const handleCancel = (ceremony: any) => {
        setConfirmAction({
            title: 'Cancel Ceremony',
            message: `Cancel "${splitDescription(ceremony).text}"? This cannot be undone.`,
            confirmLabel: 'Cancel Ceremony',
            action: async () => {
                await apiDeleteWithMfa(`/api/v1/admin/ceremonies/${ceremony.id}`, requireStepUp, StepUpOps.CancelCeremony, ceremony.id);
                showToast('success', 'Ceremony cancelled.');
                setRefreshTrigger((t) => t + 1);
            },
        });
    };

    const handleExecute = (ceremony: any) => {
        // Only a CA-creation ceremony generates keys; the other two families apply a policy or
        // user change. The irreversibility is the same for all three.
        const isCa = ceremonyFamily(ceremony) === 'CaCreation';
        const { text, warnings } = splitDescription(ceremony);
        setConfirmAction({
            title: 'Execute Ceremony',
            message: (
                <>
                    <CeremonyWarnings warnings={warnings} className="mb-2" />
                    <p>Execute &ldquo;{text}&rdquo;?</p>
                    <p className="mt-2">
                        {isCa
                            ? 'This generates the CA’s key pair now. It cannot be re-run; a mistake means a new ceremony.'
                            : 'This applies the approved change now. It cannot be re-run; a mistake means a new ceremony.'}
                    </p>
                    {ceremonyFamily(ceremony) === 'ControlledUserChange' && (
                        <p className="mt-2">A password reset shows its temporary password to you once, when it executes. It is not stored and cannot be shown again.</p>
                    )}
                </>
            ),
            confirmLabel: 'Execute',
            confirmClass: executeConfirmClass,
            action: async () => {
                const result = await apiPostWithMfa<any>(`/api/v1/admin/ceremonies/${ceremony.id}/execute`, {}, requireStepUp, StepUpOps.ExecuteCeremony, ceremony.id);
                if (result?.temporaryPassword) setTemporaryPassword(result.temporaryPassword);
                showToast('success', result?.message || 'Ceremony executed successfully.');
                setRefreshTrigger((t) => t + 1);
            },
        });
    };

    const isInitiator = (c: any) =>
        !!currentUserId && (c.initiatedByUserId === currentUserId || c.initiatorId === currentUserId || c.initiatedBy === currentUserId);
    const isApproverOrInitiator = (c: any) => {
        if (isInitiator(c)) return true;
        if (!currentUserId) return false;
        return !!(c.approvalsJson && c.approvalsJson.includes(currentUserId));
    };
    const canExecute = (c: any) => c.status === 'Approved' && isApproverOrInitiator(c);
    const needsMyAction = (c: any) => !!c.canApprove || canExecute(c);

    const filtered = ceremonies.filter((c) => {
        if (filterType !== 'all' && ceremonyFamily(c) !== filterType) return false;
        if (filterStatus === 'pending') return c.status === 'Pending';
        if (filterStatus === 'mine') return needsMyAction(c);
        return true;
    });
    const mineCount = ceremonies.filter(needsMyAction).length;

    const listed = openId ? ceremonies.find((c) => c.id === openId) ?? null : null;
    const opened = listed ?? linked;

    // A linked ceremony missing from the list (not loaded yet, or not returned) is fetched by id.
    useEffect(() => {
        setLinked(null);
        setLinkedError(null);
        if (!openId || loading || listed) return;
        let cancelled = false;
        apiGet<any>(`/api/v1/admin/ceremonies/${encodeURIComponent(openId)}`)
            .then((d) => { if (!cancelled) setLinked(d); })
            .catch((err) => { if (!cancelled) setLinkedError(errorNotice(err, 'Failed to load the ceremony')); });
        return () => { cancelled = true; };
    }, [openId, loading, !!listed]); // eslint-disable-line react-hooks/exhaustive-deps

    // Widen the filters once when the linked ceremony is listed but filtered out, so it can be selected to act on.
    useEffect(() => {
        if (listed && !filtered.some((c) => c.id === listed.id)) { setFilterStatus('all'); setFilterType('all'); }
    }, [listed?.id]); // eslint-disable-line react-hooks/exhaustive-deps
    const pendingCount = ceremonies.filter((c) => c.status === 'Pending').length;

    const segBtn = (active: boolean) =>
        `px-3 py-1.5 text-xs font-medium rounded border transition-colors ${active
            ? 'bg-accent text-on-accent border-accent'
            : 'bg-raised text-ink border-line hover:bg-hover'}`;

    const columns: DataTableColumn<any>[] = [
        { key: 'description', header: 'Description', defaultWidth: 300, minWidth: 200, exportValue: (c) => c.description || c.operationType,
            render: (c) => {
                const { text, warnings } = splitDescription(c);
                return (
                    <span className="inline-flex items-center gap-2">
                        {warnings.length > 0 && (
                            <span title={warnings.join('\n')} className="inline-block px-1.5 py-0.5 text-[10px] font-semibold rounded border bg-warn-soft text-warn border-warn/40">Warning</span>
                        )}
                        <span className="font-medium text-ink">{text}</span>
                    </span>
                );
            } },
        { key: 'type', header: 'Type', defaultWidth: 130, truncate: false, exportValue: (c) => FAMILY_META[ceremonyFamily(c)].label,
            render: (c) => <span className={`inline-block px-2 py-0.5 text-[10px] font-semibold rounded border w-fit ${FAMILY_META[ceremonyFamily(c)].cls}`}>{FAMILY_META[ceremonyFamily(c)].label}</span> },
        { key: 'status', header: 'Status', defaultWidth: 120, truncate: false, exportValue: (c) => c.status,
            render: (c) => <StatusBadge status={ceremonyBadgeStatus(c.status)} label={c.status} /> },
        { key: 'approvals', header: 'Approvals', defaultWidth: 100, align: 'right', headerTitle: APPROVALS_HINT, exportValue: (c) => `${c.currentApprovals ?? 0}/${c.requiredApprovals ?? '-'}`,
            render: (c) => <span className="text-ink-muted" title={APPROVALS_HINT}>{c.currentApprovals ?? 0} / {c.requiredApprovals ?? '-'}</span> },
        { key: 'initiator', header: 'Initiator', defaultWidth: 140, exportValue: (c) => c.initiatedByUsername || '',
            render: (c) => c.initiatedByUsername || '-' },
        { key: 'created', header: 'Created', defaultWidth: 150, exportValue: (c) => c.createdAt, render: (c) => formatDate(c.createdAt) },
    ];

    const bulkActions: DataTableBulkAction<any>[] = [
        { label: 'Approve', single: true, variant: 'primary', enabledFor: (c) => !!c.canApprove, onClick: (rows) => handleApprove(rows[0]) },
        { label: 'Execute', single: true, variant: 'primary', enabledFor: (c) => canExecute(c), onClick: (rows) => handleExecute(rows[0]) },
        { label: 'Reject', single: true, variant: 'danger', enabledFor: (c) => c.status === 'Pending' && (!!c.canApprove || isInitiator(c)), onClick: (rows) => handleReject(rows[0]) },
        { label: 'Cancel', single: true, enabledFor: (c) => c.status === 'Pending' && isInitiator(c), onClick: (rows) => handleCancel(rows[0]) },
    ];

    return (
        <div className="p-3 sm:p-6 space-y-4 sm:space-y-6">
            <h1 className="text-xl font-semibold text-ink">Ceremonies</h1>

            <div className="bg-info-soft border border-info/40 rounded-lg p-4 text-xs text-info">
                Ceremonies are created automatically when a multi-party action is required — you don't start one here.
                They originate from <Link to="/authorities/manage" className="underline">CA Management</Link> (CA creation/revocation),
                Space settings (security-policy downgrades), and the <Link to="/users" className="underline">User &amp; Access</Link> pages
                (promoting, demoting, or deleting a controlled user, or resetting their password or MFA or changing their account,
                as a non-super). Select one below to approve or reject.
            </div>

            <div className="flex flex-wrap items-center gap-3">
                <div className="flex gap-1">
                    <button className={segBtn(filterStatus === 'mine')} onClick={() => setFilterStatus('mine')}>Needs my action ({mineCount})</button>
                    <button className={segBtn(filterStatus === 'pending')} onClick={() => setFilterStatus('pending')}>Pending ({pendingCount})</button>
                    <button className={segBtn(filterStatus === 'all')} onClick={() => setFilterStatus('all')}>All</button>
                </div>
                <select value={filterType} onChange={(e) => setFilterType(e.target.value as any)}
                    className="px-3 py-1.5 text-xs bg-raised border border-line-strong rounded text-ink focus:outline-none focus:border-accent">
                    <option value="all">All types</option>
                    <option value="CaCreation">CA</option>
                    <option value="PolicyChange">Policy (space or instance)</option>
                    <option value="ControlledUserChange">Controlled User</option>
                </select>
            </div>

            <DataTable<any>
                tableId="ceremonies"
                title="Ceremonies"
                rows={filtered}
                rowKey={(c) => c.id}
                loading={loading}
                error={error}
                empty={filterStatus === 'mine' ? 'Nothing needs your action right now.' : 'No ceremonies found.'}
                columns={columns}
                selectable
                bulkActions={bulkActions}
                exportFileName="ceremonies"
                onRowClick={openRow}
            />

            <Drawer open={!!openId} onClose={closeDrawer} title={opened ? splitDescription(opened).text : 'Ceremony'}>
                {opened
                    ? <CeremonyDrawer ceremony={opened} />
                    : linkedError
                        ? <InlineNotice notice={linkedError} />
                        : <div className="text-xs text-ink-muted">Loading…</div>}
            </Drawer>

            <ConfirmModal
                isOpen={!!confirmAction}
                title={confirmAction?.title || ''}
                message={confirmAction?.message || ''}
                confirmLabel={confirmAction?.confirmLabel || 'Confirm'}
                confirmClass={confirmAction?.confirmClass || 'px-4 py-2 text-sm bg-crit text-on-accent rounded hover:bg-crit-hover transition-colors'}
                loading={confirmLoading}
                onConfirm={async () => {
                    if (!confirmAction) return;
                    setConfirmLoading(true);
                    try {
                        await confirmAction.action();
                    } catch (err: any) {
                        if (err.message !== 'Step-up MFA cancelled') showToast('error', err.message || 'Action failed');
                    } finally {
                        setConfirmLoading(false);
                        setConfirmAction(null);
                    }
                }}
                onCancel={() => setConfirmAction(null)}
            />
            <TemporaryPasswordModal password={temporaryPassword} onClose={() => setTemporaryPassword(null)} />
        </div>
    );
};

export default Ceremonies;
