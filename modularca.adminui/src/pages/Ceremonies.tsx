import React, { useState, useEffect, useCallback } from 'react';
import type { NoticeInput } from '@shared/notifications/notice';
import { errorNotice } from '@shared-auth/api/notices';
import { Link } from 'react-router-dom';
import { apiGet, apiPostWithMfa, apiDeleteWithMfa } from '../api/client';
import { useStepUp } from '../components/StepUpMfaContext';
import { useToast } from '@shared/context/ToastContext';
import { StatusBadge } from '@shared/components/cards/StatusBadge';
import { DetailField } from '@shared/components/cards/DetailField';
import ConfirmModal from '../components/ConfirmModal';
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

type Family = 'CaCreation' | 'TenantPolicyChange' | 'ControlledUserChange';

function ceremonyFamily(c: any): Family {
    const ct = c?.ceremonyType;
    if (ct === 'TenantPolicyChange' || c?.operationType === 'TenantPolicyChange') return 'TenantPolicyChange';
    if (ct === 'ControlledUserChange' || c?.operationType === 'ControlledUserChange') return 'ControlledUserChange';
    return 'CaCreation';
}

const FAMILY_META: Record<Family, { label: string; cls: string }> = {
    CaCreation: { label: 'CA', cls: 'bg-blue-50 dark:bg-blue-900/50 text-blue-800 dark:text-blue-300 border-blue-300 dark:border-blue-700' },
    TenantPolicyChange: { label: 'Tenant Policy', cls: 'bg-amber-50 dark:bg-amber-900/50 text-amber-800 dark:text-amber-300 border-amber-300 dark:border-amber-700' },
    ControlledUserChange: { label: 'Controlled User', cls: 'bg-purple-50 dark:bg-purple-900/50 text-purple-800 dark:text-purple-300 border-purple-300 dark:border-purple-700' },
};

const TIER_LABELS: Record<number, string> = { 1: 'Operator', 2: 'CA Admin', 3: 'System Admin', 4: 'System Super' };

function controlledChangeLabel(changeType: string): string {
    switch (changeType) {
        case 'GrantCapability': return 'Promote — grant capability';
        case 'AssignRole': return 'Promote — assign role';
        case 'AddGroupMember': return 'Promote — add to group';
        case 'RevokeCapability': return 'Demote — revoke capability';
        case 'UnassignRole': return 'Demote — unassign role';
        case 'RemoveGroupMember': return 'Demote — remove from group';
        case 'DeleteUser': return 'Delete user';
        default: return changeType || '-';
    }
}

const parseJson = (json: string | null): any => { if (!json) return null; try { return JSON.parse(json); } catch { return null; } };

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

    return (
        <div className="text-sm space-y-4">
            <div>
                <DetailField label="Type" value={FAMILY_META[family].label} />
                <DetailField label="Operation" value={ceremony.operationType} />
                <DetailField label="Description" value={ceremony.description} />
                <DetailField label="Status" value={ceremony.status} />
                <DetailField label="Initiator" value={ceremony.initiatedByUsername || '-'} />
                <DetailField label="Approvals" value={`${ceremony.currentApprovals ?? 0} / ${ceremony.requiredApprovals ?? '-'}`} />
                <FieldHint className="-mt-1 mb-1">{APPROVALS_HINT}</FieldHint>
                <DetailField label="Created" value={formatDate(ceremony.createdAt)} />
                <DetailField label="Expires" value={formatDate(ceremony.expiresAt)} />
                {ceremony.executedAt && <DetailField label="Executed" value={formatDate(ceremony.executedAt)} />}
                <DetailField label="ID" value={ceremony.id} mono />
            </div>

            {loading && <div className="text-xs text-gray-500">Loading details…</div>}

            {params && family === 'ControlledUserChange' && (
                <div>
                    <span className="text-xs font-semibold text-gray-600 dark:text-gray-400">Controlled-User Change</span>
                    <DetailField label="Action" value={controlledChangeLabel(params.changeType || params.ChangeType)} />
                    <DetailField label="Target user" value={params.targetUsername || params.TargetUsername || params.targetUserId || params.TargetUserId || '-'} mono />
                    <DetailField label="Affected tier" value={`${TIER_LABELS[params.mintedTierLevel ?? params.MintedTierLevel] || '-'}` + ((params.mintedTierCaId || params.MintedTierCaId) ? ` (CA ${params.mintedTierCaId || params.MintedTierCaId})` : ' (system)')} />
                    {(params.capability || params.Capability) && <DetailField label="Capability" value={params.capability || params.Capability} mono />}
                    {(params.roleId || params.RoleId) && <DetailField label="Role" value={params.roleId || params.RoleId} mono />}
                    {(params.groupId || params.GroupId) && <DetailField label="Group" value={params.groupId || params.GroupId} mono />}
                </div>
            )}

            {params && family === 'TenantPolicyChange' && (
                <div>
                    <span className="text-xs font-semibold text-gray-600 dark:text-gray-400">Policy Change</span>
                    {(params.tenantId || params.TenantId) && <DetailField label="Tenant ID" value={params.tenantId || params.TenantId} mono />}
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
                    <span className="text-xs font-semibold text-gray-600 dark:text-gray-400">CA Parameters</span>
                    <DetailField label="Common Name" value={params.subjectCN || params.SubjectCN || '-'} />
                    <DetailField label="Algorithm" value={params.keyAlgorithm || params.KeyAlgorithm || '-'} />
                    <DetailField label="Key Size" value={params.keySize || params.KeySize || '-'} />
                    <DetailField label="Validity (Years)" value={params.validityYears || params.ValidityYears || '-'} />
                    <DetailField label="Tenant ID" value={params.tenantId || params.TenantId || '-'} mono />
                    {(params.parentCaId || params.ParentCaId) && <DetailField label="Parent CA ID" value={params.parentCaId || params.ParentCaId} mono />}
                    {(params.label || params.Label) && <DetailField label="Label" value={params.label || params.Label} />}
                </div>
            )}

            {approvalLog.length > 0 && (
                <div>
                    <h4 className="text-xs text-gray-600 dark:text-gray-400 font-semibold mb-2">Approval Log</h4>
                    <div className="space-y-1">
                        {approvalLog.map((entry: any, idx: number) => (
                            <div key={idx} className="flex items-center gap-3 py-1 px-2 bg-gray-100 dark:bg-gray-800 rounded text-xs">
                                <StatusBadge status={entry.action === 'Approved' ? 'active' : entry.action === 'Rejected' ? 'revoked' : 'disabled'} label={entry.action || entry.type} />
                                <span className="text-gray-700 dark:text-gray-300">{entry.Username || entry.userName || entry.user || '-'}</span>
                                <span className="text-gray-600 ml-auto">{formatDate(entry.timestamp || entry.date)}</span>
                            </div>
                        ))}
                    </div>
                </div>
            )}

            <p className="text-[11px] text-gray-500">Select this ceremony in the table to approve, reject, cancel, or execute.</p>
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

    const [filterStatus, setFilterStatus] = useState<'mine' | 'pending' | 'all'>('mine');
    const [filterType, setFilterType] = useState<'all' | Family>('all');

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

    const primaryConfirmClass = 'px-4 py-2 text-sm bg-blue-600 text-white rounded hover:bg-blue-700 transition-colors';
    const executeConfirmClass = 'px-4 py-2 text-sm bg-green-600 text-white rounded hover:bg-green-700 transition-colors';

    const handleApprove = (ceremony: any) => {
        setConfirmAction({
            title: 'Approve Ceremony',
            message: (
                <>
                    <p>Approve &ldquo;{ceremony.description || ceremony.operationType}&rdquo;?</p>
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
            message: `Reject "${ceremony.description || ceremony.operationType}"? This is permanent.`,
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
            message: `Cancel "${ceremony.description || ceremony.operationType}"? This cannot be undone.`,
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
        setConfirmAction({
            title: 'Execute Ceremony',
            message: (
                <>
                    <p>Execute &ldquo;{ceremony.description || ceremony.operationType}&rdquo;?</p>
                    <p className="mt-2">
                        {isCa
                            ? 'This generates the CA’s key pair now. It cannot be re-run; a mistake means a new ceremony.'
                            : 'This applies the approved change now. It cannot be re-run; a mistake means a new ceremony.'}
                    </p>
                </>
            ),
            confirmLabel: 'Execute',
            confirmClass: executeConfirmClass,
            action: async () => {
                const result = await apiPostWithMfa<any>(`/api/v1/admin/ceremonies/${ceremony.id}/execute`, {}, requireStepUp, StepUpOps.ExecuteCeremony, ceremony.id);
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
    const pendingCount = ceremonies.filter((c) => c.status === 'Pending').length;

    const segBtn = (active: boolean) =>
        `px-3 py-1.5 text-xs font-medium rounded border transition-colors ${active
            ? 'bg-blue-600 text-white border-blue-600'
            : 'bg-gray-100 dark:bg-gray-800 text-gray-700 dark:text-gray-300 border-gray-300 dark:border-gray-700 hover:bg-gray-200 dark:hover:bg-gray-700'}`;

    const columns: DataTableColumn<any>[] = [
        { key: 'description', header: 'Description', defaultWidth: 300, minWidth: 200, exportValue: (c) => c.description || c.operationType,
            render: (c) => <span className="font-medium text-gray-900 dark:text-white">{c.description || c.operationType}</span> },
        { key: 'type', header: 'Type', defaultWidth: 130, truncate: false, exportValue: (c) => FAMILY_META[ceremonyFamily(c)].label,
            render: (c) => <span className={`inline-block px-2 py-0.5 text-[10px] font-semibold rounded border w-fit ${FAMILY_META[ceremonyFamily(c)].cls}`}>{FAMILY_META[ceremonyFamily(c)].label}</span> },
        { key: 'status', header: 'Status', defaultWidth: 120, truncate: false, exportValue: (c) => c.status,
            render: (c) => <StatusBadge status={ceremonyBadgeStatus(c.status)} label={c.status} /> },
        { key: 'approvals', header: 'Approvals', defaultWidth: 100, align: 'right', headerTitle: APPROVALS_HINT, exportValue: (c) => `${c.currentApprovals ?? 0}/${c.requiredApprovals ?? '-'}`,
            render: (c) => <span className="text-gray-600 dark:text-gray-400" title={APPROVALS_HINT}>{c.currentApprovals ?? 0} / {c.requiredApprovals ?? '-'}</span> },
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
            <h1 className="text-2xl font-bold text-gray-900 dark:text-white">Ceremonies</h1>

            <div className="bg-blue-50 dark:bg-blue-900/20 border border-blue-300 dark:border-blue-800 rounded-lg p-4 text-xs text-blue-800 dark:text-blue-300">
                Ceremonies are created automatically when a multi-party action is required — you don't start one here.
                They originate from <Link to="/authorities/manage" className="underline">CA Management</Link> (CA creation/revocation),
                Tenant settings (security-policy downgrades), and the <Link to="/users" className="underline">User &amp; Access</Link> pages
                (promoting, demoting, or deleting a controlled user as a non-super). Select one below to approve or reject.
            </div>

            <div className="flex flex-wrap items-center gap-3">
                <div className="flex gap-1">
                    <button className={segBtn(filterStatus === 'mine')} onClick={() => setFilterStatus('mine')}>Needs my action ({mineCount})</button>
                    <button className={segBtn(filterStatus === 'pending')} onClick={() => setFilterStatus('pending')}>Pending ({pendingCount})</button>
                    <button className={segBtn(filterStatus === 'all')} onClick={() => setFilterStatus('all')}>All</button>
                </div>
                <select value={filterType} onChange={(e) => setFilterType(e.target.value as any)}
                    className="px-3 py-1.5 text-xs bg-gray-100 dark:bg-gray-800 border border-gray-300 dark:border-gray-700 rounded text-gray-900 dark:text-white focus:outline-none focus:border-blue-500">
                    <option value="all">All types</option>
                    <option value="CaCreation">CA</option>
                    <option value="TenantPolicyChange">Tenant Policy</option>
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
                renderDrawer={(c) => <CeremonyDrawer ceremony={c} />}
                drawerTitle={(c) => c.description || c.operationType}
            />

            <ConfirmModal
                isOpen={!!confirmAction}
                title={confirmAction?.title || ''}
                message={confirmAction?.message || ''}
                confirmLabel={confirmAction?.confirmLabel || 'Confirm'}
                confirmClass={confirmAction?.confirmClass || 'px-4 py-2 text-sm bg-red-600 text-white rounded hover:bg-red-700 transition-colors'}
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
        </div>
    );
};

export default Ceremonies;
