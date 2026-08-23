import React, { useEffect, useState } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { apiGet, apiPostWithMfa, apiPutWithMfa, apiDeleteWithMfa } from '../api/client';
import { useStepUp } from '../components/StepUpMfaContext';
import { useToast } from '../context/ToastContext';
import { useAuth } from '../context/AuthContext';
import StatusBadge from '../components/cards/StatusBadge';
import DetailField from '../components/cards/DetailField';
import ConfirmModal from '../components/ConfirmModal';
import { DetailPage, DetailSection } from '../components/DetailPage';
import { groupChipClass } from './Users';
import { StepUpOps } from '@shared/generated';

function formatDate(d: string | null) {
    if (!d) return '-';
    return new Date(d).toLocaleDateString('en-US', { year: 'numeric', month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' });
}

/// <summary>
/// Detail page for a single user: identity, group membership management (add/remove, ceremony-aware),
/// and guarded account actions (reset password, disable/enable, delete) in the action bar. The page is
/// View/Edit — Edit mode exposes the add/remove-group controls.
/// </summary>
const UserDetail: React.FC = () => {
    const { id } = useParams<{ id: string }>();
    const navigate = useNavigate();
    const { showToast } = useToast();
    const { requireStepUp } = useStepUp();
    const { user: currentUser } = useAuth();
    const currentUserId = currentUser?.id ?? null;

    const [user, setUser] = useState<any | null>(null);
    const [users, setUsers] = useState<any[]>([]);
    const [allGroups, setAllGroups] = useState<any[]>([]);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState<string | null>(null);
    const [refresh, setRefresh] = useState(0);

    // Staged bulk group edit: pending adds/removes applied together behind one step-up prompt.
    const [pendingAdd, setPendingAdd] = useState<string[]>([]);
    const [pendingRemove, setPendingRemove] = useState<string[]>([]);
    const [groupBusy, setGroupBusy] = useState(false);
    const [confirm, setConfirm] = useState<{ title: string; message: string; confirmLabel?: string; action: () => Promise<void> } | null>(null);
    const [confirmLoading, setConfirmLoading] = useState(false);

    useEffect(() => {
        let cancelled = false;
        setLoading(true);
        setError(null);
        Promise.all([
            apiGet<any>('/api/v1/admin/users'),
            apiGet<any>('/api/v1/admin/groups'),
        ]).then(([usersData, groupsData]) => {
            if (cancelled) return;
            const list = Array.isArray(usersData) ? usersData : (usersData.items || usersData.users || []);
            setUsers(list);
            setUser(list.find((u: any) => (u.id || u.username) === id) || null);
            setAllGroups(Array.isArray(groupsData) ? groupsData : (groupsData.items || groupsData.groups || []));
            setLoading(false);
        }).catch((err) => { if (!cancelled) { setError(err.message || 'Failed to load user'); setLoading(false); } });
        return () => { cancelled = true; };
    }, [id, refresh]);

    const toggleAdd = (gid: string) => setPendingAdd((p) => p.includes(gid) ? p.filter((x) => x !== gid) : [...p, gid]);
    const toggleRemove = (gid: string) => setPendingRemove((p) => p.includes(gid) ? p.filter((x) => x !== gid) : [...p, gid]);
    const resetStaging = () => { setPendingAdd([]); setPendingRemove([]); };

    // Apply all staged group changes in one step-up-gated batch; each privileged add/remove starts
    // its own controlled-user ceremony, uncontrolled changes apply directly.
    const applyGroupChanges = async () => {
        if (pendingAdd.length === 0 && pendingRemove.length === 0) return;
        setGroupBusy(true);
        try {
            const res: any = await apiPostWithMfa(`/api/v1/admin/users/${id}/groups/bulk`, { addGroupIds: pendingAdd, removeGroupIds: pendingRemove }, requireStepUp, StepUpOps.UpdateUserGroups, id!);
            const added = res?.added ?? 0, removed = res?.removed ?? 0, ceremonies = res?.ceremonies ?? 0, skipped = res?.skipped ?? 0;
            const parts = [
                added ? `${added} added` : '',
                removed ? `${removed} removed` : '',
                ceremonies ? `${ceremonies} ceremon${ceremonies === 1 ? 'y' : 'ies'} started` : '',
                skipped ? `${skipped} skipped` : '',
            ].filter(Boolean);
            const msg = parts.join(' · ') || 'No changes';
            showToast(ceremonies > 0 ? 'info' : 'success', ceremonies > 0 ? `${msg} — approve on the Ceremonies page.` : msg);
            setPendingAdd([]); setPendingRemove([]);
            setRefresh((r) => r + 1);
        } catch (err: any) {
            if (err.message !== 'Step-up MFA cancelled') showToast('error', err.message || 'Failed to update groups');
        } finally {
            setGroupBusy(false);
        }
    };

    const resetPassword = () => setConfirm({
        title: 'Reset Password', message: `Are you sure you want to reset the password for "${user.username}"?`, confirmLabel: 'Reset Password',
        action: async () => { await apiPostWithMfa(`/api/v1/admin/users/${id}/reset-password`, {}, requireStepUp, StepUpOps.ResetPassword, id!); showToast('success', 'Password reset initiated'); },
    });

    if (loading) return <div className="p-6 text-sm text-gray-600 dark:text-gray-400">Loading…</div>;
    if (error) return <div className="p-6 text-sm text-red-800 dark:text-red-400">{error}</div>;
    if (!user) return (
        <div className="p-6 space-y-3">
            <p className="text-sm text-gray-600 dark:text-gray-400">User not found.</p>
            <button onClick={() => navigate('/users')} className="px-3 py-1.5 text-sm bg-gray-200 dark:bg-gray-700 rounded">Back to Users</button>
        </div>
    );

    const userGroups: any[] = user.groups || [];
    const availableGroups = allGroups.filter((g: any) => !userGroups.some((ug: any) => ug.groupId === g.id));
    const isActive = user.isActive !== false && !user.isLocked;
    const isSelf = user.id === currentUserId;
    const isSuperGroup = userGroups.some((g: any) => (g.groupName || g.name) === 'system-super');
    const otherSystemAdminCount = users.filter((u: any) => u.id !== user.id && u.isActive !== false &&
        (u.groups || []).some((g: any) => { const n = g.groupName || g.name || ''; return n === 'system-admin' || n === 'system-super'; })).length;
    const canDisable = !isSelf && (!isSuperGroup || otherSystemAdminCount > 0);

    const disableAccount = () => {
        if (isSuperGroup && otherSystemAdminCount === 0) { showToast('warning', 'Cannot disable the super admin account — no other system admins exist. Create another system admin first.'); return; }
        const superWarning = isSuperGroup ? ' WARNING: This is a super admin account. Once disabled, it can ONLY be re-enabled via direct database access.' : '';
        setConfirm({
            title: 'Disable Account', message: `Disable user "${user.username}"? They will not be able to log in.${superWarning}`, confirmLabel: 'Disable',
            action: async () => { await apiPutWithMfa(`/api/v1/admin/users/${id}`, { isActive: false }, requireStepUp, StepUpOps.UpdateUser, id!); setRefresh((r) => r + 1); },
        });
    };
    const enableAccount = () => setConfirm({
        title: 'Enable Account', message: `Re-enable user "${user.username}"? They will be able to log in again.`, confirmLabel: 'Enable',
        action: async () => { await apiPutWithMfa(`/api/v1/admin/users/${id}`, { isActive: true }, requireStepUp, StepUpOps.UpdateUser, id!); setRefresh((r) => r + 1); },
    });
    const deleteUser = () => {
        if (isSelf) { showToast('warning', 'You cannot delete your own account.'); return; }
        setConfirm({
            title: 'Delete User', message: `Permanently delete user "${user.username}"? If they hold an admin / operator / CA-admin tier, this requires a controlled-user ceremony approved by the required quorum.`, confirmLabel: 'Delete User',
            action: async () => {
                const res: any = await apiDeleteWithMfa(`/api/v1/admin/users/${id}`, requireStepUp, StepUpOps.DeleteUser, id!);
                if (res?.requiresCeremony) { showToast('info', res.message || 'A controlled-user ceremony was started — approve it on the Ceremonies page.'); setRefresh((r) => r + 1); }
                else { showToast('success', `User "${user.username}" deleted`); navigate('/users'); }
            },
        });
    };

    const renderGroups = () => (
        <div className="flex gap-2 flex-wrap">
            {userGroups.map((g: any) => (
                <span key={g.groupId} className={`inline-flex items-center gap-1 px-2 py-1 text-xs rounded border ${groupChipClass(g)}`}>
                    {g.displayName || g.groupName}
                </span>
            ))}
            {userGroups.length === 0 && <span className="text-xs text-gray-600">No groups assigned</span>}
        </div>
    );

    return (
        <DetailPage
            breadcrumbs={[{ label: 'Users', to: '/users' }, { label: user.username }]}
            title={user.username}
            status={<StatusBadge status={user.isLocked ? 'locked' : (isActive ? 'active' : 'disabled')} />}
            subtitle={user.email}
            backTo="/users"
            editable
            actions={
                <div className="flex items-center gap-2 flex-wrap">
                    <button onClick={resetPassword} className="px-3 py-1.5 text-xs bg-yellow-50 dark:bg-yellow-900/50 text-yellow-800 dark:text-yellow-300 border border-yellow-300 dark:border-yellow-700 rounded hover:bg-yellow-900 transition-colors">Reset Password</button>
                    {user.isActive !== false
                        ? <button onClick={disableAccount} disabled={!canDisable} title={isSelf ? 'You cannot disable your own account' : !canDisable ? 'Cannot disable — no other system admins exist' : 'Disable this account'} className="px-3 py-1.5 text-xs bg-red-50 dark:bg-red-900/50 text-red-800 dark:text-red-300 border border-red-300 dark:border-red-700 rounded hover:bg-red-900 transition-colors disabled:opacity-30 disabled:cursor-not-allowed">Disable Account</button>
                        : <button onClick={enableAccount} className="px-3 py-1.5 text-xs bg-green-50 dark:bg-green-900/50 text-green-800 dark:text-green-300 border border-green-300 dark:border-green-700 rounded hover:bg-green-900 transition-colors">Enable Account</button>}
                    <button onClick={deleteUser} disabled={isSelf} title={isSelf ? 'You cannot delete your own account' : 'Delete this user'} className="px-3 py-1.5 text-xs bg-red-600 text-white rounded hover:bg-red-700 transition-colors disabled:opacity-30 disabled:cursor-not-allowed">Delete User</button>
                </div>
            }
        >
            {(mode) => (<>
                <DetailSection title="User">
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-x-8">
                        <DetailField label="Username" value={user.username} />
                        <DetailField label="Email" value={user.email} />
                        <DetailField label="Active" value={isActive ? 'Yes' : 'No'} />
                        <DetailField label="Locked" value={user.isLocked ? 'Yes' : 'No'} />
                        <DetailField label="Created" value={formatDate(user.createdAt)} />
                        <DetailField label="Last Login" value={formatDate(user.lastLogin || user.lastLoginAt)} />
                        <DetailField label="Failed Logins" value={user.failedLoginCount} />
                    </div>
                </DetailSection>

                <DetailSection title={`Groups (${userGroups.length})`}>
                    {mode === 'view' ? (<>
                        {renderGroups()}
                        <p className="text-[11px] text-gray-500 mt-2">Switch to Edit to add or remove groups.</p>
                    </>) : (
                        <div className="space-y-3">
                            <div>
                                <div className="text-[11px] font-semibold text-gray-600 dark:text-gray-400 mb-1">Current groups — click to mark for removal</div>
                                <div className="flex gap-2 flex-wrap">
                                    {userGroups.length === 0 && <span className="text-xs text-gray-600">No groups assigned</span>}
                                    {userGroups.map((g: any) => {
                                        const staged = pendingRemove.includes(g.groupId);
                                        return (
                                            <button key={g.groupId} type="button" onClick={() => toggleRemove(g.groupId)}
                                                title={staged ? 'Marked for removal — click to keep' : 'Click to remove'}
                                                className={`inline-flex items-center gap-1 px-2 py-1 text-xs rounded border transition-colors ${staged ? 'line-through opacity-70 bg-red-50 dark:bg-red-900/40 text-red-700 dark:text-red-300 border-red-300 dark:border-red-700' : groupChipClass(g)}`}>
                                                {g.displayName || g.groupName}
                                                <span className="opacity-70">{staged ? '↺' : '×'}</span>
                                            </button>
                                        );
                                    })}
                                </div>
                            </div>
                            {availableGroups.length > 0 && (
                                <div>
                                    <div className="text-[11px] font-semibold text-gray-600 dark:text-gray-400 mb-1">Add to groups</div>
                                    <div className="flex gap-2 flex-wrap">
                                        {availableGroups.map((g: any) => {
                                            const staged = pendingAdd.includes(g.id);
                                            return (
                                                <button key={g.id} type="button" onClick={() => toggleAdd(g.id)}
                                                    className={`px-2 py-1 text-xs rounded border transition-colors ${staged ? 'bg-green-50 dark:bg-green-900/50 text-green-800 dark:text-green-300 border-green-300 dark:border-green-700' : 'bg-gray-200/50 dark:bg-gray-700/50 text-gray-600 dark:text-gray-400 border-gray-400 dark:border-gray-600 hover:bg-gray-200 dark:hover:bg-gray-700'}`}>
                                                    {staged ? '✓ ' : '+ '}{g.displayName || g.name}
                                                </button>
                                            );
                                        })}
                                    </div>
                                </div>
                            )}
                            <div className="flex items-center gap-2 pt-1 flex-wrap">
                                <button onClick={applyGroupChanges} disabled={groupBusy || (pendingAdd.length === 0 && pendingRemove.length === 0)}
                                    className="px-3 py-1.5 text-xs bg-blue-600 text-white rounded hover:bg-blue-700 disabled:opacity-50 transition-colors">
                                    {groupBusy ? 'Applying…' : `Apply changes (+${pendingAdd.length} / −${pendingRemove.length})`}
                                </button>
                                {(pendingAdd.length > 0 || pendingRemove.length > 0) && (
                                    <button onClick={resetStaging} disabled={groupBusy} className="px-3 py-1.5 text-xs bg-gray-200 dark:bg-gray-700 text-gray-700 dark:text-gray-300 rounded hover:bg-gray-300 dark:hover:bg-gray-600 disabled:opacity-50 transition-colors">Reset</button>
                                )}
                                <span className="text-[10px] text-gray-500">One MFA prompt; each privileged group change starts its own ceremony.</span>
                            </div>
                        </div>
                    )}
                </DetailSection>

                <ConfirmModal
                    isOpen={!!confirm}
                    title={confirm?.title || ''}
                    message={confirm?.message || ''}
                    confirmLabel={confirm?.confirmLabel || 'Confirm'}
                    loading={confirmLoading}
                    onConfirm={async () => {
                        if (!confirm) return;
                        setConfirmLoading(true);
                        try { await confirm.action(); }
                        catch (err: any) { if (err.message !== 'Step-up MFA cancelled') showToast('error', err.message || 'Operation failed'); }
                        finally { setConfirmLoading(false); setConfirm(null); }
                    }}
                    onCancel={() => setConfirm(null)}
                />
            </>)}
        </DetailPage>
    );
};

export default UserDetail;
