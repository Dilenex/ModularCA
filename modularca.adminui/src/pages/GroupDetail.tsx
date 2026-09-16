import React, { useEffect, useState } from 'react';
import type { NoticeInput } from '@shared/notifications/notice';
import { InlineNotice } from '@shared/components/InlineNotice';
import { errorNotice } from '@shared-auth/api/notices';
import { useParams, useNavigate } from 'react-router-dom';
import { apiGet, apiPutWithMfa, apiPostWithMfa, apiDeleteWithMfa } from '../api/client';
import { useToast } from '@shared/context/ToastContext';
import { useStepUp } from '../components/StepUpMfaContext';
import { StatusBadge } from '@shared/components/cards/StatusBadge';
import { DetailField } from '@shared/components/cards/DetailField';
import ConfirmModal from '../components/ConfirmModal';
import { DetailPage, DetailSection } from '../components/DetailPage';
import { StepUpOps } from '@shared/generated';
import { inputClass as inputCls, labelClass as labelCls } from '@shared/components/forms';

function templateLabel(t: string | null): string { return t || 'Custom'; }
function templateStatus(t: string | null): 'revoked' | 'held' | 'pending' | 'active' {
    switch (t?.toLowerCase() ?? '') {
        case 'administrator': return 'revoked';
        case 'operator': return 'held';
        case 'auditor': return 'pending';
        default: return 'active';
    }
}


const GroupDetail: React.FC = () => {
    const { id } = useParams<{ id: string }>();
    const navigate = useNavigate();
    const { showToast } = useToast();
    const { requireStepUp } = useStepUp();

    const [group, setGroup] = useState<any | null>(null);
    const [authorities, setAuthorities] = useState<any[]>([]);
    const [allUsers, setAllUsers] = useState<any[]>([]);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState<NoticeInput | null>(null);
    const [refresh, setRefresh] = useState(0);

    const [form, setForm] = useState({ displayName: '', mtlsSigningCaId: '' });
    const [initialForm, setInitialForm] = useState({ displayName: '', mtlsSigningCaId: '' });
    const [selectedUserIds, setSelectedUserIds] = useState<string[]>([]);
    const [selectedMemberIds, setSelectedMemberIds] = useState<string[]>([]);
    const [confirm, setConfirm] = useState<{ title: string; message: string; action: () => Promise<void> } | null>(null);
    const [confirmLoading, setConfirmLoading] = useState(false);

    useEffect(() => {
        let cancelled = false;
        setLoading(true);
        setError(null);
        Promise.all([
            apiGet<any>(`/api/v1/admin/groups/${id}`),
            apiGet<any>('/api/v1/admin/authorities').catch(() => []),
            apiGet<any>('/api/v1/admin/users').catch(() => []),
        ]).then(([g, authData, usersData]) => {
            if (cancelled) return;
            setGroup(g);
            if (g) {
                const snap = { displayName: g.displayName || '', mtlsSigningCaId: g.mtlsSigningCaId || '' };
                setForm(snap);
                setInitialForm(snap);
            }
            const cas = Array.isArray(authData) ? authData : (authData.items || authData.authorities || []);
            const flat: any[] = [];
            const flatten = (l: any[]) => { for (const c of l) { flat.push(c); if (c.children) flatten(c.children); } };
            flatten(cas);
            setAuthorities(flat);
            setAllUsers(Array.isArray(usersData) ? usersData : (usersData.items || usersData.users || []));
            setLoading(false);
        }).catch((err) => { if (!cancelled) { setError(errorNotice(err, 'Failed to load group')); setLoading(false); } });
        return () => { cancelled = true; };
    }, [id, refresh]);

    const caNameById = (caId: string | null) => {
        if (!caId) return '-';
        const ca = authorities.find((a) => a.id === caId);
        return ca ? (ca.label || ca.commonName || ca.id) : caId.substring(0, 8);
    };

    const dirty = JSON.stringify(form) !== JSON.stringify(initialForm);

    const handleSave = async () => {
        try {
            await apiPutWithMfa(`/api/v1/admin/groups/${id}`, {
                displayName: form.displayName,
                mtlsSigningCaId: form.mtlsSigningCaId || null,
            }, requireStepUp, StepUpOps.UpdateGroup, id!);
            showToast('success', 'Group updated');
            setRefresh((r) => r + 1);
        } catch (err: any) {
            if (err.message !== 'Step-up MFA cancelled') showToast('error', err.message || 'Failed to update group');
            throw err;
        }
    };

    const handleCancel = () => {
        setForm(initialForm);
        setSelectedUserIds([]);
        setSelectedMemberIds([]);
    };

    // One step-up prompt authorizes the whole batch; the server adds uncontrolled users directly and
    // starts a controlled-user ceremony PER privileged user.
    const performAddMembers = async () => {
        try {
            const res: any = await apiPostWithMfa(`/api/v1/admin/groups/${id}/members/bulk`, { userIds: selectedUserIds }, requireStepUp, StepUpOps.AddGroupMember, id!);
            setSelectedUserIds([]);
            setRefresh((r) => r + 1);
            const added = res?.added ?? 0, ceremonies = res?.ceremonies ?? 0, skipped = res?.skipped ?? 0;
            const parts = [
                added ? `${added} added` : '',
                ceremonies ? `${ceremonies} ceremon${ceremonies === 1 ? 'y' : 'ies'} started` : '',
                skipped ? `${skipped} skipped` : '',
            ].filter(Boolean);
            const msg = parts.join(' · ') || 'No changes';
            showToast(ceremonies > 0 ? 'info' : 'success', ceremonies > 0 ? `${msg} — approve on the Ceremonies page.` : msg);
        } catch (err: any) {
            if (err.message !== 'Step-up MFA cancelled') showToast('error', err.message || 'Failed to add members');
        }
    };

    // Adding to an Administrator group hands every capability to the chosen users, which is as
    // consequential as removal (which already confirms), so it confirms too. Other templates add
    // straight away as before.
    const addMembers = () => {
        if (selectedUserIds.length === 0) return;
        if ((group?.templateName || '').toLowerCase() !== 'administrator') { void performAddMembers(); return; }
        const n = selectedUserIds.length;
        const names = selectedUserIds
            .map((uid) => allUsers.find((u) => u.id === uid)?.username || uid)
            .slice(0, 5);
        const more = n - names.length;
        setConfirm({
            title: 'Add to an Administrator group',
            message: `Add ${n} user${n === 1 ? '' : 's'} (${names.join(', ')}${more > 0 ? ` and ${more} more` : ''}) to "${group.displayName || group.name}"? Members of an Administrator group hold every capability${group.certificateAuthorityId ? ' on this CA' : group.isSystemGroup ? ' across the whole system' : ' in this tenant'}. Privileged users will each require a controlled-user ceremony.`,
            action: performAddMembers,
        });
    };

    // One step-up prompt authorizes the whole batch; the server removes uncontrolled users directly,
    // starts a demotion ceremony PER controlled user, and refuses any that would be the last admin.
    const removeMembers = () => {
        if (selectedMemberIds.length === 0) return;
        const n = selectedMemberIds.length;
        setConfirm({
            title: 'Remove Members',
            message: `Remove ${n} member${n === 1 ? '' : 's'} from this group? Privileged users will each require a controlled-user ceremony.`,
            action: async () => {
                const res: any = await apiPostWithMfa(`/api/v1/admin/groups/${id}/members/bulk-remove`, { userIds: selectedMemberIds }, requireStepUp, StepUpOps.RemoveGroupMember, id!);
                setSelectedMemberIds([]);
                setRefresh((r) => r + 1);
                const removed = res?.removed ?? 0, ceremonies = res?.ceremonies ?? 0, refused = res?.refused ?? 0, skipped = res?.skipped ?? 0;
                const parts = [
                    removed ? `${removed} removed` : '',
                    ceremonies ? `${ceremonies} ceremon${ceremonies === 1 ? 'y' : 'ies'} started` : '',
                    refused ? `${refused} refused (last admin)` : '',
                    skipped ? `${skipped} skipped` : '',
                ].filter(Boolean);
                const msg = parts.join(' · ') || 'No changes';
                showToast(ceremonies > 0 || refused > 0 ? 'info' : 'success', ceremonies > 0 ? `${msg} — approve on the Ceremonies page.` : msg);
            },
        });
    };
    const toggleSelectMember = (uid: string) => setSelectedMemberIds((prev) => prev.includes(uid) ? prev.filter((x) => x !== uid) : [...prev, uid]);

    const deleteGroup = () => {
        if (!group) return;
        setConfirm({
            title: 'Delete Group',
            message: `Delete "${group.displayName || group.name}"? This cannot be undone.`,
            action: async () => { await apiDeleteWithMfa(`/api/v1/admin/groups/${id}`, requireStepUp, StepUpOps.DeleteGroup, id!); navigate('/groups'); },
        });
    };

    if (loading) return <div className="p-6 text-sm text-gray-600 dark:text-gray-400">Loading…</div>;
    if (error) return <InlineNotice notice={error} />;
    if (!group) return (
        <div className="p-6 space-y-3">
            <p className="text-sm text-gray-600 dark:text-gray-400">Group not found.</p>
            <button onClick={() => navigate('/groups')} className="px-3 py-1.5 text-sm bg-gray-200 dark:bg-gray-700 rounded">Back to Groups</button>
        </div>
    );

    const members: any[] = group.members || [];
    const eligibleCas = authorities.filter((ca: any) => !ca.isSshCa && (ca.label || '').toLowerCase() !== 'system-signing-ca' && (ca.type || '').toLowerCase() !== 'root');
    const eligibleUsers = allUsers.filter((u) => !members.some((m: any) => m.id === u.id || m.userId === u.id));
    const toggleSelectUser = (uid: string) => setSelectedUserIds((prev) => prev.includes(uid) ? prev.filter((x) => x !== uid) : [...prev, uid]);

    return (
        <DetailPage
            breadcrumbs={[{ label: 'Groups', to: '/groups' }, { label: group.displayName || group.name }]}
            title={group.displayName || group.name}
            status={<StatusBadge status={templateStatus(group.templateName)} label={templateLabel(group.templateName)} />}
            subtitle={<span className="font-mono">{group.name}</span>}
            editable
            onSave={handleSave}
            onCancel={handleCancel}
            saveDisabled={!dirty}
            actions={!group.isAutoGenerated ? (
                <button onClick={deleteGroup} className="px-3 py-1.5 text-xs bg-red-50 dark:bg-red-900/50 text-red-800 dark:text-red-300 border border-red-300 dark:border-red-700 rounded hover:bg-red-900 transition-colors">Delete</button>
            ) : undefined}
        >
            {(mode) => (<>
                {mode === 'view' ? (
                    <DetailSection title="Group">
                        <div className="grid grid-cols-1 md:grid-cols-2 gap-x-8">
                            <DetailField label="ID" value={group.id} mono />
                            <DetailField label="Backend Name" value={group.name} mono />
                            <DetailField label="Display Name" value={group.displayName} />
                            <DetailField label="Template" value={templateLabel(group.templateName)} />
                            <DetailField label="CA" value={caNameById(group.certificateAuthorityId)} />
                            <DetailField label="System Group" value={group.isSystemGroup ? 'Yes' : 'No'} />
                            <DetailField label="Auto-generated" value={group.isAutoGenerated ? 'Yes' : 'No'} />
                            <DetailField label="mTLS Signing CA" value={group.mtlsSigningCaId ? caNameById(group.mtlsSigningCaId) : 'None'} />
                        </div>
                    </DetailSection>
                ) : (
                    <DetailSection title="Edit Group">
                        <div className="space-y-4 max-w-2xl">
                            <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                                <div>
                                    <label className={labelCls}>Display Name</label>
                                    <input type="text" value={form.displayName} disabled={group.isAutoGenerated}
                                        onChange={(e) => setForm({ ...form, displayName: e.target.value })} className={inputCls} />
                                    {group.isAutoGenerated && <p className="text-[10px] text-gray-500 mt-1">Auto-generated group names can't be changed.</p>}
                                </div>
                                <div className="md:col-span-2">
                                    <label className={labelCls}>mTLS Signing CA</label>
                                    {group.isSystemGroup ? (
                                        <p className="text-xs text-gray-500">System-tenant groups never sign mTLS client certs. Assign this to an org-tenant group instead.</p>
                                    ) : (
                                        <>
                                            <select value={form.mtlsSigningCaId} onChange={(e) => setForm({ ...form, mtlsSigningCaId: e.target.value })} className={inputCls}>
                                                <option value="">None (mTLS disabled for this group)</option>
                                                {eligibleCas.map((ca) => <option key={ca.id} value={ca.id}>{ca.name}</option>)}
                                            </select>
                                            <p className="text-[10px] text-gray-500 mt-1">Only non-Root issuing/intermediate CAs are eligible.</p>
                                        </>
                                    )}
                                </div>
                            </div>
                        </div>
                    </DetailSection>
                )}

                <DetailSection title={`Members (${members.length})`}>
                    {mode === 'edit' && (
                        <div className="mb-4 space-y-2">
                            <div className="flex items-center justify-between gap-2">
                                <label className="text-xs font-semibold text-gray-600 dark:text-gray-400">
                                    Add members{selectedUserIds.length > 0 ? ` · ${selectedUserIds.length} selected` : ''}
                                </label>
                                <button onClick={addMembers} disabled={selectedUserIds.length === 0} className="px-3 py-1.5 text-xs bg-green-600 text-white rounded hover:bg-green-700 disabled:opacity-50">
                                    Add {selectedUserIds.length || ''} {selectedUserIds.length === 1 ? 'user' : 'users'}
                                </button>
                            </div>
                            {eligibleUsers.length === 0 ? (
                                <p className="text-xs text-gray-500">All users are already members.</p>
                            ) : (
                                <div className="max-h-48 overflow-y-auto bg-gray-50 dark:bg-gray-900 border border-gray-300 dark:border-gray-700 rounded divide-y divide-gray-200 dark:divide-gray-700/60">
                                    {eligibleUsers.map((u) => (
                                        <label key={u.id} className="flex items-center gap-2 px-3 py-1.5 text-sm cursor-pointer hover:bg-gray-100 dark:hover:bg-gray-800">
                                            <input type="checkbox" checked={selectedUserIds.includes(u.id)} onChange={() => toggleSelectUser(u.id)} className="accent-blue-500" />
                                            <span className="text-gray-900 dark:text-white">{u.username}</span>
                                            {u.email && <span className="text-xs text-gray-500">{u.email}</span>}
                                        </label>
                                    ))}
                                </div>
                            )}
                            <p className="text-[10px] text-gray-500">One MFA prompt adds them all; each privileged user starts its own controlled-user ceremony.</p>
                        </div>
                    )}
                    {members.length === 0 ? (
                        <div className="text-xs text-gray-500">No members in this group.</div>
                    ) : (<>
                        {mode === 'edit' && (
                            <div className="flex items-center justify-between gap-2 mb-2">
                                <span className="text-[11px] text-gray-500">{selectedMemberIds.length > 0 ? `${selectedMemberIds.length} selected` : 'Select members to remove'}</span>
                                <button onClick={removeMembers} disabled={selectedMemberIds.length === 0} className="px-3 py-1.5 text-xs bg-red-50 dark:bg-red-900/50 text-red-800 dark:text-red-300 border border-red-300 dark:border-red-700 rounded hover:bg-red-900 disabled:opacity-50 transition-colors">
                                    Remove {selectedMemberIds.length || ''} {selectedMemberIds.length === 1 ? 'member' : 'members'}
                                </button>
                            </div>
                        )}
                        <div className="divide-y divide-gray-200 dark:divide-gray-700/60">
                            {members.map((m: any) => {
                                const uid = m.id || m.userId;
                                return (
                                    <label key={uid} className={`flex items-center gap-2 py-2 text-sm ${mode === 'edit' ? 'cursor-pointer' : ''}`}>
                                        {mode === 'edit' && (
                                            <input type="checkbox" checked={selectedMemberIds.includes(uid)} onChange={() => toggleSelectMember(uid)} className="accent-blue-500" />
                                        )}
                                        <span className="text-gray-900 dark:text-white">{m.username || m.email || uid}</span>
                                        {m.email && m.username && <span className="text-xs text-gray-500">{m.email}</span>}
                                    </label>
                                );
                            })}
                        </div>
                    </>)}
                    {mode === 'view' && <p className="text-[11px] text-gray-500 mt-2">Switch to Edit to add or remove members.</p>}
                </DetailSection>

                <ConfirmModal
                    isOpen={!!confirm}
                    title={confirm?.title || ''}
                    message={confirm?.message || ''}
                    confirmLabel="Confirm"
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

export default GroupDetail;
