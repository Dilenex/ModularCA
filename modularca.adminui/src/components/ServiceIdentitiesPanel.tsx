import React, { useCallback, useEffect, useMemo, useState } from 'react';
import type { NoticeInput } from '@shared/notifications/notice';
import { errorNotice } from '@shared-auth/api/notices';
import ConfirmModal from './ConfirmModal';
import { apiGet, apiPostWithMfa, apiPutWithMfa, apiDeleteWithMfa } from '../api/client';
import { useStepUp } from './StepUpMfaContext';
import { useAuth } from '../context/AuthContext';
import { can, canAtTenant, consoleCas, tenantsOf } from '../authz';
import { useToast } from '@shared/context/ToastContext';
import { DataTable, DataTableColumn } from '@shared/components/DataTable';
import { DetailField } from '@shared/components/cards/DetailField';
import { StatusBadge } from '@shared/components/cards/StatusBadge';
import { FieldHint, inputClass, labelClass } from '@shared/components/forms';
import { Drawer } from '@shared/components/Drawer';
import { Capabilities, StepUpOps } from '@shared/generated';
import AuditTable from './AuditTable';

/**
 * Service identities: accounts that hold permissions for a non-person caller, such as the
 * enrollment identity a Kerberos realm acts as, and that can never sign in. Each is confined to
 * the system, one tenant or one CA; the caller sees and manages only the scopes they administer,
 * and the groups offered are the ones inside that scope.
 */
export interface ServiceIdentity {
    id: string; username: string; displayName?: string | null; description?: string | null; isActive: boolean; createdAt: string;
    scope: 'system' | 'tenant' | 'ca'; tenantId?: string | null; tenantName?: string | null; caId?: string | null; caLabel?: string | null;
    groups: Array<{ groupId: string; name: string; displayName: string; certificateAuthorityId?: string | null; tenantId: string; templateName?: string | null }>;
}
interface GroupOption { id: string; name: string; displayName: string; certificateAuthorityId?: string | null; tenantId: string; isSystemGroup: boolean; isSystemTierSuper?: boolean; isSystemTenant?: boolean }

type ScopeChoice = { key: string; label: string; tenantId: string | null; caId: string | null };

const fmt = (iso?: string | null) => (iso ? new Date(iso).toLocaleString() : '-');
const scopeLabel = (s: ServiceIdentity) => s.scope === 'ca' ? `CA ${s.caLabel || s.caId}` : s.scope === 'tenant' ? `Tenant ${s.tenantName || s.tenantId}` : 'System';

/** The scope a group belongs to fits an identity scope the same way the server decides it. */
const groupFits = (g: GroupOption, tenantId: string | null, caId: string | null) => {
    if (g.isSystemGroup || g.isSystemTierSuper || g.isSystemTenant) return false;
    if (!tenantId && !caId) return true;
    if (g.certificateAuthorityId) return caId === g.certificateAuthorityId || (!caId && tenantId === g.tenantId);
    return !caId && tenantId === g.tenantId;
};

const ServiceIdentitiesPanel: React.FC = () => {
    const { requireStepUp } = useStepUp();
    const { showToast } = useToast();
    const { capabilities } = useAuth();

    const [rows, setRows] = useState<ServiceIdentity[]>([]);
    const [groups, setGroups] = useState<GroupOption[]>([]);
    // The group list is fetched separately and may fail on its own (a 403 for a caller without
    // group.view, say). That is "could not load groups", not "no groups inside this scope".
    const [groupsError, setGroupsError] = useState<string | null>(null);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState<NoticeInput | null>(null);
    const [creating, setCreating] = useState(false);
    const [busy, setBusy] = useState(false);
    // The panel owns the drawer rather than handing DataTable a renderDrawer: the drawer edits, and
    // DataTable's own drawer closes on X, backdrop and Escape with no way for the content to ask
    // "discard unsaved changes?" first. Holding the id (not the row) also means the drawer shows
    // the record as reloaded after a save, and disappears when the identity is deleted.
    const [openId, setOpenId] = useState<string | null>(null);

    /** Scopes the caller may create in: system when ca.manage is held at system scope, then tenants held tenant-wide, then single CAs. */
    const scopes = useMemo<ScopeChoice[]>(() => {
        const out: ScopeChoice[] = [];
        if (can(capabilities, Capabilities.SystemManage) || can(capabilities, Capabilities.CaManage)) out.push({ key: 'system', label: 'System (any tenant, any CA)', tenantId: null, caId: null });
        for (const t of tenantsOf(capabilities)) if (canAtTenant(capabilities, Capabilities.CaManage, t.id)) out.push({ key: `t:${t.id}`, label: `Tenant: ${t.name}`, tenantId: t.id, caId: null });
        for (const ca of consoleCas(capabilities)) if (can(capabilities, Capabilities.CaManage, ca.id)) out.push({ key: `c:${ca.id}`, label: `CA: ${ca.label} (${ca.tenantName || ca.tenantSlug})`, tenantId: ca.tenantId, caId: ca.id });
        return out;
    }, [capabilities]);

    const [form, setForm] = useState({ username: '', displayName: '', description: '', scopeKey: '', groupIds: [] as string[] });
    const scope = scopes.find((s) => s.key === (form.scopeKey || scopes[0]?.key)) || null;
    const offeredGroups = groups.filter((g) => scope && groupFits(g, scope.tenantId, scope.caId));

    const load = useCallback(() => {
        setLoading(true);
        setGroupsError(null);
        Promise.all([
            apiGet<ServiceIdentity[]>('/api/v1/admin/service-identities'),
            apiGet<any>('/api/v1/admin/groups').catch((e: any) => { setGroupsError(e?.message || 'request failed'); return []; }),
        ])
            .then(([ids, gs]) => { setRows(Array.isArray(ids) ? ids : []); setGroups(Array.isArray(gs) ? gs : gs.items || []); setError(null); })
            .catch((e) => setError(errorNotice(e, 'Failed to load service identities')))
            .finally(() => setLoading(false));
    }, []);
    useEffect(() => { load(); }, [load]);

    const run = async (label: string, fn: () => Promise<void>) => {
        setBusy(true);
        try { await fn(); load(); }
        catch (e: any) { if (e?.message !== 'Step-up MFA cancelled') showToast('error', e?.message || `${label} failed`); }
        finally { setBusy(false); }
    };

    const create = () => run('Create', async () => {
        if (!scope) throw new Error('Pick a scope.');
        await apiPostWithMfa('/api/v1/admin/service-identities', {
            username: form.username, displayName: form.displayName || null, description: form.description || null,
            tenantId: scope.tenantId, caId: scope.caId, groupIds: form.groupIds,
        }, requireStepUp, StepUpOps.CreateUser);
        showToast('success', `Service identity ${form.username} created.`);
        setForm({ username: '', displayName: '', description: '', scopeKey: form.scopeKey, groupIds: [] });
        setCreating(false);
    });

    const current = openId ? rows.find((r) => r.id === openId) ?? null : null;

    const columns: DataTableColumn<ServiceIdentity>[] = [
        { key: 'username', header: 'Identity', defaultWidth: 200, minWidth: 140, exportValue: (r) => r.username, render: (r) => (
            <button type="button" onClick={() => setOpenId(r.id)} title="Open" className="font-mono text-xs text-gray-900 dark:text-white hover:underline text-left">{r.username}</button>
        ) },
        { key: 'displayName', header: 'Display name', defaultWidth: 180, exportValue: (r) => r.displayName || '', render: (r) => <span className="text-xs text-gray-700 dark:text-gray-300">{r.displayName || '-'}</span> },
        { key: 'scope', header: 'Scope', defaultWidth: 200, exportValue: scopeLabel, render: (r) => <span className="text-xs text-gray-600 dark:text-gray-400">{scopeLabel(r)}</span> },
        { key: 'groups', header: 'Groups', defaultWidth: 260, truncate: false, exportValue: (r) => r.groups.map((g) => g.displayName || g.name).join(', '), render: (r) => (
            <span className="flex flex-wrap gap-1">
                {r.groups.length === 0 && <span className="text-xs text-amber-700 dark:text-amber-400">no groups: holds nothing</span>}
                {r.groups.map((g) => <span key={g.groupId} className="px-1.5 py-0.5 text-[10px] rounded border border-gray-300 dark:border-gray-600 text-gray-700 dark:text-gray-300">{g.displayName || g.name}</span>)}
            </span>
        ) },
        { key: 'status', header: 'Status', defaultWidth: 100, truncate: false, exportValue: (r) => (r.isActive ? 'Active' : 'Disabled'), render: (r) => <StatusBadge status={r.isActive ? 'enabled' : 'disabled'} label={r.isActive ? 'Active' : 'Disabled'} /> },
        { key: 'created', header: 'Created', defaultWidth: 160, exportValue: (r) => r.createdAt, render: (r) => <span className="text-xs text-gray-600 dark:text-gray-400">{fmt(r.createdAt)}</span> },
    ];

    return (
        <div className="space-y-3">
            <div className="flex items-start justify-between gap-3 flex-wrap">
                <p className="text-xs text-gray-600 dark:text-gray-400 max-w-3xl">
                    Accounts that hold permissions for something that is not a person: the identity a Kerberos realm acts as, an integration, a protocol credential. They have no password and can never sign in. Each is confined to the system, one tenant or one CA, and can only hold groups inside that scope. System groups are never available to them.
                </p>
                <button onClick={() => setCreating((v) => !v)} disabled={scopes.length === 0} className="px-3 py-1.5 text-xs font-semibold rounded bg-blue-600 text-white hover:bg-blue-700 disabled:opacity-50 transition-colors">
                    {creating ? 'Cancel' : 'New service identity'}
                </button>
            </div>

            {creating && (
                <div className="bg-gray-100 dark:bg-gray-800 border border-gray-300 dark:border-gray-700 rounded-lg p-4 space-y-3">
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                        <div>
                            <label className={labelClass}>Username *</label>
                            <input className={`${inputClass} font-mono`} value={form.username} onChange={(e) => setForm({ ...form, username: e.target.value })} placeholder="svc-lab-msae-enroll" />
                        </div>
                        <div>
                            <label className={labelClass}>Display name</label>
                            <input className={inputClass} value={form.displayName} onChange={(e) => setForm({ ...form, displayName: e.target.value })} placeholder="LAB.MSAE.TEST enrollment" />
                        </div>
                        <div>
                            <label className={labelClass}>Scope *</label>
                            <select className={inputClass} value={form.scopeKey || scopes[0]?.key || ''} onChange={(e) => setForm({ ...form, scopeKey: e.target.value, groupIds: [] })}>
                                {scopes.map((s) => <option key={s.key} value={s.key}>{s.label}</option>)}
                            </select>
                        </div>
                        <div>
                            <label className={labelClass}>Purpose</label>
                            <input className={inputClass} value={form.description} onChange={(e) => setForm({ ...form, description: e.target.value })} placeholder="Windows autoenrollment for the lab forest" />
                        </div>
                    </div>
                    <div>
                        <label className={labelClass}>Groups within the scope</label>
                        <div className="flex flex-wrap gap-2">
                            {offeredGroups.map((g) => {
                                const selected = form.groupIds.includes(g.id);
                                return (
                                    <button key={g.id} type="button" onClick={() => setForm({ ...form, groupIds: selected ? form.groupIds.filter((x) => x !== g.id) : [...form.groupIds, g.id] })}
                                        className={`px-2 py-1 text-xs rounded border transition-colors ${selected ? 'bg-blue-50 dark:bg-blue-900/50 text-blue-800 dark:text-blue-300 border-blue-300 dark:border-blue-700' : 'bg-gray-200/50 dark:bg-gray-700/50 text-gray-600 dark:text-gray-400 border-gray-400 dark:border-gray-600 hover:bg-gray-200 dark:hover:bg-gray-700'}`}>
                                        {selected ? '✓ ' : ''}{g.displayName || g.name}
                                    </button>
                                );
                            })}
                            {groupsError
                                ? <span className="text-xs text-red-800 dark:text-red-400" role="status">Unavailable: could not load groups ({groupsError}). The identity can still be created and given groups later.</span>
                                : offeredGroups.length === 0 && <span className="text-xs text-gray-500">No groups inside this scope.</span>}
                        </div>
                    </div>
                    <div className="flex justify-end">
                        <button disabled={busy || !form.username || !scope} onClick={create} className="px-3 py-1.5 text-xs font-semibold rounded bg-blue-600 text-white hover:bg-blue-700 disabled:opacity-50">Create</button>
                    </div>
                </div>
            )}

            <DataTable<ServiceIdentity>
                onRowClick={(r) => setOpenId(r.id)}
                tableId="service-identities"
                title="Service identities"
                rows={rows}
                rowKey={(r) => r.id}
                loading={loading}
                error={error}
                empty="No service identities in the scopes you administer."
                columns={columns}
                exportFileName="service-identities"
            />
            {current && <IdentityDrawer identity={current} groups={groups} groupsError={groupsError} onChanged={load} onClose={() => setOpenId(null)} />}
        </div>
    );
};

type DrawerTab = 'overview' | 'groups' | 'audit';
const TAB_LABEL: Record<DrawerTab, string> = { overview: 'Overview', groups: 'Groups', audit: 'Audit' };

/** Two group selections hold the same members, whatever order they were clicked in. */
const sameMembers = (a: string[], b: string[]) => a.length === b.length && [...a].sort().join('\n') === [...b].sort().join('\n');

/**
 * The drawer for one identity. Overview and Groups save through different endpoints with different
 * bodies, so each tab keeps its own baseline (the values last loaded or last saved) and knows on its
 * own whether it is dirty: the tab label carries a dot, Save is enabled only then, the other tab is
 * told about it, and closing with either dirty asks first.
 */
const IdentityDrawer: React.FC<{ identity: ServiceIdentity; groups: GroupOption[]; groupsError?: string | null; onChanged: () => void; onClose: () => void }> = ({ identity, groups, groupsError, onChanged, onClose }) => {
    const { requireStepUp } = useStepUp();
    const { showToast } = useToast();
    const [tab, setTab] = useState<DrawerTab>('overview');
    const [busy, setBusy] = useState(false);
    const [selected, setSelected] = useState<string[]>(identity.groups.map((g) => g.groupId));
    const [displayName, setDisplayName] = useState(identity.displayName || '');
    const [description, setDescription] = useState(identity.description || '');
    // Baselines: what the server holds as far as this drawer knows. Set from the record on open,
    // replaced by the posted values after each successful save so the dirty mark clears at once
    // rather than after the list reloads.
    const [overviewBase, setOverviewBase] = useState({ displayName: identity.displayName || '', description: identity.description || '' });
    const [groupsBase, setGroupsBase] = useState<string[]>(identity.groups.map((g) => g.groupId));
    const [confirmDelete, setConfirmDelete] = useState(false);
    const [confirmDiscard, setConfirmDiscard] = useState(false);
    const path = `/api/v1/admin/service-identities/${identity.id}`;

    useEffect(() => {
        const groupIds = identity.groups.map((g) => g.groupId);
        setTab('overview');
        setSelected(groupIds);
        setDisplayName(identity.displayName || '');
        setDescription(identity.description || '');
        setOverviewBase({ displayName: identity.displayName || '', description: identity.description || '' });
        setGroupsBase(groupIds);
    }, [identity.id]); // eslint-disable-line react-hooks/exhaustive-deps

    const overviewDirty = displayName !== overviewBase.displayName || description !== overviewBase.description;
    const groupsDirty = !sameMembers(selected, groupsBase);
    const dirty: Record<DrawerTab, boolean> = { overview: overviewDirty, groups: groupsDirty, audit: false };
    const anyDirty = overviewDirty || groupsDirty;
    /** The editable tabs other than the open one that still hold unsaved edits. */
    const otherDirty = (['overview', 'groups'] as const).filter((t) => t !== tab && dirty[t]);
    const dirtyLabels = (['overview', 'groups'] as const).filter((t) => dirty[t]).map((t) => TAB_LABEL[t]).join(' and ');

    const requestClose = useCallback(() => {
        if (overviewDirty || groupsDirty) setConfirmDiscard(true);
        else onClose();
    }, [overviewDirty, groupsDirty, onClose]);

    const offered = groups.filter((g) => groupFits(g, identity.tenantId || null, identity.caId || null));

    const run = async (label: string, fn: () => Promise<void>) => {
        setBusy(true);
        try { await fn(); onChanged(); }
        catch (e: any) { if (e?.message !== 'Step-up MFA cancelled') showToast('error', e?.message || `${label} failed`); }
        finally { setBusy(false); }
    };

    /** Saves the Overview form. */
    const save = () => run('Update', async () => {
        await apiPutWithMfa(path, { displayName: displayName || null, description: description || null, isActive: identity.isActive }, requireStepUp, StepUpOps.UpdateUser, identity.id);
        setOverviewBase({ displayName, description });
        showToast('success', 'Saved.');
    });
    /** Flips active state only. It posts the saved name and purpose, not the form, so an unsaved
     *  Overview edit is neither committed by surprise nor lost: it stays pending with its dot. */
    const setActive = (isActive: boolean) => run('Update', async () => {
        await apiPutWithMfa(path, { displayName: overviewBase.displayName || null, description: overviewBase.description || null, isActive }, requireStepUp, StepUpOps.UpdateUser, identity.id);
        showToast('success', isActive ? 'Enabled.' : 'Disabled.');
    });
    const saveGroups = () => run('Update groups', async () => {
        await apiPutWithMfa(`${path}/groups`, { groupIds: selected }, requireStepUp, StepUpOps.UpdateUserGroups, identity.id);
        setGroupsBase(selected);
        showToast('success', 'Groups updated.');
    });
    const remove = () => run('Delete', async () => {
        await apiDeleteWithMfa(path, requireStepUp, StepUpOps.DeleteUser, identity.id);
        showToast('success', `${identity.username} deleted.`);
        onClose();
    });

    const tabBtn = (k: DrawerTab) => (
        <button key={k} onClick={() => setTab(k)} className={`px-3 py-1.5 text-xs font-medium border-b-2 -mb-px transition-colors ${tab === k ? 'border-blue-600 text-blue-700 dark:text-blue-400' : 'border-transparent text-gray-600 dark:text-gray-400 hover:text-gray-900 dark:hover:text-white'}`}>
            {TAB_LABEL[k]}{dirty[k] && <span className="ml-1 text-amber-600 dark:text-amber-400" title="Unsaved changes" aria-label="unsaved changes">•</span>}
        </button>
    );

    /** One amber line per other tab that still holds unsaved edits, with a way back to it. */
    const unsavedNotes = otherDirty.length > 0 && (
        <div>
            {otherDirty.map((t) => (
                <FieldHint key={t} tone="warn">
                    Unsaved changes on {TAB_LABEL[t]}.{' '}
                    <button type="button" onClick={() => setTab(t)} className="underline hover:text-amber-950 dark:hover:text-amber-200">Go back to {TAB_LABEL[t]}</button>
                </FieldHint>
            ))}
        </div>
    );

    return (
        <Drawer open onClose={requestClose} title={identity.username}>
        <div className="space-y-3">
            <ConfirmModal isOpen={confirmDiscard} title="Discard unsaved changes?"
                message={`Unsaved changes on ${dirtyLabels} will be lost.`}
                confirmLabel="Discard" onConfirm={() => { setConfirmDiscard(false); onClose(); }} onCancel={() => setConfirmDiscard(false)} />
            <ConfirmModal isOpen={confirmDelete} title={`Delete ${identity.username}?`}
                message="Any Kerberos realm binding that uses this identity as its enrollment identity stops issuing for its whole forest, and the identity's group memberships are gone with it. To pause it instead, use Disable."
                confirmLabel="Delete identity" loading={busy} onConfirm={() => { setConfirmDelete(false); remove(); }} onCancel={() => setConfirmDelete(false)} />
            <div className="flex items-center justify-between gap-2 flex-wrap">
                <StatusBadge status={identity.isActive ? 'enabled' : 'disabled'} label={identity.isActive ? 'Active' : 'Disabled'} />
                <span className="flex items-center gap-1.5 flex-wrap">
                    <button disabled={busy} onClick={() => setActive(!identity.isActive)} className="px-2.5 py-1 text-xs rounded border bg-gray-100 dark:bg-gray-700 text-gray-700 dark:text-gray-300 border-gray-300 dark:border-gray-600 hover:bg-gray-200 dark:hover:bg-gray-600 disabled:opacity-40">{identity.isActive ? 'Disable' : 'Enable'}</button>
                    <button disabled={busy} onClick={() => setConfirmDelete(true)} className="px-2.5 py-1 text-xs rounded border bg-red-50 dark:bg-red-900/50 text-red-800 dark:text-red-300 border-red-300 dark:border-red-700 hover:bg-red-100 dark:hover:bg-red-900 disabled:opacity-40">Delete</button>
                </span>
            </div>
            <div className="flex gap-1 border-b border-gray-200 dark:border-gray-800">{tabBtn('overview')}{tabBtn('groups')}{tabBtn('audit')}</div>
            {unsavedNotes}

            {tab === 'overview' && (
                <div className="space-y-3">
                    <div className="grid grid-cols-1 sm:grid-cols-2 gap-x-4">
                        <DetailField label="Username" value={identity.username} mono />
                        <DetailField label="Scope" value={scopeLabel(identity)} />
                        <DetailField label="Sign-in" value="Never: no password, no session" />
                        <DetailField label="Created" value={fmt(identity.createdAt)} />
                    </div>
                    <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                        <div>
                            <label className={labelClass}>Display name</label>
                            <input className={inputClass} value={displayName} onChange={(e) => setDisplayName(e.target.value)} />
                        </div>
                        <div>
                            <label className={labelClass}>Purpose</label>
                            <input className={inputClass} value={description} onChange={(e) => setDescription(e.target.value)} />
                        </div>
                    </div>
                    <div className="flex justify-end">
                        <button disabled={busy || !overviewDirty} onClick={save} className="px-3 py-1.5 text-xs font-semibold rounded bg-blue-600 text-white hover:bg-blue-700 disabled:opacity-50">Save</button>
                    </div>
                </div>
            )}

            {tab === 'groups' && (
                <div className="space-y-3">
                    <p className="text-xs text-gray-600 dark:text-gray-400">Only groups inside the identity's scope are offered. System groups never are.</p>
                    <div className="flex flex-wrap gap-2">
                        {offered.map((g) => {
                            const on = selected.includes(g.id);
                            return (
                                <button key={g.id} type="button" onClick={() => setSelected(on ? selected.filter((x) => x !== g.id) : [...selected, g.id])}
                                    className={`px-2 py-1 text-xs rounded border transition-colors ${on ? 'bg-blue-50 dark:bg-blue-900/50 text-blue-800 dark:text-blue-300 border-blue-300 dark:border-blue-700' : 'bg-gray-200/50 dark:bg-gray-700/50 text-gray-600 dark:text-gray-400 border-gray-400 dark:border-gray-600 hover:bg-gray-200 dark:hover:bg-gray-700'}`}>
                                    {on ? '✓ ' : ''}{g.displayName || g.name}
                                </button>
                            );
                        })}
                        {groupsError
                            ? <span className="text-xs text-red-800 dark:text-red-400" role="status">Unavailable: could not load groups ({groupsError}). Saving now would drop the memberships this identity already has, so the button is disabled.</span>
                            : offered.length === 0 && <span className="text-xs text-gray-500">No groups inside this scope.</span>}
                    </div>
                    <div className="flex justify-end">
                        <button disabled={busy || !!groupsError || !groupsDirty} onClick={saveGroups} className="px-3 py-1.5 text-xs font-semibold rounded bg-blue-600 text-white hover:bg-blue-700 disabled:opacity-50">Save groups</button>
                    </div>
                </div>
            )}

            {tab === 'audit' && <AuditTable tab="General" target={{ type: 'User', id: identity.id }} pageSize={10} />}
        </div>
        </Drawer>
    );
};

export default ServiceIdentitiesPanel;
