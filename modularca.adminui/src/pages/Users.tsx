import React, { useState, useEffect } from 'react';
import type { NoticeInput } from '@shared/notifications/notice';
import { errorNotice } from '@shared-auth/api/notices';
import { apiGet, apiPostWithMfa } from '../api/client';
import { useStepUp } from '../components/StepUpMfaContext';
import { useToast } from '@shared/context/ToastContext';
import { StatusBadge, Tag } from '@shared/components/cards/StatusBadge';

/** Group memberships shown in a table row before "+N more". */
const GROUPS_SHOWN = 3;
import { DetailField } from '@shared/components/cards/DetailField';
import { DataTable, DataTableColumn } from '@shared/components/DataTable';
import { StepUpOps } from '@shared/generated';
import { FilterBar, FilterField, filterControlClass } from '@shared/components/FilterBar';
import { userMatches } from './userFilters';
import ServiceIdentitiesPanel from '../components/ServiceIdentitiesPanel';

function formatDate(d: string | null) {
    if (!d) return '-';
    return new Date(d).toLocaleDateString('en-US', { year: 'numeric', month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' });
}

/// <summary>
/// Users page: a DataTable of users + a create form. Per-user group management and account actions
/// live on the /users/:id detail page.
/// </summary>
const Users: React.FC = () => {
    const { showToast } = useToast();
    const { requireStepUp } = useStepUp();
    const [users, setUsers] = useState<any[]>([]);
    const [allGroups, setAllGroups] = useState<any[]>([]);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState<NoticeInput | null>(null);
    const [search, setSearch] = useState('');
    const [statusFilter, setStatusFilter] = useState('');
    const [signInFilter, setSignInFilter] = useState('');
    const [groupFilter, setGroupFilter] = useState('');
    const [showCreate, setShowCreate] = useState(false);
    const [createForm, setCreateForm] = useState({ username: '', email: '', password: '', firstName: '', lastName: '', groupIds: [] as string[] });
    const [creating, setCreating] = useState(false);
    const [refreshTrigger, setRefreshTrigger] = useState(0);
    const [tab, setTab] = useState<'people' | 'service'>('people');

    useEffect(() => {
        let cancelled = false;
        setLoading(true);
        setError(null);
        Promise.all([
            apiGet<any>('/api/v1/admin/users'),
            apiGet<any>('/api/v1/admin/groups'),
        ]).then(([usersData, groupsData]) => {
            if (cancelled) return;
            setUsers(Array.isArray(usersData) ? usersData : (usersData.items || usersData.users || []));
            setAllGroups(Array.isArray(groupsData) ? groupsData : (groupsData.items || groupsData.groups || []));
            setLoading(false);
        }).catch((err) => { if (!cancelled) { setError(errorNotice(err, 'Failed to load users')); setLoading(false); } });
        return () => { cancelled = true; };
    }, [refreshTrigger]);

    const filteredUsers = users.filter((u) => userMatches(u, { search, status: statusFilter, signIn: signInFilter, groupId: groupFilter }));

    const handleCreate = async (e: React.FormEvent) => {
        e.preventDefault();
        setCreating(true);
        try {
            await apiPostWithMfa<any>('/api/v1/admin/users', {
                username: createForm.username, email: createForm.email, password: createForm.password,
                firstName: createForm.firstName, lastName: createForm.lastName, groupIds: createForm.groupIds,
            }, requireStepUp, StepUpOps.CreateUser);
            setShowCreate(false);
            setCreateForm({ username: '', email: '', password: '', firstName: '', lastName: '', groupIds: [] });
            setRefreshTrigger((t) => t + 1);
        } catch (err: any) {
            if (err.message !== 'Step-up MFA cancelled') showToast('error', err.message || 'Failed to create user');
        } finally {
            setCreating(false);
        }
    };

    const toggleCreateGroup = (groupId: string) => setCreateForm((prev) => ({
        ...prev,
        groupIds: prev.groupIds.includes(groupId) ? prev.groupIds.filter((id) => id !== groupId) : [...prev.groupIds, groupId],
    }));

    const userStatus = (u: any): { status: 'locked' | 'active' | 'disabled'; label: string } => {
        if (u.isLocked) return { status: 'locked', label: 'Locked' };
        if (u.isActive === false) return { status: 'disabled', label: 'Disabled' };
        return { status: 'active', label: 'Active' };
    };

    const columns: DataTableColumn<any>[] = [
        { key: 'status', header: 'Status', defaultWidth: 100, truncate: false, exportValue: (u) => userStatus(u).label, render: (u) => <StatusBadge status={userStatus(u).status} /> },
        { key: 'username', header: 'Username', defaultWidth: 180, minWidth: 120, truncate: false, exportValue: (u) => u.username, render: (u) => <span className="text-ink font-medium truncate">{u.username}</span> },
        { key: 'email', header: 'Email', defaultWidth: 220, exportValue: (u) => u.email || '', render: (u) => <span className="text-xs text-ink-muted truncate">{u.email}</span> },
        {
            key: 'groups', header: 'Groups', defaultWidth: 240, minWidth: 140, truncate: false,
            exportValue: (u) => (u.groups || []).map((g: any) => g.displayName || g.groupName).join(', '),
            render: (u) => (
                <span className="flex gap-1 flex-wrap items-center" title={(u.groups || []).map((g: any) => g.displayName || g.groupName).join(', ')}>
                    {/* The first few; the drawer and the user's page list them all. */}
                    {(u.groups || []).slice(0, GROUPS_SHOWN).map((g: any) => <Tag key={g.groupId} label={g.displayName || g.groupName} />)}
                    {(u.groups || []).length > GROUPS_SHOWN && <span className="text-xs text-ink-muted">+{(u.groups || []).length - GROUPS_SHOWN} more</span>}
                    {(u.groups || []).length === 0 && <span className="text-xs text-ink-muted">-</span>}
                </span>
            ),
        },
        { key: 'lastLogin', header: 'Last Login', defaultWidth: 160, exportValue: (u) => formatDate(u.lastLogin || u.lastLoginAt), render: (u) => <span className="text-xs text-ink-muted">{formatDate(u.lastLogin || u.lastLoginAt)}</span> },
    ];

    const drawer = (u: any) => {
        const userGroups: any[] = u.groups || [];
        return (
            <div className="text-sm">
                <DetailField label="Username" value={u.username} />
                <DetailField label="Email" value={u.email} />
                <DetailField label="Groups" value={userGroups.map((g: any) => g.displayName || g.groupName).join(', ') || 'None'} />
                <DetailField label="Active" value={u.isActive !== false ? 'Yes' : 'No'} />
                <DetailField label="Locked" value={u.isLocked ? 'Yes' : 'No'} />
                <DetailField label="Created" value={formatDate(u.createdAt)} />
                <DetailField label="Last Login" value={formatDate(u.lastLogin || u.lastLoginAt)} />
                <p className="text-[11px] text-ink-muted pt-3">Open the full page to manage groups or the account.</p>
            </div>
        );
    };

    return (
        <div className="p-3 sm:p-6 space-y-4 sm:space-y-6">
            <div className="flex items-center justify-between gap-3 flex-wrap">
                <div className="flex items-center gap-4">
                    <h1 className="text-xl font-semibold text-ink">Users</h1>
                    <div className="flex gap-1 border-b border-line">
                        {([['people', 'People'], ['service', 'Service identities']] as const).map(([k, label]) => (
                            <button key={k} onClick={() => setTab(k)}
                                className={`px-3 py-1.5 text-sm font-medium border-b-2 -mb-px transition-colors ${tab === k ? 'border-accent text-accent-ink' : 'border-transparent text-ink-muted hover:text-ink'}`}>
                                {label}
                            </button>
                        ))}
                    </div>
                </div>
                {tab === 'people' && (
                    <button onClick={() => setShowCreate(!showCreate)} className="px-4 py-2 text-sm bg-accent text-on-accent rounded hover:bg-accent-hover transition-colors">
                        {showCreate ? 'Cancel' : 'Create User'}
                    </button>
                )}
            </div>

            {tab === 'service' && <ServiceIdentitiesPanel />}

            {tab === 'people' && (<>
            {/* Create User Form */}
            {showCreate && (
                <form onSubmit={handleCreate} className="bg-raised border border-line rounded-lg p-4 space-y-3">
                    <h3 className="text-sm font-semibold text-ink">New User</h3>
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                        <input type="text" placeholder="Username" required value={createForm.username} onChange={(e) => setCreateForm({ ...createForm, username: e.target.value })}
                            className="px-3 py-2 bg-raised border border-line-strong rounded text-sm text-ink placeholder-ink-faint focus:outline-none focus:border-accent" />
                        <input type="email" placeholder="Email" required value={createForm.email} onChange={(e) => setCreateForm({ ...createForm, email: e.target.value })}
                            className="px-3 py-2 bg-raised border border-line-strong rounded text-sm text-ink placeholder-ink-faint focus:outline-none focus:border-accent" />
                        <input type="password" placeholder="Password" required value={createForm.password} onChange={(e) => setCreateForm({ ...createForm, password: e.target.value })}
                            className="px-3 py-2 bg-raised border border-line-strong rounded text-sm text-ink placeholder-ink-faint focus:outline-none focus:border-accent" />
                        <input type="text" placeholder="First Name" required value={createForm.firstName} onChange={(e) => setCreateForm({ ...createForm, firstName: e.target.value })}
                            className="px-3 py-2 bg-raised border border-line-strong rounded text-sm text-ink placeholder-ink-faint focus:outline-none focus:border-accent" />
                        <input type="text" placeholder="Last Name" required value={createForm.lastName} onChange={(e) => setCreateForm({ ...createForm, lastName: e.target.value })}
                            className="px-3 py-2 bg-raised border border-line-strong rounded text-sm text-ink placeholder-ink-faint focus:outline-none focus:border-accent" />
                    </div>
                    <div>
                        <label className="text-xs text-ink-muted block mb-2">Groups (select one or more):</label>
                        <div className="flex flex-wrap gap-2 max-h-32 overflow-y-auto p-2 bg-ground border border-line rounded">
                            {allGroups.map((g) => {
                                const selected = createForm.groupIds.includes(g.id);
                                return (
                                    <button key={g.id} type="button" onClick={() => toggleCreateGroup(g.id)}
                                        className={`px-2 py-1 text-xs rounded border transition-colors ${selected ? 'bg-accent-soft text-accent-ink border-accent/40' : 'bg-sunken text-ink-muted border-line-strong hover:bg-hover'}`}>
                                        {selected ? '✓ ' : ''}{g.displayName || g.name}
                                    </button>
                                );
                            })}
                            {allGroups.length === 0 && <span className="text-xs text-ink-muted">No groups available</span>}
                        </div>
                    </div>
                    <button type="submit" disabled={creating} className="px-4 py-2 text-sm bg-ok text-on-accent rounded hover:bg-ok-hover disabled:opacity-50 transition-colors">
                        {creating ? 'Creating...' : 'Create'}
                    </button>
                </form>
            )}

            <FilterBar>
                <FilterField label="Search" grow>
                    <input type="text" placeholder="Username or email" value={search} onChange={(e) => setSearch(e.target.value)} className={filterControlClass} />
                </FilterField>
                <FilterField label="Status">
                    <select value={statusFilter} onChange={(e) => setStatusFilter(e.target.value)} className={filterControlClass}>
                        <option value="">Any</option>
                        <option value="active">Active</option>
                        <option value="locked">Locked</option>
                        <option value="disabled">Disabled</option>
                    </select>
                </FilterField>
                <FilterField label="Signed in">
                    <select value={signInFilter} onChange={(e) => setSignInFilter(e.target.value)} className={filterControlClass}>
                        <option value="">Any</option>
                        <option value="never">Never</option>
                        <option value="90">Not in the last 90 days</option>
                    </select>
                </FilterField>
                <FilterField label="Group">
                    <select value={groupFilter} onChange={(e) => setGroupFilter(e.target.value)} className={filterControlClass}>
                        <option value="">Any</option>
                        {allGroups.map((g: any) => <option key={g.id} value={g.id}>{g.displayName || g.name}</option>)}
                    </select>
                </FilterField>
                {(search || statusFilter || signInFilter || groupFilter) && (
                    <button onClick={() => { setSearch(''); setStatusFilter(''); setSignInFilter(''); setGroupFilter(''); }} className="px-3 py-2 text-sm text-ink-muted hover:text-ink transition-colors">Clear filters</button>
                )}
            </FilterBar>

            <DataTable<any>
                tableId="users"
                title="Users"
                rows={filteredUsers}
                rowKey={(u) => u.id || u.username}
                loading={loading}
                error={error}
                empty={search ? 'No users match this search' : 'No users found'}
                columns={columns}
                selectable
                exportFileName="users"
                renderDrawer={drawer}
                drawerTitle={(u) => u.username}
                detailPath={(u) => `/users/${u.id || u.username}`}
            />
            </>)}
        </div>
    );
};

export default Users;
