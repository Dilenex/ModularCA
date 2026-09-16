import React, { useState, useEffect } from 'react';
import { apiGet, apiPostWithMfa } from '../api/client';
import { useStepUp } from '../components/StepUpMfaContext';
import { useToast } from '@shared/context/ToastContext';
import { StatusBadge } from '@shared/components/cards/StatusBadge';
import { DetailField } from '@shared/components/cards/DetailField';
import { DataTable, DataTableColumn } from '@shared/components/DataTable';
import { StepUpOps } from '@shared/generated';
import ServiceIdentitiesPanel from '../components/ServiceIdentitiesPanel';

function formatDate(d: string | null) {
    if (!d) return '-';
    return new Date(d).toLocaleDateString('en-US', { year: 'numeric', month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' });
}

/** Returns a StatusBadge-compatible status for a group's template name (color coding). */
export function groupBadgeStatus(templateName: string | null): 'revoked' | 'held' | 'pending' | 'active' {
    switch (templateName?.toLowerCase() ?? '') {
        case 'administrator': return 'revoked';   // red
        case 'operator': return 'held';            // orange
        case 'auditor': return 'pending';          // blue
        case 'requester': return 'active';         // green
        default: return 'active';                  // green (custom)
    }
}

/** Tailwind classes for a group membership chip (system groups get an outlined variant). */
export function groupChipClass(g: any): string {
    const s = groupBadgeStatus(g.templateName);
    const colors: Record<string, string> = {
        revoked: 'text-red-800 dark:text-red-300 border-red-300 dark:border-red-700 bg-red-50 dark:bg-red-900/50',
        held: 'text-orange-800 dark:text-orange-300 border-orange-300 dark:border-orange-700 bg-orange-50 dark:bg-orange-900/50',
        pending: 'text-blue-800 dark:text-blue-300 border-blue-300 dark:border-blue-700 bg-blue-50 dark:bg-blue-900/50',
        active: 'text-green-800 dark:text-green-300 border-green-300 dark:border-green-700 bg-green-50 dark:bg-green-900/50',
    };
    const outline: Record<string, string> = {
        revoked: 'text-red-800 dark:text-red-300 border-red-500 bg-transparent',
        held: 'text-orange-800 dark:text-orange-300 border-orange-500 bg-transparent',
        pending: 'text-blue-800 dark:text-blue-300 border-blue-500 bg-transparent',
        active: 'text-green-800 dark:text-green-300 border-green-500 bg-transparent',
    };
    return g.isSystemGroup ? (outline[s] || outline.active) : (colors[s] || colors.active);
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
    const [error, setError] = useState<string | null>(null);
    const [search, setSearch] = useState('');
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
        }).catch((err) => { if (!cancelled) { setError(err.message || 'Failed to load users'); setLoading(false); } });
        return () => { cancelled = true; };
    }, [refreshTrigger]);

    const filteredUsers = users.filter((u) => {
        if (!search) return true;
        const s = search.toLowerCase();
        return (u.username || '').toLowerCase().includes(s) || (u.email || '').toLowerCase().includes(s);
    });

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
        { key: 'username', header: 'Username', defaultWidth: 180, minWidth: 120, truncate: false, exportValue: (u) => u.username, render: (u) => <span className="text-gray-900 dark:text-white font-medium truncate">{u.username}</span> },
        { key: 'email', header: 'Email', defaultWidth: 220, exportValue: (u) => u.email || '', render: (u) => <span className="text-xs text-gray-600 dark:text-gray-400 truncate">{u.email}</span> },
        {
            key: 'groups', header: 'Groups', defaultWidth: 240, minWidth: 140, truncate: false,
            exportValue: (u) => (u.groups || []).map((g: any) => g.displayName || g.groupName).join(', '),
            render: (u) => (
                <span className="flex gap-1 flex-wrap">
                    {(u.groups || []).map((g: any) => <span key={g.groupId} className={`inline-block px-2 py-0.5 text-xs rounded border ${groupChipClass(g)}`}>{g.displayName || g.groupName}</span>)}
                    {(u.groups || []).length === 0 && <span className="text-xs text-gray-500">-</span>}
                </span>
            ),
        },
        { key: 'lastLogin', header: 'Last Login', defaultWidth: 160, exportValue: (u) => formatDate(u.lastLogin || u.lastLoginAt), render: (u) => <span className="text-xs text-gray-600 dark:text-gray-400">{formatDate(u.lastLogin || u.lastLoginAt)}</span> },
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
                <p className="text-[11px] text-gray-500 pt-3">Open the full page to manage groups or the account.</p>
            </div>
        );
    };

    return (
        <div className="p-3 sm:p-6 space-y-4 sm:space-y-6">
            <div className="flex items-center justify-between gap-3 flex-wrap">
                <div className="flex items-center gap-4">
                    <h1 className="text-2xl font-bold text-gray-900 dark:text-white">Users</h1>
                    <div className="flex gap-1 border-b border-gray-200 dark:border-gray-800">
                        {([['people', 'People'], ['service', 'Service identities']] as const).map(([k, label]) => (
                            <button key={k} onClick={() => setTab(k)}
                                className={`px-3 py-1.5 text-sm font-medium border-b-2 -mb-px transition-colors ${tab === k ? 'border-blue-600 text-blue-700 dark:text-blue-400' : 'border-transparent text-gray-600 dark:text-gray-400 hover:text-gray-900 dark:hover:text-white'}`}>
                                {label}
                            </button>
                        ))}
                    </div>
                </div>
                {tab === 'people' && (
                    <button onClick={() => setShowCreate(!showCreate)} className="px-4 py-2 text-sm bg-blue-600 text-white rounded hover:bg-blue-700 transition-colors">
                        {showCreate ? 'Cancel' : 'Create User'}
                    </button>
                )}
            </div>

            {tab === 'service' && <ServiceIdentitiesPanel />}

            {tab === 'people' && (<>
            {/* Create User Form */}
            {showCreate && (
                <form onSubmit={handleCreate} className="bg-gray-100 dark:bg-gray-800 border border-gray-300 dark:border-gray-700 rounded-lg p-4 space-y-3">
                    <h3 className="text-sm font-semibold text-gray-900 dark:text-white">New User</h3>
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                        <input type="text" placeholder="Username" required value={createForm.username} onChange={(e) => setCreateForm({ ...createForm, username: e.target.value })}
                            className="px-3 py-2 bg-gray-50 dark:bg-gray-900 border border-gray-300 dark:border-gray-700 rounded text-sm text-gray-900 dark:text-white placeholder-gray-400 dark:placeholder-gray-500 focus:outline-none focus:border-blue-500" />
                        <input type="email" placeholder="Email" required value={createForm.email} onChange={(e) => setCreateForm({ ...createForm, email: e.target.value })}
                            className="px-3 py-2 bg-gray-50 dark:bg-gray-900 border border-gray-300 dark:border-gray-700 rounded text-sm text-gray-900 dark:text-white placeholder-gray-400 dark:placeholder-gray-500 focus:outline-none focus:border-blue-500" />
                        <input type="password" placeholder="Password" required value={createForm.password} onChange={(e) => setCreateForm({ ...createForm, password: e.target.value })}
                            className="px-3 py-2 bg-gray-50 dark:bg-gray-900 border border-gray-300 dark:border-gray-700 rounded text-sm text-gray-900 dark:text-white placeholder-gray-400 dark:placeholder-gray-500 focus:outline-none focus:border-blue-500" />
                        <input type="text" placeholder="First Name" required value={createForm.firstName} onChange={(e) => setCreateForm({ ...createForm, firstName: e.target.value })}
                            className="px-3 py-2 bg-gray-50 dark:bg-gray-900 border border-gray-300 dark:border-gray-700 rounded text-sm text-gray-900 dark:text-white placeholder-gray-400 dark:placeholder-gray-500 focus:outline-none focus:border-blue-500" />
                        <input type="text" placeholder="Last Name" required value={createForm.lastName} onChange={(e) => setCreateForm({ ...createForm, lastName: e.target.value })}
                            className="px-3 py-2 bg-gray-50 dark:bg-gray-900 border border-gray-300 dark:border-gray-700 rounded text-sm text-gray-900 dark:text-white placeholder-gray-400 dark:placeholder-gray-500 focus:outline-none focus:border-blue-500" />
                    </div>
                    <div>
                        <label className="text-xs text-gray-600 dark:text-gray-400 block mb-2">Groups (select one or more):</label>
                        <div className="flex flex-wrap gap-2 max-h-32 overflow-y-auto p-2 bg-gray-50 dark:bg-gray-900 border border-gray-300 dark:border-gray-700 rounded">
                            {allGroups.map((g) => {
                                const selected = createForm.groupIds.includes(g.id);
                                return (
                                    <button key={g.id} type="button" onClick={() => toggleCreateGroup(g.id)}
                                        className={`px-2 py-1 text-xs rounded border transition-colors ${selected ? 'bg-blue-50 dark:bg-blue-900/50 text-blue-800 dark:text-blue-300 border-blue-300 dark:border-blue-700' : 'bg-gray-200/50 dark:bg-gray-700/50 text-gray-600 dark:text-gray-400 border-gray-400 dark:border-gray-600 hover:bg-gray-200 dark:hover:bg-gray-700'}`}>
                                        {selected ? '✓ ' : ''}{g.displayName || g.name}
                                    </button>
                                );
                            })}
                            {allGroups.length === 0 && <span className="text-xs text-gray-600">No groups available</span>}
                        </div>
                    </div>
                    <button type="submit" disabled={creating} className="px-4 py-2 text-sm bg-green-600 text-white rounded hover:bg-green-700 disabled:opacity-50 transition-colors">
                        {creating ? 'Creating...' : 'Create'}
                    </button>
                </form>
            )}

            <input type="text" placeholder="Search by username or email..." value={search} onChange={(e) => setSearch(e.target.value)}
                className="w-full max-w-md px-3 py-2 bg-gray-100 dark:bg-gray-800 border border-gray-300 dark:border-gray-700 rounded text-sm text-gray-900 dark:text-white placeholder-gray-400 dark:placeholder-gray-500 focus:outline-none focus:border-blue-500" />

            <DataTable<any>
                tableId="users"
                title="All Users"
                rows={filteredUsers}
                rowKey={(u) => u.id || u.username}
                loading={loading}
                error={error}
                empty="No users found"
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
