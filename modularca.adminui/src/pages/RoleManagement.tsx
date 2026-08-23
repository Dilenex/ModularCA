import React, { useState, useEffect } from 'react';
import { apiGet, apiPostWithMfa, apiDeleteWithMfa } from '../api/client';
import { useToast } from '../context/ToastContext';
import { useStepUp } from '../components/StepUpMfaContext';
import StatusBadge from '../components/cards/StatusBadge';
import DetailField from '../components/cards/DetailField';
import ConfirmModal from '../components/ConfirmModal';
import { DataTable, DataTableColumn, DataTableBulkAction } from '../components/DataTable';
import { StepUpOps } from '@shared/generated';

/// <summary>
/// Returns the display category for a capability string.
/// </summary>
function capabilityCategory(cap: string): string {
    if (cap.startsWith('cert.')) return 'Certificate';
    if (cap.startsWith('profile.')) return 'Profile';
    if (cap.startsWith('token.')) return 'Token';
    if (cap.startsWith('ca.')) return 'CA';
    return 'Admin';
}

/// <summary>
/// Returns a StatusBadge-compatible status string for a capability category.
/// </summary>
function categoryStatus(category: string): 'active' | 'pending' | 'held' | 'revoked' | 'disabled' {
    switch (category) {
        case 'Certificate': return 'active';
        case 'Profile': return 'pending';
        case 'Token': return 'held';
        case 'CA': return 'revoked';
        case 'Admin': return 'disabled';
        default: return 'disabled';
    }
}

interface RoleSummary {
    id: string;
    name: string;
    description: string;
    isBuiltIn: boolean;
    tenantId: string | null;
    capabilityCount: number;
    createdAt: string;
}

interface RoleCapability {
    id: string;
    capability: string;
    resourceType: string | null;
    resourceId: string | null;
}

interface RoleDetail {
    id: string;
    name: string;
    description: string;
    isBuiltIn: boolean;
    tenantId: string | null;
    createdAt: string;
    capabilities: RoleCapability[];
}

/* ── read-only drawer (fetches role detail incl. capabilities) ───────────────── */
const RoleDrawer: React.FC<{ role: RoleSummary }> = ({ role }) => {
    const [detail, setDetail] = useState<RoleDetail | null>(null);
    useEffect(() => {
        let cancelled = false;
        apiGet<RoleDetail>(`/api/v1/admin/roles/${role.id}`).then((d) => { if (!cancelled) setDetail(d); }).catch(() => { });
        return () => { cancelled = true; };
    }, [role.id]);
    const caps: RoleCapability[] = detail?.capabilities || [];
    return (
        <div className="text-sm">
            <DetailField label="Name" value={role.name} mono />
            <DetailField label="Description" value={role.description || '-'} />
            <DetailField label="Type" value={role.isBuiltIn ? 'Built-in' : 'Custom'} />
            {detail?.tenantId && <DetailField label="Tenant" value={detail.tenantId} mono />}
            <div className="mt-3">
                <span className="text-xs text-gray-500">Capabilities ({detail ? caps.length : '…'})</span>
                <div className="mt-1 space-y-0.5">
                    {detail && caps.length === 0 && <span className="text-xs text-gray-500">No capabilities.</span>}
                    {caps.map((c) => (
                        <div key={c.id} className="text-xs text-gray-800 dark:text-gray-200 font-mono">
                            {c.capability}{c.resourceType ? <span className="text-gray-500"> · {c.resourceType}</span> : null}
                        </div>
                    ))}
                </div>
            </div>
            <p className="text-[11px] text-gray-500 pt-3">Open the full page to edit or manage capabilities.</p>
        </div>
    );
};

/// <summary>
/// Role management page with a reusable DataTable list, read-only drawer peek, and an editable
/// detail page at /roles/:id. Built-in roles are read-only.
/// </summary>
const RoleManagement: React.FC = () => {
    const { showToast } = useToast();
    // These endpoints carry [RequireStepUp]; the plain api helpers never attach
    // X-MFA-Token and never retry, so role create/delete always 403'd with an MFA error
    // and no modal to satisfy it.
    const { requireStepUp } = useStepUp();
    const [roles, setRoles] = useState<RoleSummary[]>([]);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState<string | null>(null);
    const [refreshTrigger, setRefreshTrigger] = useState(0);

    const [showCreate, setShowCreate] = useState(false);
    const [createForm, setCreateForm] = useState({ name: '', description: '' });
    const [creating, setCreating] = useState(false);

    const [confirmBulk, setConfirmBulk] = useState<RoleSummary[] | null>(null);
    const [confirmLoading, setConfirmLoading] = useState(false);

    useEffect(() => {
        let cancelled = false;
        setLoading(true);
        setError(null);
        apiGet<any>('/api/v1/admin/roles')
            .then((data) => {
                if (cancelled) return;
                setRoles(Array.isArray(data) ? data : (data.items || data.roles || []));
                setLoading(false);
            })
            .catch((err) => {
                if (!cancelled) {
                    setError(err.message || 'Failed to load roles');
                    setLoading(false);
                }
            });
        return () => { cancelled = true; };
    }, [refreshTrigger]);

    const handleCreate = async (e: React.FormEvent) => {
        e.preventDefault();
        setCreating(true);
        try {
            await apiPostWithMfa('/api/v1/admin/roles', {
                name: createForm.name,
                description: createForm.description,
            }, requireStepUp, StepUpOps.CreateRole);
            setShowCreate(false);
            setCreateForm({ name: '', description: '' });
            setRefreshTrigger((t) => t + 1);
        } catch (err: any) {
            showToast('error', err.message || 'Failed to create role');
        } finally {
            setCreating(false);
        }
    };

    const performBulkDelete = async () => {
        if (!confirmBulk) return;
        setConfirmLoading(true);
        let ok = 0, failed = 0;
        try {
            for (const r of confirmBulk) {
                if (r.isBuiltIn) continue;
                try { await apiDeleteWithMfa(`/api/v1/admin/roles/${r.id}`, requireStepUp, StepUpOps.DeleteRole, r.id); ok++; } catch { failed++; }
            }
            if (ok) showToast('success', `Deleted ${ok} role${ok !== 1 ? 's' : ''}.`);
            if (failed) showToast('error', `${failed} failed to delete.`);
            setRefreshTrigger((t) => t + 1);
        } finally {
            setConfirmLoading(false);
            setConfirmBulk(null);
        }
    };

    const columns: DataTableColumn<RoleSummary>[] = [
        { key: 'name', header: 'Name', defaultWidth: 220, minWidth: 140, truncate: false, exportValue: (r) => r.name, render: (r) => <span className="text-gray-900 dark:text-white font-medium truncate">{r.name}</span> },
        { key: 'description', header: 'Description', defaultWidth: 280, exportValue: (r) => r.description || '', render: (r) => <span className="text-xs text-gray-600 dark:text-gray-400 truncate">{r.description || '-'}</span> },
        { key: 'type', header: 'Type', defaultWidth: 110, truncate: false, exportValue: (r) => (r.isBuiltIn ? 'Built-in' : 'Custom'), render: (r) => <StatusBadge status={r.isBuiltIn ? 'pending' : 'active'} label={r.isBuiltIn ? 'Built-in' : 'Custom'} /> },
        { key: 'capabilities', header: 'Capabilities', defaultWidth: 120, exportValue: (r) => (r.capabilityCount ?? 0), render: (r) => <span className="text-xs text-gray-600 dark:text-gray-400">{r.capabilityCount ?? 0}</span> },
    ];

    const bulkActions: DataTableBulkAction<RoleSummary>[] = [
        { label: 'Delete', variant: 'danger', enabledFor: (r) => !r.isBuiltIn, onClick: (rows) => setConfirmBulk(rows) },
    ];

    return (
        <div className="p-3 sm:p-6 space-y-4 sm:space-y-6">
            <div className="flex items-center justify-between">
                <h1 className="text-2xl font-bold text-gray-900 dark:text-white">Role Management</h1>
                <button
                    onClick={() => setShowCreate(!showCreate)}
                    className="px-4 py-2 text-sm bg-blue-600 text-white rounded hover:bg-blue-700 transition-colors"
                >
                    {showCreate ? 'Cancel' : 'Create Role'}
                </button>
            </div>

            {/* Create Role Form */}
            {showCreate && (
                <form onSubmit={handleCreate} className="bg-gray-100 dark:bg-gray-800 border border-gray-300 dark:border-gray-700 rounded-lg p-4 space-y-3">
                    <h3 className="text-sm font-semibold text-gray-900 dark:text-white">New Role</h3>
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                        <input
                            type="text"
                            placeholder="Role name (e.g., certificate-manager)"
                            required
                            value={createForm.name}
                            onChange={(e) => setCreateForm({ ...createForm, name: e.target.value })}
                            className="px-3 py-2 bg-gray-50 dark:bg-gray-900 border border-gray-300 dark:border-gray-700 rounded text-sm text-gray-900 dark:text-white placeholder-gray-400 dark:placeholder-gray-500 focus:outline-none focus:border-blue-500"
                        />
                        <input
                            type="text"
                            placeholder="Description"
                            value={createForm.description}
                            onChange={(e) => setCreateForm({ ...createForm, description: e.target.value })}
                            className="px-3 py-2 bg-gray-50 dark:bg-gray-900 border border-gray-300 dark:border-gray-700 rounded text-sm text-gray-900 dark:text-white placeholder-gray-400 dark:placeholder-gray-500 focus:outline-none focus:border-blue-500"
                        />
                    </div>
                    <button
                        type="submit"
                        disabled={creating}
                        className="px-4 py-2 text-sm bg-green-600 text-white rounded hover:bg-green-700 disabled:opacity-50 transition-colors"
                    >
                        {creating ? 'Creating...' : 'Create'}
                    </button>
                </form>
            )}

            <DataTable<RoleSummary>
                tableId="roles"
                title="All Roles"
                rows={roles}
                rowKey={(r) => r.id}
                loading={loading}
                error={error}
                empty="No roles found"
                columns={columns}
                selectable
                bulkActions={bulkActions}
                exportFileName="roles"
                renderDrawer={(r) => <RoleDrawer role={r} />}
                drawerTitle={(r) => r.name}
                detailPath={(r) => `/roles/${r.id}`}
            />

            <ConfirmModal
                isOpen={!!confirmBulk}
                title="Delete Roles"
                message={confirmBulk ? (() => {
                    const deletable = confirmBulk.filter((r) => !r.isBuiltIn).length;
                    const skipped = confirmBulk.length - deletable;
                    return `Delete ${deletable} role${deletable !== 1 ? 's' : ''}?${skipped ? ` ${skipped} built-in role${skipped !== 1 ? 's' : ''} will be skipped.` : ''} This cannot be undone.`;
                })() : ''}
                confirmLabel="Delete"
                loading={confirmLoading}
                onConfirm={performBulkDelete}
                onCancel={() => setConfirmBulk(null)}
            />
        </div>
    );
};

export default RoleManagement;

export { capabilityCategory, categoryStatus };
export type { RoleSummary, RoleCapability, RoleDetail };
