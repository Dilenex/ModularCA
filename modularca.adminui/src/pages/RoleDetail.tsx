import React, { useEffect, useState } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { apiGet, apiPutWithMfa, apiDeleteWithMfa } from '../api/client';
import { useToast } from '@shared/context/ToastContext';
import { useStepUp } from '../components/StepUpMfaContext';
import { StatusBadge } from '@shared/components/cards/StatusBadge';
import { DetailField } from '@shared/components/cards/DetailField';
import ConfirmModal from '../components/ConfirmModal';
import { DetailPage, DetailSection } from '../components/DetailPage';
import { capabilityCategory, categoryStatus } from './RoleManagement';
import type { RoleDetail as RoleDetailModel, RoleCapability } from './RoleManagement';
import { StepUpOps } from '@shared/generated';
import { inputClass as inputCls, labelClass as labelCls } from '@shared/components/forms';

const ALL_CAPABILITIES = [
    'cert.request', 'cert.view', 'cert.revoke', 'cert.reissue', 'cert.approve',
    'profile.view', 'profile.use', 'profile.manage', 'profile.assign',
    'token.create', 'token.manage',
    'ca.view', 'ca.manage',
    'group.view', 'group.manage', 'user.manage',
    'audit.view', 'backup.manage', 'system.manage',
];


type CapEdit = { capability: string; resourceType?: string; resourceId?: string };

function formatDate(d: string | null) {
    if (!d) return '-';
    return new Date(d).toLocaleDateString('en-US', { year: 'numeric', month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' });
}

/// <summary>
/// Editable detail page for a single role: view its metadata and capabilities, and in edit mode
/// rename/redescribe the role plus add/remove capabilities. All edits (fields and capability set)
/// are persisted together via a single step-up-gated Save. Built-in roles are read-only.
/// </summary>
const RoleDetail: React.FC = () => {
    const { id } = useParams<{ id: string }>();
    const navigate = useNavigate();
    const { showToast } = useToast();
    const { requireStepUp } = useStepUp();

    const [role, setRole] = useState<RoleDetailModel | null>(null);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState<string | null>(null);
    const [refresh, setRefresh] = useState(0);

    const [form, setForm] = useState({ name: '', description: '' });
    const [capsEdit, setCapsEdit] = useState<CapEdit[]>([]);
    const [initial, setInitial] = useState<{ name: string; description: string; caps: CapEdit[] }>({ name: '', description: '', caps: [] });

    // Add capability state
    const [newCapability, setNewCapability] = useState('');
    const [newResourceType, setNewResourceType] = useState('');
    const [newResourceId, setNewResourceId] = useState('');

    const [confirm, setConfirm] = useState<{ title: string; message: string; action: () => Promise<void> } | null>(null);
    const [confirmLoading, setConfirmLoading] = useState(false);

    useEffect(() => {
        let cancelled = false;
        setLoading(true);
        setError(null);
        apiGet<RoleDetailModel>(`/api/v1/admin/roles/${id}`)
            .then((r) => {
                if (cancelled) return;
                setRole(r);
                if (r) {
                    setForm({ name: r.name || '', description: r.description || '' });
                    const caps: CapEdit[] = (r.capabilities || []).map((c) => ({ capability: c.capability, resourceType: c.resourceType || undefined, resourceId: c.resourceId || undefined }));
                    setCapsEdit(caps);
                    setInitial({ name: r.name || '', description: r.description || '', caps });
                }
                setLoading(false);
            })
            .catch((err) => { if (!cancelled) { setError(err.message || 'Failed to load role'); setLoading(false); } });
        return () => { cancelled = true; };
    }, [id, refresh]);

    const dirty = JSON.stringify({ name: form.name, description: form.description, caps: capsEdit }) !== JSON.stringify(initial);

    const handleSave = async () => {
        try {
            await apiPutWithMfa(`/api/v1/admin/roles/${id}`, {
                name: form.name,
                description: form.description,
                capabilities: capsEdit.map((c) => ({ capability: c.capability, resourceType: c.resourceType || undefined, resourceId: c.resourceId || undefined })),
            }, requireStepUp, StepUpOps.UpdateRole, id!);
            showToast('success', 'Role updated');
            setRefresh((r) => r + 1);
        } catch (err: any) {
            if (err.message !== 'Step-up MFA cancelled') showToast('error', err.message || 'Failed to update role');
            throw err;
        }
    };

    const handleCancel = () => {
        setForm({ name: initial.name, description: initial.description });
        setCapsEdit(initial.caps);
        setNewCapability('');
        setNewResourceType('');
        setNewResourceId('');
    };

    const addCapability = () => {
        if (!newCapability) return;
        const rt = newResourceType || undefined;
        const rid = newResourceId || undefined;
        const exists = capsEdit.some((c) => c.capability === newCapability && (c.resourceType || undefined) === rt && (c.resourceId || undefined) === rid);
        if (!exists) {
            setCapsEdit((prev) => [...prev, { capability: newCapability, resourceType: rt, resourceId: rid }]);
        }
        setNewCapability('');
        setNewResourceType('');
        setNewResourceId('');
    };

    const removeCapability = (cap: CapEdit) => {
        setCapsEdit((prev) => prev.filter((c) => !(c.capability === cap.capability && (c.resourceType || undefined) === (cap.resourceType || undefined) && (c.resourceId || undefined) === (cap.resourceId || undefined))));
    };

    const deleteRole = () => {
        if (!role) return;
        setConfirm({
            title: 'Delete Role',
            message: `Delete "${role.name}"? This cannot be undone.`,
            action: async () => { await apiDeleteWithMfa(`/api/v1/admin/roles/${id}`, requireStepUp, StepUpOps.DeleteRole, id!); navigate('/roles'); },
        });
    };

    if (loading) return <div className="p-6 text-sm text-gray-600 dark:text-gray-400">Loading…</div>;
    if (error) return <div className="p-6 text-sm text-red-800 dark:text-red-400">{error}</div>;
    if (!role) return (
        <div className="p-6 space-y-3">
            <p className="text-sm text-gray-600 dark:text-gray-400">Role not found.</p>
            <button onClick={() => navigate('/roles')} className="px-3 py-1.5 text-sm bg-gray-200 dark:bg-gray-700 rounded">Back to Roles</button>
        </div>
    );

    const viewCaps: RoleCapability[] = role.capabilities || [];
    const groupedView: Record<string, RoleCapability[]> = {};
    for (const cap of viewCaps) {
        const cat = capabilityCategory(cap.capability);
        (groupedView[cat] ||= []).push(cap);
    }
    const groupedEdit: Record<string, CapEdit[]> = {};
    for (const cap of capsEdit) {
        const cat = capabilityCategory(cap.capability);
        (groupedEdit[cat] ||= []).push(cap);
    }

    return (
        <DetailPage
            breadcrumbs={[{ label: 'Roles', to: '/roles' }, { label: role.name }]}
            title={role.name}
            status={<StatusBadge status={role.isBuiltIn ? 'pending' : 'active'} label={role.isBuiltIn ? 'Built-in' : 'Custom'} />}
            subtitle={role.description ? role.description : undefined}
            editable={!role.isBuiltIn}
            onSave={handleSave}
            onCancel={handleCancel}
            saveDisabled={!dirty || !form.name}
            actions={!role.isBuiltIn ? (
                <button onClick={deleteRole} className="px-3 py-1.5 text-xs bg-red-50 dark:bg-red-900/50 text-red-800 dark:text-red-300 border border-red-300 dark:border-red-700 rounded hover:bg-red-900 transition-colors">Delete</button>
            ) : undefined}
        >
            {(mode) => (<>
                {mode === 'view' ? (
                    <DetailSection title="Role">
                        <div className="grid grid-cols-1 md:grid-cols-2 gap-x-8">
                            <DetailField label="ID" value={role.id} mono />
                            <DetailField label="Name" value={role.name} mono />
                            <DetailField label="Description" value={role.description || '-'} />
                            <DetailField label="Type" value={role.isBuiltIn ? 'Built-in' : 'Custom'} />
                            <DetailField label="Created" value={formatDate(role.createdAt)} />
                            {role.tenantId && <DetailField label="Tenant" value={role.tenantId} mono />}
                        </div>
                    </DetailSection>
                ) : (
                    <DetailSection title="Edit Role">
                        <div className="space-y-4 max-w-2xl">
                            <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                                <div>
                                    <label className={labelCls}>Name</label>
                                    <input type="text" value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} className={inputCls} />
                                </div>
                                <div>
                                    <label className={labelCls}>Description</label>
                                    <input type="text" value={form.description} onChange={(e) => setForm({ ...form, description: e.target.value })} className={inputCls} />
                                </div>
                            </div>
                        </div>
                    </DetailSection>
                )}

                <DetailSection title={`Capabilities (${mode === 'edit' ? capsEdit.length : viewCaps.length})`}>
                    {mode === 'edit' && (
                        <div className="bg-gray-50 dark:bg-gray-900/50 border border-gray-300 dark:border-gray-700 rounded p-3 mb-4 space-y-2">
                            <div className="grid grid-cols-1 md:grid-cols-3 gap-2">
                                <div>
                                    <label className={labelCls}>Capability</label>
                                    <select value={newCapability} onChange={(e) => setNewCapability(e.target.value)} className={inputCls}>
                                        <option value="">Select capability…</option>
                                        {ALL_CAPABILITIES.map((cap) => <option key={cap} value={cap}>[{capabilityCategory(cap)}] {cap}</option>)}
                                    </select>
                                </div>
                                <div>
                                    <label className={labelCls}>Resource Type (optional)</label>
                                    <input type="text" value={newResourceType} onChange={(e) => setNewResourceType(e.target.value)} placeholder="e.g., ca, profile" className={inputCls} />
                                </div>
                                <div>
                                    <label className={labelCls}>Resource ID (optional)</label>
                                    <input type="text" value={newResourceId} onChange={(e) => setNewResourceId(e.target.value)} placeholder="specific resource ID" className={inputCls} />
                                </div>
                            </div>
                            <button onClick={addCapability} disabled={!newCapability} className="px-3 py-1.5 text-xs bg-green-600 text-white rounded hover:bg-green-700 disabled:opacity-50">Add Capability</button>
                        </div>
                    )}

                    {mode === 'edit' ? (
                        capsEdit.length === 0 ? (
                            <div className="text-xs text-gray-500">No capabilities assigned to this role.</div>
                        ) : (
                            Object.entries(groupedEdit).map(([category, caps]) => (
                                <div key={category} className="mb-3 last:mb-0">
                                    <div className="flex items-center gap-2 mb-1">
                                        <StatusBadge status={categoryStatus(category)} label={category} />
                                        <span className="text-[10px] text-gray-500">({caps.length})</span>
                                    </div>
                                    <div className="bg-gray-50 dark:bg-gray-900/40 border border-gray-300 dark:border-gray-700 rounded overflow-hidden">
                                        <div className="px-3 py-1 border-b border-gray-300 dark:border-gray-700 grid grid-cols-[1fr_120px_120px_70px] gap-2 text-[10px] text-gray-500 font-semibold">
                                            <span>Capability</span>
                                            <span>Resource Type</span>
                                            <span>Resource ID</span>
                                            <span></span>
                                        </div>
                                        {caps.map((cap) => (
                                            <div key={`${cap.capability}|${cap.resourceType || ''}|${cap.resourceId || ''}`} className="px-3 py-1.5 border-b border-gray-200 dark:border-gray-700 last:border-b-0 grid grid-cols-[1fr_120px_120px_70px] gap-2 items-center">
                                                <span className="text-xs text-gray-900 dark:text-white font-mono truncate">{cap.capability}</span>
                                                <span className="text-xs text-gray-600 dark:text-gray-400">{cap.resourceType || '-'}</span>
                                                <span className="text-xs text-gray-600 dark:text-gray-400 font-mono truncate">{cap.resourceId || '-'}</span>
                                                <button onClick={() => removeCapability(cap)} className="px-2 py-0.5 text-[10px] bg-red-50 dark:bg-red-900/50 text-red-800 dark:text-red-300 border border-red-300 dark:border-red-700 rounded hover:bg-red-900 transition-colors">Remove</button>
                                            </div>
                                        ))}
                                    </div>
                                </div>
                            ))
                        )
                    ) : (
                        viewCaps.length === 0 ? (
                            <div className="text-xs text-gray-500">No capabilities assigned to this role.</div>
                        ) : (
                            Object.entries(groupedView).map(([category, caps]) => (
                                <div key={category} className="mb-3 last:mb-0">
                                    <div className="flex items-center gap-2 mb-1">
                                        <StatusBadge status={categoryStatus(category)} label={category} />
                                        <span className="text-[10px] text-gray-500">({caps.length})</span>
                                    </div>
                                    <div className="bg-gray-50 dark:bg-gray-900/40 border border-gray-300 dark:border-gray-700 rounded overflow-hidden">
                                        <div className="px-3 py-1 border-b border-gray-300 dark:border-gray-700 grid grid-cols-[1fr_120px_120px_70px] gap-2 text-[10px] text-gray-500 font-semibold">
                                            <span>Capability</span>
                                            <span>Resource Type</span>
                                            <span>Resource ID</span>
                                            <span></span>
                                        </div>
                                        {caps.map((cap) => (
                                            <div key={`${cap.capability}|${cap.resourceType || ''}|${cap.resourceId || ''}`} className="px-3 py-1.5 border-b border-gray-200 dark:border-gray-700 last:border-b-0 grid grid-cols-[1fr_120px_120px_70px] gap-2 items-center">
                                                <span className="text-xs text-gray-900 dark:text-white font-mono truncate">{cap.capability}</span>
                                                <span className="text-xs text-gray-600 dark:text-gray-400">{cap.resourceType || '-'}</span>
                                                <span className="text-xs text-gray-600 dark:text-gray-400 font-mono truncate">{cap.resourceId || '-'}</span>
                                                <span />
                                            </div>
                                        ))}
                                    </div>
                                </div>
                            ))
                        )
                    )}
                    {mode === 'view' && !role.isBuiltIn && <p className="text-[11px] text-gray-500 mt-2">Switch to Edit to add or remove capabilities.</p>}
                    {role.isBuiltIn && <p className="text-[11px] text-gray-500 mt-2">Built-in roles are read-only.</p>}
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

export default RoleDetail;
