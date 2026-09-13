import React, { useState, useEffect } from 'react';
import { apiGet, apiPost, apiDeleteWithMfa } from '../api/client';
import { useStepUp } from '../components/StepUpMfaContext';
import { useToast } from '@shared/context/ToastContext';
import { StatusBadge } from '@shared/components/cards/StatusBadge';
import { DetailField } from '@shared/components/cards/DetailField';
import ConfirmModal from '../components/ConfirmModal';
import { DataTable, DataTableColumn, DataTableBulkAction } from '@shared/components/DataTable';
import { StepUpOps } from '@shared/generated';
import { caRowId, caDisplayName } from './profileHelpers';
import { inputClass, labelClass } from '@shared/components/forms';
import {
    RequestProfileRulesEditor, emptyRules, serializeRules,
    type RequestProfileRules,
} from '../components/RequestProfileRulesEditor';

/* read-only drawer for a request profile row */
const RequestProfileDrawer: React.FC<{ profile: any; parentName: (id?: string | null) => string | undefined }> = ({ profile: p, parentName }) => (
    <div className="text-sm">
        <DetailField label="Name" value={p.name} />
        <DetailField label="Description" value={p.description} />
        <DetailField label="Require Approval" value={p.requireApproval ? 'Yes' : 'No'} />
        <DetailField label="Max Validity" value={p.maxValidityPeriod} />
        <DetailField label="Subject DN Rules" value={`${p.subjectDnRules?.length || 0} rule(s)`} />
        <DetailField label="SAN Required" value={p.sanRules?.required ? 'Yes' : 'No'} />
        {p.inheritanceEnabled && <DetailField label="Inherits From" value={parentName(p.inheritsFromId) || 'None'} />}
        <DetailField label="CA Scope" value={p.certificateAuthorityId ? String(p.certificateAuthorityId) : 'System-wide'} />
        <p className="text-[11px] text-gray-500 pt-3">Open the full page to view rules or edit.</p>
    </div>
);

/// <summary>
/// Request Profiles tab: a DataTable of enrollment request profiles plus a create form. Row detail
/// and editing live on the /profiles/request/:id page.
/// </summary>
const RequestProfiles: React.FC = () => {
    const { requireStepUp } = useStepUp();
    const { showToast } = useToast();
    const [profiles, setProfiles] = useState<any[]>([]);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState<string | null>(null);
    const [showCreate, setShowCreate] = useState(false);
    const [creating, setCreating] = useState(false);
    const [certProfiles, setCertProfiles] = useState<any[]>([]);
    const [authorities, setAuthorities] = useState<any[]>([]);
    const [confirmDelete, setConfirmDelete] = useState<any | null>(null);
    const [deleting, setDeleting] = useState(false);

    const [form, setForm] = useState({
        name: '', description: '', requireApproval: false, maxValidityPeriod: '',
        defaultCertProfileId: '',
        rules: emptyRules() as RequestProfileRules,
        inheritsFromId: '', inheritanceEnabled: false, certificateAuthorityId: '',
    });

    const resetForm = () => setForm({
        name: '', description: '', requireApproval: false, maxValidityPeriod: '',
        defaultCertProfileId: '',
        rules: emptyRules(),
        inheritsFromId: '', inheritanceEnabled: false, certificateAuthorityId: '',
    });

    const load = () => {
        setLoading(true);
        setError(null);
        apiGet<any>('/api/v1/admin/request-profiles')
            .then((data) => setProfiles(Array.isArray(data) ? data : (data.items || data.profiles || [])))
            .catch((err) => setError(err.message))
            .finally(() => setLoading(false));
    };

    useEffect(() => {
        load();
        apiGet<any>('/api/v1/admin/cert-profiles')
            .then((data) => setCertProfiles(Array.isArray(data) ? data : (data.items || data.profiles || [])))
            .catch(() => {});
        apiGet<any>('/api/v1/admin/authorities')
            .then((data) => setAuthorities(Array.isArray(data) ? data : (data.items || data.authorities || [])))
            .catch(() => {});
    }, []);

    const resolveParentName = (id: string | undefined | null) => {
        if (!id) return undefined;
        const p = profiles.find((pr) => pr.id === id);
        return p ? p.name : id;
    };

    const handleCreate = async () => {
        setCreating(true);
        try {
            const body = {
                name: form.name,
                description: form.description || undefined,
                requireApproval: form.requireApproval,
                maxValidityPeriod: form.maxValidityPeriod || undefined,
                defaultCertProfileId: form.defaultCertProfileId || undefined,
                // serializeRules, not a hand-rolled projection: this form used to post
                // `rules: {}` unconditionally, so a per-SAN-type regex or maxCount could not be
                // created here at all and had to be added afterwards through the edit page's JSON.
                ...serializeRules(form.rules),
                inheritsFromId: form.inheritsFromId || undefined,
                inheritanceEnabled: form.inheritanceEnabled,
                certificateAuthorityId: form.certificateAuthorityId || undefined,
            };
            await apiPost('/api/v1/admin/request-profiles', body);
            setShowCreate(false);
            resetForm();
            load();
        } catch (err: any) {
            showToast('error', err.message || 'Failed to create request profile');
        } finally {
            setCreating(false);
        }
    };

    const performDelete = async () => {
        if (!confirmDelete) return;
        setDeleting(true);
        try {
            await apiDeleteWithMfa(`/api/v1/admin/request-profiles/${confirmDelete.id}`, requireStepUp, StepUpOps.DeleteRequestProfile, confirmDelete.id);
            showToast('success', 'Request profile deleted');
            load();
        } catch (err: any) {
            if (err.message !== 'Step-up MFA cancelled') showToast('error', err.message || 'Failed to delete request profile');
        } finally {
            setDeleting(false);
            setConfirmDelete(null);
        }
    };

    const columns: DataTableColumn<any>[] = [
        {
            key: 'name', header: 'Name', defaultWidth: 240, minWidth: 160, truncate: false, exportValue: (p) => p.name,
            render: (p) => (
                <span className="flex items-center gap-2 min-w-0">
                    <span className="text-gray-900 dark:text-white font-medium truncate">{p.name}</span>
                    {p.inheritanceEnabled && p.inheritsFromId && (
                        <span className="px-2 py-0.5 text-[10px] rounded bg-purple-100 dark:bg-purple-900/40 text-purple-700 dark:text-purple-300 border border-purple-300 dark:border-purple-700 shrink-0">Inherits: {resolveParentName(p.inheritsFromId)}</span>
                    )}
                </span>
            ),
        },
        { key: 'approval', header: 'Approval', defaultWidth: 110, truncate: false, exportValue: (p) => (p.requireApproval ? 'Required' : 'Auto'), render: (p) => <StatusBadge status={p.requireApproval ? 'pending' : 'enabled'} label={p.requireApproval ? 'Required' : 'Auto'} /> },
        { key: 'dnRules', header: 'DN Rules', defaultWidth: 100, exportValue: (p) => (p.subjectDnRules?.length || 0), render: (p) => <span className="text-xs text-gray-700 dark:text-gray-300">{p.subjectDnRules?.length || 0} rules</span> },
        { key: 'san', header: 'SAN', defaultWidth: 110, truncate: false, exportValue: (p) => (p.sanRules?.required ? 'Required' : 'Optional'), render: (p) => <StatusBadge status={p.sanRules?.required ? 'active' : 'disabled'} label={p.sanRules?.required ? 'Required' : 'Optional'} /> },
        { key: 'maxValidity', header: 'Max Validity', defaultWidth: 130, exportValue: (p) => p.maxValidityPeriod || '', render: (p) => <span className="text-xs text-gray-600 dark:text-gray-400">{p.maxValidityPeriod || '-'}</span> },
    ];

    const bulkActions: DataTableBulkAction<any>[] = [
        { label: 'Delete', single: true, variant: 'danger', onClick: (rows) => setConfirmDelete(rows[0]) },
    ];

    return (
        <div className="space-y-4">
            <p className="text-sm text-gray-600 dark:text-gray-400">
                Manage enrollment request profiles that define subject DN rules, SAN constraints, and approval requirements.
            </p>

            <div className="flex items-center justify-between">
                <h3 className="text-sm font-semibold text-gray-900 dark:text-white">All Profiles</h3>
                <button onClick={() => setShowCreate(!showCreate)} className="px-4 py-2 text-sm bg-blue-600 text-white rounded hover:bg-blue-700 transition-colors">
                    {showCreate ? 'Cancel' : 'Create Profile'}
                </button>
            </div>

            {/* Create Form */}
            {showCreate && (
                <div className="bg-gray-100 dark:bg-gray-800 border border-gray-300 dark:border-gray-700 rounded-lg p-4 space-y-4">
                    <h4 className="text-sm font-semibold text-gray-900 dark:text-white">New Request Profile</h4>

                    <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                        <div>
                            <label className={labelClass}>Name</label>
                            <input type="text" value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} className={inputClass} placeholder="e.g. Standard TLS Request" />
                        </div>
                        <div>
                            <label className={labelClass}>Description</label>
                            <input type="text" value={form.description} onChange={(e) => setForm({ ...form, description: e.target.value })} className={inputClass} placeholder="Optional description" />
                        </div>
                        <div>
                            <label className={labelClass}>Max Validity Period (ISO 8601)</label>
                            <input type="text" value={form.maxValidityPeriod} onChange={(e) => setForm({ ...form, maxValidityPeriod: e.target.value })} className={inputClass} placeholder="e.g. P365D or P1Y" />
                        </div>
                        <div>
                            <label className={labelClass}>Default Certificate Profile</label>
                            <select value={form.defaultCertProfileId} onChange={(e) => setForm({ ...form, defaultCertProfileId: e.target.value })} className={inputClass}>
                                <option value="">-- None --</option>
                                {certProfiles.map((cp) => { const cpId = cp.id || cp.certProfileId; return <option key={cpId} value={cpId}>{cp.name}</option>; })}
                            </select>
                        </div>
                    </div>

                    <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                        <div>
                            <label className={labelClass}>Inherits From</label>
                            <select value={form.inheritsFromId} onChange={(e) => setForm({ ...form, inheritsFromId: e.target.value })} className={inputClass}>
                                <option value="">-- None (standalone) --</option>
                                {profiles.map((pr) => <option key={pr.id} value={pr.id}>{pr.name}</option>)}
                            </select>
                        </div>
                        <div>
                            <label className={labelClass}>CA Scope</label>
                            <select value={form.certificateAuthorityId} onChange={(e) => setForm({ ...form, certificateAuthorityId: e.target.value })} className={inputClass}>
                                <option value="">-- System-wide --</option>
                                {authorities.map((a) => <option key={caRowId(a)} value={caRowId(a)}>{caDisplayName(a)}</option>)}
                            </select>
                        </div>
                    </div>

                    <div className="flex flex-wrap gap-4">
                        <label className="flex items-center gap-2 text-xs text-gray-700 dark:text-gray-300">
                            <input type="checkbox" checked={form.requireApproval} onChange={(e) => setForm({ ...form, requireApproval: e.target.checked })} className="w-4 h-4 rounded" />
                            Require Approval
                        </label>
                        <label className="flex items-center gap-2 text-xs text-gray-700 dark:text-gray-300">
                            <input type="checkbox" checked={form.inheritanceEnabled} onChange={(e) => setForm({ ...form, inheritanceEnabled: e.target.checked })} className="w-4 h-4 rounded" />
                            Enable Inheritance
                        </label>
                    </div>

                    <RequestProfileRulesEditor
                        value={form.rules}
                        onChange={(rules) => setForm({ ...form, rules })}
                    />


                    <button onClick={handleCreate} disabled={creating || !form.name} className="px-4 py-2 text-sm bg-blue-600 text-white rounded hover:bg-blue-700 disabled:opacity-50 transition-colors">
                        {creating ? 'Creating...' : 'Create'}
                    </button>
                </div>
            )}

            <DataTable<any>
                tableId="request-profiles"
                title="Request Profiles"
                rows={profiles}
                rowKey={(p) => p.id}
                loading={loading}
                error={error}
                empty="No request profiles found"
                columns={columns}
                selectable
                bulkActions={bulkActions}
                exportFileName="request-profiles"
                renderDrawer={(p) => <RequestProfileDrawer profile={p} parentName={resolveParentName} />}
                drawerTitle={(p) => p.name}
                detailPath={(p) => `/profiles/request/${p.id}`}
            />

            <ConfirmModal
                isOpen={!!confirmDelete}
                title="Delete Request Profile"
                message={confirmDelete ? `Delete request profile "${confirmDelete.name}"? This cannot be undone.` : ''}
                confirmLabel="Delete"
                confirmClass="bg-red-600 hover:bg-red-700"
                loading={deleting}
                onConfirm={performDelete}
                onCancel={() => setConfirmDelete(null)}
            />
        </div>
    );
};

export default RequestProfiles;
