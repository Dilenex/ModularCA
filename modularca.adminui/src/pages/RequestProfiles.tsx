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

const DN_FIELD_OPTIONS = ['CN', 'O', 'OU', 'L', 'ST', 'C', 'DC'];
const REQUIREMENT_OPTIONS = ['Required', 'Optional', 'Forbidden'];
// UPN must be selectable here or it can never be used: profile validation rejects any SAN whose
// type is absent from a profile's allowedTypes, on the server and in the browser. It is off by
// default on every existing profile, which is the intended posture — a UPN asserts an Active
// Directory identity, so permitting it should be a deliberate per-profile choice.
const SAN_TYPE_OPTIONS = ['DNS', 'IP', 'Email', 'URI', 'UPN'];


interface SubjectDnFieldRule {
    field: string;
    requirement: string;
    fixedValue?: string;
    regex?: string;
    maxLength?: number | null;
    defaultValue?: string;
}

interface SanRulesModel {
    allowedTypes: string[];
    required: boolean;
    rules: Record<string, { regex?: string; maxCount: number }>;
}

const emptyDnRule = (): SubjectDnFieldRule => ({
    field: 'CN', requirement: 'Required', fixedValue: '', regex: '', maxLength: null, defaultValue: '',
});

const emptySanRules = (): SanRulesModel => ({
    allowedTypes: ['DNS', 'IP'], required: false, rules: {},
});

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
        subjectDnRules: [emptyDnRule()] as SubjectDnFieldRule[],
        sanRules: emptySanRules(),
        inheritsFromId: '', inheritanceEnabled: false, certificateAuthorityId: '',
    });

    const resetForm = () => setForm({
        name: '', description: '', requireApproval: false, maxValidityPeriod: '',
        defaultCertProfileId: '',
        subjectDnRules: [emptyDnRule()],
        sanRules: emptySanRules(),
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
                subjectDnRules: form.subjectDnRules.map((r) => ({
                    field: r.field, requirement: r.requirement,
                    fixedValue: r.fixedValue || undefined, regex: r.regex || undefined,
                    maxLength: r.maxLength || undefined, defaultValue: r.defaultValue || undefined,
                })),
                sanRules: { allowedTypes: form.sanRules.allowedTypes, required: form.sanRules.required, rules: {} },
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

    // --- Subject DN Rules builder helpers ---
    const updateDnRule = (index: number, updates: Partial<SubjectDnFieldRule>) => {
        const rules = [...form.subjectDnRules];
        rules[index] = { ...rules[index], ...updates };
        setForm({ ...form, subjectDnRules: rules });
    };
    const addDnRule = () => setForm({ ...form, subjectDnRules: [...form.subjectDnRules, emptyDnRule()] });
    const removeDnRule = (index: number) => {
        const rules = form.subjectDnRules.filter((_, i) => i !== index);
        setForm({ ...form, subjectDnRules: rules.length > 0 ? rules : [emptyDnRule()] });
    };
    const toggleSanType = (type: string) => {
        const current = form.sanRules.allowedTypes;
        const next = current.includes(type) ? current.filter((t) => t !== type) : [...current, type];
        setForm({ ...form, sanRules: { ...form.sanRules, allowedTypes: next } });
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

                    {/* Subject DN Rules builder */}
                    <div>
                        <div className="flex items-center justify-between mb-2">
                            <label className={labelClass}>Subject DN Rules</label>
                            <button type="button" onClick={addDnRule} className="px-2 py-1 text-xs bg-gray-200 dark:bg-gray-700 text-gray-700 dark:text-gray-300 rounded hover:bg-gray-300 dark:hover:bg-gray-600 transition-colors">+ Add Rule</button>
                        </div>
                        <div className="bg-gray-50 dark:bg-gray-900 border border-gray-300 dark:border-gray-700 rounded overflow-x-auto">
                            <table className="w-full min-w-[600px] text-xs">
                                <thead>
                                    <tr className="border-b border-gray-300 dark:border-gray-700 text-gray-600 dark:text-gray-400">
                                        <th className="px-2 py-2 text-left">Field</th><th className="px-2 py-2 text-left">Requirement</th><th className="px-2 py-2 text-left">Fixed Value</th><th className="px-2 py-2 text-left">Regex</th><th className="px-2 py-2 text-left">Max Length</th><th className="px-2 py-2 text-left">Default</th><th className="px-2 py-2"></th>
                                    </tr>
                                </thead>
                                <tbody>
                                    {form.subjectDnRules.map((rule, idx) => (
                                        <tr key={idx} className="border-b border-gray-200 dark:border-gray-800">
                                            <td className="px-2 py-1"><select value={rule.field} onChange={(e) => updateDnRule(idx, { field: e.target.value })} className="bg-gray-100 dark:bg-gray-800 border border-gray-300 dark:border-gray-700 rounded px-1 py-1 text-gray-900 dark:text-white text-xs w-16">{DN_FIELD_OPTIONS.map((f) => <option key={f} value={f}>{f}</option>)}</select></td>
                                            <td className="px-2 py-1"><select value={rule.requirement} onChange={(e) => updateDnRule(idx, { requirement: e.target.value })} className="bg-gray-100 dark:bg-gray-800 border border-gray-300 dark:border-gray-700 rounded px-1 py-1 text-gray-900 dark:text-white text-xs w-24">{REQUIREMENT_OPTIONS.map((r) => <option key={r} value={r}>{r}</option>)}</select></td>
                                            <td className="px-2 py-1"><input type="text" value={rule.fixedValue || ''} onChange={(e) => updateDnRule(idx, { fixedValue: e.target.value })} className="bg-gray-100 dark:bg-gray-800 border border-gray-300 dark:border-gray-700 rounded px-1 py-1 text-gray-900 dark:text-white text-xs w-24" placeholder="Optional" /></td>
                                            <td className="px-2 py-1"><input type="text" value={rule.regex || ''} onChange={(e) => updateDnRule(idx, { regex: e.target.value })} className="bg-gray-100 dark:bg-gray-800 border border-gray-300 dark:border-gray-700 rounded px-1 py-1 text-gray-900 dark:text-white text-xs w-24" placeholder="e.g. ^[a-z]+$" /></td>
                                            <td className="px-2 py-1"><input type="text" inputMode="numeric" value={rule.maxLength ?? ''} onChange={(e) => { const v = e.target.value.replace(/\D/g, ''); updateDnRule(idx, { maxLength: v ? parseInt(v) : null }); }} className="bg-gray-100 dark:bg-gray-800 border border-gray-300 dark:border-gray-700 rounded px-1 py-1 text-gray-900 dark:text-white text-xs w-16" placeholder="64" /></td>
                                            <td className="px-2 py-1"><input type="text" value={rule.defaultValue || ''} onChange={(e) => updateDnRule(idx, { defaultValue: e.target.value })} className="bg-gray-100 dark:bg-gray-800 border border-gray-300 dark:border-gray-700 rounded px-1 py-1 text-gray-900 dark:text-white text-xs w-24" placeholder="Optional" /></td>
                                            <td className="px-2 py-1"><button type="button" onClick={() => removeDnRule(idx)} className="text-red-800 dark:text-red-400 hover:text-red-300 text-xs px-1">X</button></td>
                                        </tr>
                                    ))}
                                </tbody>
                            </table>
                        </div>
                    </div>

                    {/* SAN Rules */}
                    <div>
                        <label className={labelClass}>SAN Rules</label>
                        <div className="bg-gray-50 dark:bg-gray-900 border border-gray-300 dark:border-gray-700 rounded p-3 space-y-2">
                            <div>
                                <span className="text-xs text-gray-600 dark:text-gray-400 mr-2">Allowed Types:</span>
                                <div className="inline-flex flex-wrap gap-2 mt-1">
                                    {SAN_TYPE_OPTIONS.map((type) => {
                                        const active = form.sanRules.allowedTypes.includes(type);
                                        return (
                                            <button key={type} type="button" onClick={() => toggleSanType(type)} className={`px-2 py-1 text-xs rounded border transition-colors ${active ? 'bg-blue-50 dark:bg-blue-900/50 text-blue-800 dark:text-blue-300 border-blue-300 dark:border-blue-700' : 'bg-gray-50 dark:bg-gray-900 text-gray-600 dark:text-gray-400 border-gray-300 dark:border-gray-700 hover:border-gray-500'}`}>{type}</button>
                                        );
                                    })}
                                </div>
                            </div>
                            <label className="flex items-center gap-2 text-xs text-gray-700 dark:text-gray-300">
                                <input type="checkbox" checked={form.sanRules.required} onChange={(e) => setForm({ ...form, sanRules: { ...form.sanRules, required: e.target.checked } })} className="w-4 h-4 rounded" />
                                SAN Required
                            </label>
                        </div>
                    </div>

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
