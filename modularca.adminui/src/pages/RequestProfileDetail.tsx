import React, { useEffect, useState } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { apiGet, apiPost, apiPutWithMfa, apiDeleteWithMfa } from '../api/client';
import { useStepUp } from '../components/StepUpMfaContext';
import { useToast } from '@shared/context/ToastContext';
import { DetailField } from '@shared/components/cards/DetailField';
import ConfirmModal from '../components/ConfirmModal';
import { DetailPage, DetailSection } from '../components/DetailPage';
import { StepUpOps } from '@shared/generated';
import { caRowId, caDisplayName } from './profileHelpers';
import { inputClass, labelClass } from '@shared/components/forms';

const REQUEST_TAB = `/profiles?tab=${encodeURIComponent('Request Profiles')}`;

/** Field source indicator for resolved profile views */
const ReqFieldSourceBadge: React.FC<{ source?: string }> = ({ source }) => {
    if (!source) return null;
    const isOverridden = source === 'overridden';
    return (
        <span className={`ml-2 px-1.5 py-0.5 text-[10px] rounded border ${isOverridden
            ? 'bg-green-50 dark:bg-green-900/40 text-green-800 dark:text-green-300 border-green-300 dark:border-green-700'
            : 'bg-gray-200 dark:bg-gray-700/40 text-gray-600 dark:text-gray-400 border-gray-400 dark:border-gray-600'}`}>
            {isOverridden ? 'overridden' : 'inherited'}
        </span>
    );
};

const ReqSourceBorderedField: React.FC<{ source?: string; label: string; value?: string | null }> = ({ source, label, value }) => {
    const borderColor = source === 'overridden' ? 'border-l-green-500' : source === 'inherited' ? 'border-l-gray-500' : '';
    return (
        <div className={`pl-3 border-l-2 ${borderColor}`}>
            <div className="flex items-center">
                <span className="text-xs text-gray-600 dark:text-gray-400">{label}</span>
                <ReqFieldSourceBadge source={source} />
            </div>
            <span className="text-sm text-gray-900 dark:text-white">{value || '-'}</span>
        </div>
    );
};

/// <summary>
/// Editable detail page for a single enrollment request profile (a tab on Profile Management). View
/// shows DN/SAN rules and inheritance; Edit changes metadata, JSON rule bodies, allowed cert profiles
/// and inheritance (step-up MFA). Delete and the resolve/validate inheritance actions are in-page.
/// </summary>
const RequestProfileDetail: React.FC = () => {
    const { id } = useParams<{ id: string }>();
    const navigate = useNavigate();
    const { requireStepUp } = useStepUp();
    const { showToast } = useToast();

    const [profile, setProfile] = useState<any | null>(null);
    const [profiles, setProfiles] = useState<any[]>([]);
    const [certProfiles, setCertProfiles] = useState<any[]>([]);
    const [authorities, setAuthorities] = useState<any[]>([]);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState<string | null>(null);
    const [refresh, setRefresh] = useState(0);

    const [resolvedProfile, setResolvedProfile] = useState<any | null>(null);
    const [resolvedLoading, setResolvedLoading] = useState(false);
    const [validationResult, setValidationResult] = useState<{ isValid: boolean; errors: string[] } | null>(null);
    const [validationLoading, setValidationLoading] = useState(false);

    const [confirmDelete, setConfirmDelete] = useState(false);
    const [deleting, setDeleting] = useState(false);

    const emptyForm = {
        name: '', description: '', requireApproval: false, maxValidityPeriod: '', defaultCertProfileId: '',
        subjectDnRulesJson: '', sanRulesJson: '', allowedCertProfileIds: [] as string[],
        inheritsFromId: '', inheritanceEnabled: false, certificateAuthorityId: '',
    };
    const [editForm, setEditForm] = useState(emptyForm);
    const [initialForm, setInitialForm] = useState(emptyForm);

    const dirty = JSON.stringify(editForm) !== JSON.stringify(initialForm);

    useEffect(() => {
        let cancelled = false;
        setLoading(true);
        setError(null);
        Promise.all([
            apiGet<any>('/api/v1/admin/request-profiles'),
            apiGet<any>('/api/v1/admin/cert-profiles').catch(() => []),
            apiGet<any>('/api/v1/admin/authorities').catch(() => []),
        ]).then(([profData, cpData, authData]) => {
            if (cancelled) return;
            const list = Array.isArray(profData) ? profData : (profData.items || profData.profiles || []);
            setProfiles(list);
            const p = list.find((x: any) => x.id === id) || null;
            setProfile(p);
            if (p) {
                const seeded = {
                    name: p.name || '', description: p.description || '', requireApproval: !!p.requireApproval,
                    maxValidityPeriod: p.maxValidityPeriod || '', defaultCertProfileId: p.defaultCertProfileId || '',
                    subjectDnRulesJson: p.subjectDnRules ? JSON.stringify(p.subjectDnRules, null, 2) : '[]',
                    sanRulesJson: p.sanRules ? JSON.stringify(p.sanRules, null, 2) : '{}',
                    allowedCertProfileIds: Array.isArray(p.allowedCertProfileIds) ? p.allowedCertProfileIds : [],
                    inheritsFromId: p.inheritsFromId || '', inheritanceEnabled: !!p.inheritanceEnabled,
                    certificateAuthorityId: p.certificateAuthorityId || '',
                };
                setEditForm(seeded);
                setInitialForm(seeded);
            }
            setCertProfiles(Array.isArray(cpData) ? cpData : (cpData.items || cpData.profiles || []));
            setAuthorities(Array.isArray(authData) ? authData : (authData.items || authData.authorities || []));
            setLoading(false);
        }).catch((err) => { if (!cancelled) { setError(err.message || 'Failed to load request profile'); setLoading(false); } });
        return () => { cancelled = true; };
    }, [id, refresh]);

    const resolveParentName = (pid: string | undefined | null) => {
        if (!pid) return undefined;
        const p = profiles.find((pr) => pr.id === pid);
        return p ? p.name : pid;
    };
    const resolveProfileName = (cpId: string) => {
        const cp = certProfiles.find((c) => (c.id || c.certProfileId) === cpId);
        return cp ? cp.name : cpId;
    };

    const fetchResolvedProfile = async () => {
        setResolvedLoading(true); setResolvedProfile(null);
        try { setResolvedProfile(await apiGet<any>(`/api/v1/admin/request-profiles/${id}/resolved`)); }
        catch (err: any) { showToast('error', err.message || 'Failed to fetch resolved profile'); }
        finally { setResolvedLoading(false); }
    };
    const fetchValidation = async () => {
        setValidationLoading(true); setValidationResult(null);
        try { setValidationResult(await apiPost<any>(`/api/v1/admin/request-profiles/${id}/validate-inheritance`, {})); }
        catch (err: any) { showToast('error', err.message || 'Failed to validate inheritance'); }
        finally { setValidationLoading(false); }
    };

    const handleSave = async () => {
        let subjectDnRules, sanRules;
        try { subjectDnRules = JSON.parse(editForm.subjectDnRulesJson); } catch { showToast('warning', 'Invalid JSON for Subject DN Rules'); throw new Error('Invalid JSON for Subject DN Rules'); }
        try { sanRules = JSON.parse(editForm.sanRulesJson); } catch { showToast('warning', 'Invalid JSON for SAN Rules'); throw new Error('Invalid JSON for SAN Rules'); }
        const body = {
            name: editForm.name, description: editForm.description || undefined, requireApproval: editForm.requireApproval,
            maxValidityPeriod: editForm.maxValidityPeriod || undefined, defaultCertProfileId: editForm.defaultCertProfileId || undefined,
            subjectDnRules, sanRules, allowedCertProfileIds: editForm.allowedCertProfileIds,
            inheritsFromId: editForm.inheritsFromId || undefined, inheritanceEnabled: editForm.inheritanceEnabled,
            certificateAuthorityId: editForm.certificateAuthorityId || undefined,
        };
        try {
            await apiPutWithMfa(`/api/v1/admin/request-profiles/${id}`, body, requireStepUp, StepUpOps.UpdateRequestProfile, id!);
            showToast('success', 'Request profile updated');
            setRefresh((r) => r + 1);
        } catch (err: any) {
            if (err.message !== 'Step-up MFA cancelled') showToast('error', err.message || 'Failed to update request profile');
            throw err;
        }
    };

    const handleCancel = () => {
        setEditForm(initialForm);
    };

    const doDelete = async () => {
        setDeleting(true);
        try {
            await apiDeleteWithMfa(`/api/v1/admin/request-profiles/${id}`, requireStepUp, StepUpOps.DeleteRequestProfile, id!);
            showToast('success', 'Request profile deleted');
            navigate(REQUEST_TAB);
        } catch (err: any) {
            if (err.message !== 'Step-up MFA cancelled') showToast('error', err.message || 'Failed to delete request profile');
        } finally {
            setDeleting(false);
            setConfirmDelete(false);
        }
    };

    if (loading) return <div className="p-6 text-sm text-gray-600 dark:text-gray-400">Loading…</div>;
    if (error) return <div className="p-6 text-sm text-red-800 dark:text-red-400">{error}</div>;
    if (!profile) return (
        <div className="p-6 space-y-3">
            <p className="text-sm text-gray-600 dark:text-gray-400">Request profile not found.</p>
            <button onClick={() => navigate(REQUEST_TAB)} className="px-3 py-1.5 text-sm bg-gray-200 dark:bg-gray-700 rounded">Back to Request Profiles</button>
        </div>
    );

    const p = profile;
    const dnRules: any[] = p.subjectDnRules || [];

    return (
        <DetailPage
            breadcrumbs={[{ label: 'Profile Management', to: REQUEST_TAB }, { label: 'Request Profiles', to: REQUEST_TAB }, { label: p.name }]}
            title={p.name}
            subtitle={p.description || undefined}
            backTo={REQUEST_TAB}
            editable
            onSave={handleSave}
            onCancel={handleCancel}
            saveDisabled={!dirty || !editForm.name}
            actions={<button onClick={() => setConfirmDelete(true)} disabled={deleting} className="px-3 py-1.5 text-xs bg-red-50 dark:bg-red-900/50 text-red-800 dark:text-red-300 border border-red-300 dark:border-red-700 rounded hover:bg-red-900 disabled:opacity-50 transition-colors">Delete</button>}
        >
            {(mode) => mode === 'edit' ? (
                <DetailSection title="Edit Request Profile">
                    <div className="space-y-3 max-w-3xl">
                        <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                            <div><label className={labelClass}>Name</label><input type="text" value={editForm.name} onChange={(e) => setEditForm({ ...editForm, name: e.target.value })} className={inputClass} /></div>
                            <div><label className={labelClass}>Description</label><input type="text" value={editForm.description} onChange={(e) => setEditForm({ ...editForm, description: e.target.value })} className={inputClass} /></div>
                            <div><label className={labelClass}>Max Validity Period (ISO 8601)</label><input type="text" value={editForm.maxValidityPeriod} onChange={(e) => setEditForm({ ...editForm, maxValidityPeriod: e.target.value })} className={inputClass} placeholder="e.g. P365D" /></div>
                            <div>
                                <label className={labelClass}>Default Certificate Profile</label>
                                <select value={editForm.defaultCertProfileId} onChange={(e) => setEditForm({ ...editForm, defaultCertProfileId: e.target.value })} className={inputClass}>
                                    <option value="">-- None --</option>
                                    {certProfiles.map((cp) => { const cpId = cp.id || cp.certProfileId; return <option key={cpId} value={cpId}>{cp.name}</option>; })}
                                </select>
                            </div>
                            <div>
                                <label className={labelClass}>Inherits From</label>
                                <select value={editForm.inheritsFromId} onChange={(e) => setEditForm({ ...editForm, inheritsFromId: e.target.value })} className={inputClass}>
                                    <option value="">-- None (standalone) --</option>
                                    {profiles.filter(pr => pr.id !== p.id).map((pr) => <option key={pr.id} value={pr.id}>{pr.name}</option>)}
                                </select>
                            </div>
                            <div>
                                <label className={labelClass}>CA Scope</label>
                                <select value={editForm.certificateAuthorityId} onChange={(e) => setEditForm({ ...editForm, certificateAuthorityId: e.target.value })} className={inputClass}>
                                    <option value="">-- System-wide --</option>
                                    {authorities.map((a) => <option key={caRowId(a)} value={caRowId(a)}>{caDisplayName(a)}</option>)}
                                </select>
                            </div>
                        </div>
                        <div className="flex flex-wrap gap-4">
                            <label className="flex items-center gap-2 text-xs text-gray-700 dark:text-gray-300"><input type="checkbox" checked={editForm.requireApproval} onChange={(e) => setEditForm({ ...editForm, requireApproval: e.target.checked })} className="w-4 h-4 rounded" />Require Approval</label>
                            <label className="flex items-center gap-2 text-xs text-gray-700 dark:text-gray-300"><input type="checkbox" checked={editForm.inheritanceEnabled} onChange={(e) => setEditForm({ ...editForm, inheritanceEnabled: e.target.checked })} className="w-4 h-4 rounded" />Enable Inheritance</label>
                        </div>
                        <div><label className={labelClass}>Subject DN Rules (JSON)</label><textarea rows={6} value={editForm.subjectDnRulesJson} onChange={(e) => setEditForm({ ...editForm, subjectDnRulesJson: e.target.value })} className={inputClass + ' font-mono text-xs'} /></div>
                        <div><label className={labelClass}>SAN Rules (JSON)</label><textarea rows={4} value={editForm.sanRulesJson} onChange={(e) => setEditForm({ ...editForm, sanRulesJson: e.target.value })} className={inputClass + ' font-mono text-xs'} /></div>
                        <div>
                            <label className={labelClass}>Allowed Cert Profiles</label>
                            <div className="max-h-40 overflow-y-auto bg-gray-50 dark:bg-gray-900 border border-gray-300 dark:border-gray-700 rounded p-2 space-y-1">
                                {certProfiles.length === 0 && <span className="text-xs text-gray-600">No cert profiles available</span>}
                                {certProfiles.map((cp) => {
                                    const cpId = cp.id || cp.certProfileId;
                                    return (
                                        <label key={cpId} className="flex items-center gap-2 text-sm text-gray-900 dark:text-white cursor-pointer hover:bg-gray-100 dark:hover:bg-gray-800 px-1 rounded">
                                            <input type="checkbox" checked={editForm.allowedCertProfileIds.includes(cpId)}
                                                onChange={(e) => setEditForm({ ...editForm, allowedCertProfileIds: e.target.checked ? [...editForm.allowedCertProfileIds, cpId] : editForm.allowedCertProfileIds.filter((x) => x !== cpId) })}
                                                className="accent-blue-500" />
                                            <span>{cp.name}</span>
                                        </label>
                                    );
                                })}
                            </div>
                        </div>
                    </div>
                </DetailSection>
            ) : (<>
                <DetailSection title="Request Profile">
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-x-8">
                        <DetailField label="ID" value={p.id} mono />
                        <DetailField label="Name" value={p.name} />
                        <DetailField label="Description" value={p.description} />
                        <DetailField label="Require Approval" value={p.requireApproval ? 'Yes' : 'No'} />
                        <DetailField label="Max Validity Period" value={p.maxValidityPeriod} />
                        <DetailField label="Default Cert Profile" value={p.defaultCertProfileId ? resolveProfileName(p.defaultCertProfileId) : 'None'} />
                        <DetailField label="Created" value={p.createdAt ? new Date(p.createdAt).toLocaleString() : undefined} />
                        <DetailField label="Updated" value={p.updatedAt ? new Date(p.updatedAt).toLocaleString() : undefined} />
                        <DetailField label="CA Scope" value={p.certificateAuthorityId ? String(p.certificateAuthorityId) : 'System-wide'} />
                        {p.inheritanceEnabled && <DetailField label="Inherits From" value={resolveParentName(p.inheritsFromId) || 'None'} />}
                    </div>
                    {p.allowedCertProfileIds && p.allowedCertProfileIds.length > 0 && (
                        <div className="py-2">
                            <span className="text-xs text-gray-600 dark:text-gray-400">Allowed Cert Profiles</span>
                            <div className="flex flex-wrap gap-1 mt-1">
                                {p.allowedCertProfileIds.map((cpId: string, i: number) => (
                                    <span key={i} className="px-2 py-0.5 text-xs rounded bg-blue-50 dark:bg-blue-900/40 text-blue-800 dark:text-blue-300 border border-blue-300 dark:border-blue-800">{resolveProfileName(cpId)}</span>
                                ))}
                            </div>
                        </div>
                    )}
                </DetailSection>

                <DetailSection title="Subject DN Rules">
                    {dnRules.length > 0 ? (
                        <div className="overflow-x-auto">
                            <table className="w-full min-w-[600px] text-xs">
                                <thead>
                                    <tr className="border-b border-gray-300 dark:border-gray-700 text-gray-600 dark:text-gray-400">
                                        <th className="px-3 py-2 text-left">Field</th><th className="px-3 py-2 text-left">Requirement</th><th className="px-3 py-2 text-left">Fixed Value</th><th className="px-3 py-2 text-left">Regex</th><th className="px-3 py-2 text-left">Max Length</th><th className="px-3 py-2 text-left">Default</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    {dnRules.map((rule, idx) => (
                                        <tr key={idx} className="border-b border-gray-200 dark:border-gray-800 last:border-b-0">
                                            <td className="px-3 py-2 text-gray-900 dark:text-white font-medium">{rule.field}</td>
                                            <td className="px-3 py-2">
                                                <span className={`px-2 py-0.5 rounded text-xs border ${rule.requirement === 'Required' ? 'bg-green-50 dark:bg-green-900/50 text-green-800 dark:text-green-300 border-green-300 dark:border-green-700' : rule.requirement === 'Forbidden' ? 'bg-red-50 dark:bg-red-900/50 text-red-800 dark:text-red-300 border-red-300 dark:border-red-700' : 'bg-gray-200/50 dark:bg-gray-700/50 text-gray-700 dark:text-gray-300 border-gray-400 dark:border-gray-600'}`}>{rule.requirement}</span>
                                            </td>
                                            <td className="px-3 py-2 text-gray-700 dark:text-gray-300">{rule.fixedValue || '-'}</td>
                                            <td className="px-3 py-2 text-gray-700 dark:text-gray-300 font-mono">{rule.regex || '-'}</td>
                                            <td className="px-3 py-2 text-gray-700 dark:text-gray-300">{rule.maxLength ?? '-'}</td>
                                            <td className="px-3 py-2 text-gray-700 dark:text-gray-300">{rule.defaultValue || '-'}</td>
                                        </tr>
                                    ))}
                                </tbody>
                            </table>
                        </div>
                    ) : <span className="text-xs text-gray-600">No DN rules defined</span>}
                </DetailSection>

                <DetailSection title="SAN Rules">
                    <div>
                        <span className="text-xs text-gray-600 dark:text-gray-400 mr-2">Allowed Types:</span>
                        <div className="inline-flex flex-wrap gap-1 mt-1">
                            {(p.sanRules?.allowedTypes || []).map((type: string, i: number) => (
                                <span key={i} className="px-2 py-0.5 text-xs rounded bg-blue-50 dark:bg-blue-900/40 text-blue-800 dark:text-blue-300 border border-blue-300 dark:border-blue-800">{type}</span>
                            ))}
                            {(!p.sanRules?.allowedTypes || p.sanRules.allowedTypes.length === 0) && <span className="text-xs text-gray-600">None</span>}
                        </div>
                        <div className="mt-2"><DetailField label="SAN Required" value={p.sanRules?.required ? 'Yes' : 'No'} /></div>
                    </div>
                </DetailSection>

                {p.inheritanceEnabled && p.inheritsFromId && (
                    <DetailSection title="Inheritance">
                        <div className="flex gap-2">
                            <button onClick={fetchResolvedProfile} disabled={resolvedLoading} className="px-3 py-1 text-xs bg-blue-50 dark:bg-blue-900/50 text-blue-800 dark:text-blue-300 border border-blue-300 dark:border-blue-700 rounded hover:bg-blue-900 transition-colors disabled:opacity-50">{resolvedLoading ? 'Loading...' : 'Resolved Profile'}</button>
                            <button onClick={fetchValidation} disabled={validationLoading} className="px-3 py-1 text-xs bg-yellow-50 dark:bg-yellow-900/50 text-yellow-800 dark:text-yellow-300 border border-yellow-300 dark:border-yellow-700 rounded hover:bg-yellow-900 transition-colors disabled:opacity-50">{validationLoading ? 'Validating...' : 'Validate Inheritance'}</button>
                        </div>
                        {validationResult && (
                            <div className={`mt-3 p-3 rounded border text-sm ${validationResult.isValid ? 'bg-green-50 dark:bg-green-900/20 border-green-300 dark:border-green-700 text-green-800 dark:text-green-300' : 'bg-red-50 dark:bg-red-900/20 border-red-300 dark:border-red-700 text-red-800 dark:text-red-300'}`}>
                                {validationResult.isValid ? <span>Inheritance is valid. No constraint violations found.</span> : (
                                    <div><span className="font-semibold">Validation errors:</span><ul className="mt-1 list-disc list-inside space-y-0.5">{validationResult.errors.map((err, i) => <li key={i} className="text-xs">{err}</li>)}</ul></div>
                                )}
                            </div>
                        )}
                        {resolvedProfile && (
                            <div className="mt-3 bg-gray-100 dark:bg-gray-800 border border-gray-300 dark:border-gray-700 rounded-lg p-3 space-y-2">
                                <h5 className="text-xs font-semibold text-gray-900 dark:text-white mb-2">Resolved (Effective) Profile</h5>
                                {resolvedProfile.parentProfileId && <div className="text-xs text-gray-600 dark:text-gray-400 mb-2">Parent: {resolveParentName(resolvedProfile.parentProfileId)}</div>}
                                <ReqSourceBorderedField source={resolvedProfile.fieldSources?.Name} label="Name" value={resolvedProfile.name} />
                                <ReqSourceBorderedField source={resolvedProfile.fieldSources?.Description} label="Description" value={resolvedProfile.description} />
                                <ReqSourceBorderedField source={resolvedProfile.fieldSources?.RequireApproval} label="Require Approval" value={resolvedProfile.requireApproval ? 'Yes' : 'No'} />
                                <ReqSourceBorderedField source={resolvedProfile.fieldSources?.MaxValidityPeriod} label="Max Validity Period" value={resolvedProfile.maxValidityPeriod} />
                                <ReqSourceBorderedField source={resolvedProfile.fieldSources?.DefaultCertProfileId} label="Default Cert Profile" value={resolvedProfile.defaultCertProfileId ? resolveProfileName(resolvedProfile.defaultCertProfileId) : 'None'} />
                            </div>
                        )}
                    </DetailSection>
                )}

                <ConfirmModal
                    isOpen={confirmDelete}
                    title="Delete Request Profile"
                    message={`Delete request profile "${p.name}"? This cannot be undone.`}
                    confirmLabel="Delete"
                    confirmClass="bg-red-600 hover:bg-red-700"
                    loading={deleting}
                    onConfirm={doDelete}
                    onCancel={() => setConfirmDelete(false)}
                />
            </>)}
        </DetailPage>
    );
};

export default RequestProfileDetail;
