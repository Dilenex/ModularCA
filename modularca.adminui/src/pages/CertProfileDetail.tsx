import React, { useEffect, useState } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { apiGet, apiPost, apiPutWithMfa, apiDeleteWithMfa } from '../api/client';
import { useStepUp } from '../components/StepUpMfaContext';
import { useToast } from '../context/ToastContext';
import DetailField from '../components/cards/DetailField';
import ConfirmModal from '../components/ConfirmModal';
import { DetailPage, DetailSection } from '../components/DetailPage';
import { StepUpOps } from '@shared/generated';
import {
    KEY_USAGE_OPTIONS, EKU_OPTIONS, ekuLabel, keyUsageLabel,
    canonicalizeUsages, EKU_ALIASES,
    ALLOWED_KEY_ALGORITHM_OPTIONS, ALLOWED_KEY_SIZE_OPTIONS, ALLOWED_SIGNATURE_ALGORITHM_OPTIONS,
    inputClass, labelClass, parseJsonArray, parseListField, BadgeList, MultiToggle, formatKeySizeLabel,
    FieldSourceBadge, SourceBorderedField,
} from './profileHelpers';

const CERT_TAB = `/profiles?tab=${encodeURIComponent('Certificate Profiles')}`;
const cpId = (p: any): string => p.id || p.certProfileId;
// Goes through parseListField so a JSON array string displays as 'a, b' rather than raw '["a","b"]'.
const displayCommaSep = (val: any): string => parseListField(val).join(', ');

/// <summary>
/// Editable detail page for a single certificate profile (a tab on Profile Management). View shows
/// usages/algorithm allow-lists and inheritance; Edit changes all profile fields via step-up MFA.
/// </summary>
const CertProfileDetail: React.FC = () => {
    const { id } = useParams<{ id: string }>();
    const navigate = useNavigate();
    const { requireStepUp } = useStepUp();
    const { showToast } = useToast();

    const [profile, setProfile] = useState<any | null>(null);
    const [profiles, setProfiles] = useState<any[]>([]);
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
        name: '', description: '', isCaProfile: false,
        keyUsages: [] as string[], extendedKeyUsages: [] as string[],
        allowedKeyAlgorithms: [] as string[], allowedKeySizes: [] as string[], allowedSignatureAlgorithms: [] as string[],
        validityPeriodMin: '', validityPeriodMax: '', ctEnabled: false, ctLogIds: '',
        inheritsFromId: '', inheritanceEnabled: false, certificateAuthorityId: '', allowWildcard: false,
    };
    const [editForm, setEditForm] = useState(emptyForm);
    const [initialForm, setInitialForm] = useState(emptyForm);

    useEffect(() => {
        let cancelled = false;
        setLoading(true);
        setError(null);
        Promise.all([
            apiGet<any>('/api/v1/admin/cert-profiles'),
            apiGet<any>('/api/v1/admin/authorities').catch(() => []),
        ]).then(([data, authData]) => {
            if (cancelled) return;
            const list = Array.isArray(data) ? data : (data.items || data.profiles || []);
            setProfiles(list);
            const p = list.find((x: any) => cpId(x) === id) || null;
            setProfile(p);
            if (p) {
                const seeded = {
                    name: p.name || '', description: p.description || '', isCaProfile: !!p.isCaProfile,
                    // The API returns these as JSON array strings. Splitting on ',' produced tokens
                    // like '["digitalSignature"' that matched no toggle option, so the selection rendered
                    // empty and a subsequent save wrote that empty selection back over the real one.
                    // Canonicalised, not just parsed: rows written while the CSV/JSON parse bug was
                    // live hold fragments like '["[]"' or '"Server Auth"'. Normalising punctuation away
                    // recovers the real selection, and the next save rewrites the field cleanly.
                    keyUsages: canonicalizeUsages(parseListField(p.keyUsages), KEY_USAGE_OPTIONS),
                    extendedKeyUsages: canonicalizeUsages(parseListField(p.extendedKeyUsages), EKU_OPTIONS, EKU_ALIASES),
                    allowedKeyAlgorithms: parseJsonArray(p.allowedKeyAlgorithms),
                    allowedKeySizes: parseJsonArray(p.allowedKeySizes),
                    allowedSignatureAlgorithms: parseJsonArray(p.allowedSignatureAlgorithms),
                    validityPeriodMin: p.validityPeriodMin || '', validityPeriodMax: p.validityPeriodMax || '',
                    ctEnabled: !!p.ctEnabled, ctLogIds: p.ctLogIds || '',
                    inheritsFromId: p.inheritsFromId || '', inheritanceEnabled: !!p.inheritanceEnabled,
                    certificateAuthorityId: p.certificateAuthorityId || '', allowWildcard: !!p.allowWildcard,
                };
                setEditForm(seeded);
                setInitialForm(seeded);
            }
            setAuthorities(Array.isArray(authData) ? authData : (authData.items || authData.authorities || []));
            setLoading(false);
        }).catch((err) => { if (!cancelled) { setError(err.message || 'Failed to load profile'); setLoading(false); } });
        return () => { cancelled = true; };
    }, [id, refresh]);

    const resolveParentName = (pid: string | undefined | null) => {
        if (!pid) return undefined;
        const p = profiles.find((pr) => cpId(pr) === pid);
        return p ? p.name : pid;
    };

    const fetchResolvedProfile = async () => {
        setResolvedLoading(true); setResolvedProfile(null);
        try { setResolvedProfile(await apiGet<any>(`/api/v1/admin/cert-profiles/${id}/resolved`)); }
        catch (err: any) { showToast('error', err.message || 'Failed to fetch resolved profile'); }
        finally { setResolvedLoading(false); }
    };
    const fetchValidation = async () => {
        setValidationLoading(true); setValidationResult(null);
        try { setValidationResult(await apiPost<any>(`/api/v1/admin/cert-profiles/${id}/validate-inheritance`, {})); }
        catch (err: any) { showToast('error', err.message || 'Failed to validate inheritance'); }
        finally { setValidationLoading(false); }
    };

    const dirty = JSON.stringify(editForm) !== JSON.stringify(initialForm);

    const handleSave = async () => {
        try {
            const body = {
                ...editForm,
                keyUsages: editForm.keyUsages.join(', '),
                extendedKeyUsages: editForm.extendedKeyUsages.join(', '),
                allowedKeyAlgorithms: JSON.stringify(editForm.allowedKeyAlgorithms),
                allowedKeySizes: JSON.stringify(editForm.allowedKeySizes),
                allowedSignatureAlgorithms: JSON.stringify(editForm.allowedSignatureAlgorithms),
                ctLogIds: editForm.ctLogIds || undefined,
                validityPeriodMin: editForm.validityPeriodMin || undefined,
                validityPeriodMax: editForm.validityPeriodMax || undefined,
                inheritsFromId: editForm.inheritsFromId || undefined,
                inheritanceEnabled: editForm.inheritanceEnabled,
                certificateAuthorityId: editForm.certificateAuthorityId || undefined,
                allowWildcard: editForm.allowWildcard,
            };
            await apiPutWithMfa(`/api/v1/admin/cert-profiles/${id}`, body, requireStepUp, StepUpOps.UpdateCertProfile, id!);
            showToast('success', 'Certificate profile updated');
            setRefresh((r) => r + 1);
        } catch (err: any) {
            if (err.message !== 'Step-up MFA cancelled') showToast('error', err.message || 'Failed to update profile');
            throw err;
        }
    };

    const handleCancel = () => {
        setEditForm(initialForm);
    };

    const doDelete = async () => {
        setDeleting(true);
        try {
            await apiDeleteWithMfa(`/api/v1/admin/cert-profiles/${id}`, requireStepUp, StepUpOps.DeleteCertProfile, id!);
            showToast('success', 'Certificate profile deleted');
            navigate(CERT_TAB);
        } catch (err: any) {
            if (err.message !== 'Step-up MFA cancelled') showToast('error', err.message || 'Failed to delete profile');
        } finally {
            setDeleting(false);
            setConfirmDelete(false);
        }
    };

    if (loading) return <div className="p-6 text-sm text-gray-600 dark:text-gray-400">Loading…</div>;
    if (error) return <div className="p-6 text-sm text-red-800 dark:text-red-400">{error}</div>;
    if (!profile) return (
        <div className="p-6 space-y-3">
            <p className="text-sm text-gray-600 dark:text-gray-400">Certificate profile not found.</p>
            <button onClick={() => navigate(CERT_TAB)} className="px-3 py-1.5 text-sm bg-gray-200 dark:bg-gray-700 rounded">Back to Certificate Profiles</button>
        </div>
    );

    const p = profile;

    return (
        <DetailPage
            breadcrumbs={[{ label: 'Profile Management', to: CERT_TAB }, { label: 'Certificate Profiles', to: CERT_TAB }, { label: p.name }]}
            title={p.name}
            subtitle={p.isCaProfile ? 'CA Profile' : 'Leaf Profile'}
            backTo={CERT_TAB}
            editable
            onSave={handleSave}
            onCancel={handleCancel}
            saveDisabled={!dirty || !editForm.name}
            actions={<button onClick={() => setConfirmDelete(true)} disabled={deleting} className="px-3 py-1.5 text-xs bg-red-50 dark:bg-red-900/50 text-red-800 dark:text-red-300 border border-red-300 dark:border-red-700 rounded hover:bg-red-900 disabled:opacity-50 transition-colors">Delete</button>}
        >
            {(mode) => mode === 'edit' ? (
                <DetailSection title="Edit Certificate Profile">
                    <div className="space-y-3 max-w-3xl">
                        <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                            <div><label className={labelClass}>Name</label><input type="text" value={editForm.name} onChange={(e) => setEditForm({ ...editForm, name: e.target.value })} className={inputClass} /></div>
                            <div><label className={labelClass}>Description</label><input type="text" value={editForm.description} onChange={(e) => setEditForm({ ...editForm, description: e.target.value })} className={inputClass} /></div>
                            <div><label className={labelClass}>Validity Period Min (ISO 8601)</label><input type="text" placeholder="e.g. P90D" value={editForm.validityPeriodMin} onChange={(e) => setEditForm({ ...editForm, validityPeriodMin: e.target.value })} className={inputClass} /></div>
                            <div><label className={labelClass}>Validity Period Max (ISO 8601)</label><input type="text" placeholder="e.g. P1Y" value={editForm.validityPeriodMax} onChange={(e) => setEditForm({ ...editForm, validityPeriodMax: e.target.value })} className={inputClass} /></div>
                            <div><label className={labelClass}>CT Log IDs</label><input type="text" placeholder="Comma-separated log IDs" value={editForm.ctLogIds} onChange={(e) => setEditForm({ ...editForm, ctLogIds: e.target.value })} className={inputClass} /></div>
                            <div>
                                <label className={labelClass}>Inherits From</label>
                                <select value={editForm.inheritsFromId} onChange={(e) => setEditForm({ ...editForm, inheritsFromId: e.target.value })} className={inputClass}>
                                    <option value="">-- None (standalone) --</option>
                                    {profiles.filter(pr => cpId(pr) !== cpId(p)).map((pr) => <option key={cpId(pr)} value={cpId(pr)}>{pr.name}</option>)}
                                </select>
                            </div>
                            <div>
                                <label className={labelClass}>CA Scope</label>
                                <select value={editForm.certificateAuthorityId} onChange={(e) => setEditForm({ ...editForm, certificateAuthorityId: e.target.value })} className={inputClass}>
                                    <option value="">-- System-wide --</option>
                                    {authorities.map((a) => <option key={a.certificateId || a.id} value={a.certificateId || a.id}>{a.name || a.commonName || a.label || a.id}</option>)}
                                </select>
                            </div>
                        </div>
                        <div className="flex flex-wrap gap-4">
                            <label className="flex items-center gap-2 text-xs text-gray-700 dark:text-gray-300"><input type="checkbox" checked={editForm.isCaProfile} onChange={(e) => setEditForm({ ...editForm, isCaProfile: e.target.checked })} className="w-4 h-4 rounded" />CA Profile</label>
                            <label className="flex items-center gap-2 text-xs text-gray-700 dark:text-gray-300"><input type="checkbox" checked={editForm.ctEnabled} onChange={(e) => setEditForm({ ...editForm, ctEnabled: e.target.checked })} className="w-4 h-4 rounded" />CT Enabled</label>
                            <label className="flex items-center gap-2 text-xs text-gray-700 dark:text-gray-300"><input type="checkbox" checked={editForm.inheritanceEnabled} onChange={(e) => setEditForm({ ...editForm, inheritanceEnabled: e.target.checked })} className="w-4 h-4 rounded" />Enable Inheritance</label>
                        </div>
                        <div>
                            <label className="flex items-center gap-2 text-xs text-gray-700 dark:text-gray-300"><input type="checkbox" checked={editForm.allowWildcard} onChange={(e) => setEditForm({ ...editForm, allowWildcard: e.target.checked })} className="w-4 h-4 rounded" />Allow wildcard SAN/CN entries</label>
                            <p className="text-[11px] text-gray-600 dark:text-gray-400 mt-1 ml-6">When disabled, any DNS SAN or CN containing <code className="font-mono">*</code> is rejected at issuance. Structural rules still apply when enabled: at most one <code className="font-mono">*</code>, in the leftmost label, and at least two labels.</p>
                        </div>
                        <div><label className={labelClass}>Key Usages</label><MultiToggle options={KEY_USAGE_OPTIONS} selected={editForm.keyUsages} onChange={(next) => setEditForm({ ...editForm, keyUsages: next })} formatLabel={keyUsageLabel} /></div>
                        <div><label className={labelClass}>Extended Key Usages</label><MultiToggle options={EKU_OPTIONS} selected={editForm.extendedKeyUsages} onChange={(next) => setEditForm({ ...editForm, extendedKeyUsages: next })} formatLabel={ekuLabel} /></div>
                        <div><label className={labelClass}>Allowed Key Algorithms</label><MultiToggle options={ALLOWED_KEY_ALGORITHM_OPTIONS} selected={editForm.allowedKeyAlgorithms} onChange={(next) => setEditForm({ ...editForm, allowedKeyAlgorithms: next })} /></div>
                        <div><label className={labelClass}>Allowed Key Sizes</label><MultiToggle options={ALLOWED_KEY_SIZE_OPTIONS} selected={editForm.allowedKeySizes} onChange={(next) => setEditForm({ ...editForm, allowedKeySizes: next })} formatLabel={formatKeySizeLabel} /></div>
                        <div><label className={labelClass}>Allowed Signature Algorithms</label><MultiToggle options={ALLOWED_SIGNATURE_ALGORITHM_OPTIONS} selected={editForm.allowedSignatureAlgorithms} onChange={(next) => setEditForm({ ...editForm, allowedSignatureAlgorithms: next })} /></div>
                    </div>
                </DetailSection>
            ) : (<>
                <DetailSection title="Certificate Profile">
                    <DetailField label="Name" value={p.name} />
                    <DetailField label="Description" value={p.description} />
                    <DetailField label="Type" value={p.isCaProfile ? 'CA Profile' : 'Leaf Profile'} />
                    <DetailField label="Key Usages" value={canonicalizeUsages(parseListField(p.keyUsages), KEY_USAGE_OPTIONS).map(keyUsageLabel).join(', ')} />
                    <DetailField label="Extended Key Usages" value={canonicalizeUsages(parseListField(p.extendedKeyUsages), EKU_OPTIONS, EKU_ALIASES).map(ekuLabel).join(', ')} />
                    <div className="py-1"><span className="text-xs text-gray-600 dark:text-gray-400">Allowed Key Algorithms</span><BadgeList items={p.allowedKeyAlgorithms} /></div>
                    <div className="py-1"><span className="text-xs text-gray-600 dark:text-gray-400">Allowed Key Sizes</span><BadgeList items={p.allowedKeySizes} /></div>
                    <div className="py-1"><span className="text-xs text-gray-600 dark:text-gray-400">Allowed Signature Algorithms</span><BadgeList items={p.allowedSignatureAlgorithms} /></div>
                    <DetailField label="Validity Period Min" value={p.validityPeriodMin} />
                    <DetailField label="Validity Period Max" value={p.validityPeriodMax} />
                    <DetailField label="CT Enabled" value={p.ctEnabled ? 'Yes' : 'No'} />
                    <DetailField label="CT Log IDs" value={p.ctLogIds} />
                    <DetailField label="Allow Wildcard SAN/CN" value={p.allowWildcard ? 'Yes' : 'No'} />
                    {p.inheritanceEnabled && <DetailField label="Inherits From" value={resolveParentName(p.inheritsFromId) || 'None'} />}
                    <DetailField label="CA Scope" value={p.certificateAuthorityId ? String(p.certificateAuthorityId) : 'System-wide'} />
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
                                <SourceBorderedField source={resolvedProfile.fieldSources?.Name} label="Name" value={resolvedProfile.name} />
                                <SourceBorderedField source={resolvedProfile.fieldSources?.Description} label="Description" value={resolvedProfile.description} />
                                <SourceBorderedField source={resolvedProfile.fieldSources?.IsCaProfile} label="CA Profile" value={resolvedProfile.isCaProfile ? 'Yes' : 'No'} />
                                <SourceBorderedField source={resolvedProfile.fieldSources?.KeyUsages} label="Key Usages" value={canonicalizeUsages(parseListField(resolvedProfile.keyUsages), KEY_USAGE_OPTIONS).map(keyUsageLabel).join(', ')} />
                                <SourceBorderedField source={resolvedProfile.fieldSources?.ExtendedKeyUsages} label="Extended Key Usages" value={canonicalizeUsages(parseListField(resolvedProfile.extendedKeyUsages), EKU_OPTIONS, EKU_ALIASES).map(ekuLabel).join(', ')} />
                                <SourceBorderedField source={resolvedProfile.fieldSources?.ValidityPeriodMin} label="Validity Period Min" value={resolvedProfile.validityPeriodMin} />
                                <SourceBorderedField source={resolvedProfile.fieldSources?.ValidityPeriodMax} label="Validity Period Max" value={resolvedProfile.validityPeriodMax} />
                                <div className={`pl-3 border-l-2 ${resolvedProfile.fieldSources?.AllowedKeyAlgorithms === 'overridden' ? 'border-l-green-500' : 'border-l-gray-500'}`}>
                                    <div className="flex items-center"><span className="text-xs text-gray-600 dark:text-gray-400">Allowed Key Algorithms</span><FieldSourceBadge source={resolvedProfile.fieldSources?.AllowedKeyAlgorithms} /></div>
                                    <BadgeList items={resolvedProfile.allowedKeyAlgorithms} />
                                </div>
                                <div className={`pl-3 border-l-2 ${resolvedProfile.fieldSources?.AllowedKeySizes === 'overridden' ? 'border-l-green-500' : 'border-l-gray-500'}`}>
                                    <div className="flex items-center"><span className="text-xs text-gray-600 dark:text-gray-400">Allowed Key Sizes</span><FieldSourceBadge source={resolvedProfile.fieldSources?.AllowedKeySizes} /></div>
                                    <BadgeList items={resolvedProfile.allowedKeySizes} />
                                </div>
                                <div className={`pl-3 border-l-2 ${resolvedProfile.fieldSources?.AllowedSignatureAlgorithms === 'overridden' ? 'border-l-green-500' : 'border-l-gray-500'}`}>
                                    <div className="flex items-center"><span className="text-xs text-gray-600 dark:text-gray-400">Allowed Signature Algorithms</span><FieldSourceBadge source={resolvedProfile.fieldSources?.AllowedSignatureAlgorithms} /></div>
                                    <BadgeList items={resolvedProfile.allowedSignatureAlgorithms} />
                                </div>
                                <SourceBorderedField source={resolvedProfile.fieldSources?.CtEnabled} label="CT Enabled" value={resolvedProfile.ctEnabled ? 'Yes' : 'No'} />
                                <SourceBorderedField source={resolvedProfile.fieldSources?.CtLogIds} label="CT Log IDs" value={resolvedProfile.ctLogIds} />
                            </div>
                        )}
                    </DetailSection>
                )}

                <ConfirmModal
                    isOpen={confirmDelete}
                    title="Delete Certificate Profile"
                    message={`Delete certificate profile "${p.name}"? This cannot be undone.`}
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

export default CertProfileDetail;
