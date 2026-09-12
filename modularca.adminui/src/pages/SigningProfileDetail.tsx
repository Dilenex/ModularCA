import React, { useEffect, useState } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { apiGet, apiPutWithMfa, apiDeleteWithMfa } from '../api/client';
import { useStepUp } from '../components/StepUpMfaContext';
import { useToast } from '@shared/context/ToastContext';
import { StatusBadge } from '@shared/components/cards/StatusBadge';
import { DetailField } from '@shared/components/cards/DetailField';
import ConfirmModal from '../components/ConfirmModal';
import { DetailPage, DetailSection } from '../components/DetailPage';
import { StepUpOps } from '@shared/generated';
import { SIGNING_ALLOWED_ALGORITHM_OPTIONS, parseJsonArray, parseListField, BadgeList, CeilingList, MultiToggle, canonicalizeUsages, caCertId, caDisplayName } from './profileHelpers';
import { inputClass, labelClass } from '@shared/components/forms';
import { useEkuCatalog } from '../hooks/useOidCatalog';

const SIGNING_TAB = `/profiles?tab=${encodeURIComponent('Signing Profiles')}`;
const spId = (p: any): string => p.id || p.signingProfileId;

const QUALIFIERS_PLACEHOLDER = '{\n  "2.23.140.1.2.1": {\n    "cpsUri": "https://example.com/cps",\n    "userNotice": "Subscriber agrees to the relying party agreement.",\n    "critical": false\n  }\n}';

/// <summary>
/// Editable detail page for a single signing profile (a tab on Profile Management). View shows the
/// allowed algorithms/EKUs, name constraints, policy config and the lazily-loaded allowed cert
/// profiles. Edit changes all fields plus the allowed cert profiles (step-up MFA).
/// </summary>
const SigningProfileDetail: React.FC = () => {
    // Extended key usages come from the OID catalog, not a hardcoded list — see useEkuCatalog.
    const ekuCatalog = useEkuCatalog();
    const { id } = useParams<{ id: string }>();
    const navigate = useNavigate();
    const { requireStepUp } = useStepUp();
    const { showToast } = useToast();

    const [profile, setProfile] = useState<any | null>(null);
    const [authorities, setAuthorities] = useState<any[]>([]);
    const [certProfiles, setCertProfiles] = useState<any[]>([]);
    const [allowedCpIds, setAllowedCpIds] = useState<string[]>([]);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState<string | null>(null);
    const [refresh, setRefresh] = useState(0);
    const [qualifiersError, setQualifiersError] = useState<string | null>(null);

    const [confirmDelete, setConfirmDelete] = useState(false);
    const [deleting, setDeleting] = useState(false);

    const [editForm, setEditForm] = useState({
        name: '', description: '', isDefault: false, issuerId: '',
        allowedAlgorithms: [] as string[], allowedEkus: [] as string[],
        maxPathLength: '', nameConstraintsPermitted: '', nameConstraintsExcluded: '',
        policyOids: '', inhibitAnyPolicy: false, inheritsFromId: '', inheritanceEnabled: false,
        extendedKeyUsageCritical: false, policyQualifiersJson: '{}',
        allowedCertProfileIds: [] as string[],
    });
    // Snapshot of the loaded values — drives dirty-detection and Cancel-reset for the unified save.
    const [initialForm, setInitialForm] = useState(editForm);

    useEffect(() => {
        let cancelled = false;
        setLoading(true);
        setError(null);
        Promise.all([
            apiGet<any>('/api/v1/admin/signing-profiles'),
            apiGet<any>('/api/v1/admin/authorities').catch(() => []),
            apiGet<any>('/api/v1/admin/cert-profiles').catch(() => []),
            apiGet<any>(`/api/v1/admin/signing-profiles/${id}/allowed-cert-profiles`).catch(() => []),
        ]).then(([data, authData, cpData, allowedData]) => {
            if (cancelled) return;
            const list = Array.isArray(data) ? data : (data.items || data.profiles || []);
            const p = list.find((x: any) => spId(x) === id) || null;
            setProfile(p);
            setAuthorities(Array.isArray(authData) ? authData : (authData.items || authData.authorities || []));
            setCertProfiles(Array.isArray(cpData) ? cpData : (cpData.items || cpData.profiles || []));
            const allowed = (Array.isArray(allowedData) ? allowedData : []).map((x: any) => x.id || x.certProfileId || x);
            setAllowedCpIds(allowed);
            if (p) {
                const seeded = {
                    name: p.name || '', description: p.description || '', isDefault: !!p.isDefault, issuerId: p.issuerId || '',
                    allowedAlgorithms: parseJsonArray(p.allowedAlgorithms),
                    // Wire name is `allowedEKUs`: System.Text.Json's camelCase policy lowercases only
                    // the leading char of `AllowedEKUs`. Reading `allowedEkus` gave undefined, so the
                    // toggles rendered empty and saving wrote that empty list back over the real one.
                    allowedEkus: canonicalizeUsages(parseListField(p.allowedEKUs ?? p.allowedEkus), ekuCatalog.options, ekuCatalog.aliases),
                    maxPathLength: p.maxPathLength != null ? String(p.maxPathLength) : '',
                    nameConstraintsPermitted: typeof p.nameConstraintsPermitted === 'object' ? JSON.stringify(p.nameConstraintsPermitted) : (p.nameConstraintsPermitted || ''),
                    nameConstraintsExcluded: typeof p.nameConstraintsExcluded === 'object' ? JSON.stringify(p.nameConstraintsExcluded) : (p.nameConstraintsExcluded || ''),
                    policyOids: parseJsonArray(p.policyOids).join(', '), inhibitAnyPolicy: !!p.inhibitAnyPolicy,
                    inheritsFromId: p.inheritsFromId || '', inheritanceEnabled: !!p.inheritanceEnabled,
                    extendedKeyUsageCritical: !!p.extendedKeyUsageCritical,
                    policyQualifiersJson: typeof p.policyQualifiersJson === 'string' ? (p.policyQualifiersJson || '{}') : (p.policyQualifiersJson ? JSON.stringify(p.policyQualifiersJson, null, 2) : '{}'),
                    allowedCertProfileIds: allowed,
                };
                setEditForm(seeded);
                setInitialForm(seeded);
            }
            setLoading(false);
        }).catch((err) => { if (!cancelled) { setError(err.message || 'Failed to load signing profile'); setLoading(false); } });
        return () => { cancelled = true; };
    }, [id, refresh]);

    const authorityName = (issuerId: string | undefined) => {
        if (!issuerId) return undefined;
        const a = authorities.find((x) => x.certificateId === issuerId || x.id === issuerId);
        return a ? (a.name || a.commonName || issuerId) : issuerId;
    };
    const cpName = (cpId: string) => {
        const cp = certProfiles.find((c) => (c.id || c.certProfileId) === cpId);
        return cp ? cp.name : cpId;
    };

    const dirty = JSON.stringify(editForm) !== JSON.stringify(initialForm);
    const handleCancel = () => { setEditForm(initialForm); setQualifiersError(null); };

    const handleSave = async () => {
        setQualifiersError(null);
        const rawQ = (editForm.policyQualifiersJson ?? '').trim();
        if (rawQ.length > 0) {
            let bad = false;
            try {
                const parsed = JSON.parse(rawQ);
                if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) { setQualifiersError('Policy qualifiers must be a JSON object mapping OIDs to qualifiers.'); bad = true; }
            } catch (err: any) { setQualifiersError(`Invalid JSON: ${err.message || 'parse error'}`); bad = true; }
            if (bad) throw new Error('Invalid policy qualifiers'); // keep the page in Edit; inline error shown
        }
        try {
            const body: any = {
                name: editForm.name, description: editForm.description, isDefault: editForm.isDefault,
                issuerId: editForm.issuerId || undefined,
                allowedAlgorithms: JSON.stringify(editForm.allowedAlgorithms),
                allowedEKUs: JSON.stringify(editForm.allowedEkus),
                maxPathLength: editForm.maxPathLength ? parseInt(editForm.maxPathLength) : null,
                nameConstraintsPermitted: editForm.nameConstraintsPermitted || undefined,
                nameConstraintsExcluded: editForm.nameConstraintsExcluded || undefined,
                policyOids: JSON.stringify(editForm.policyOids ? editForm.policyOids.split(',').map((s) => s.trim()).filter(Boolean) : []),
                inhibitAnyPolicy: editForm.inhibitAnyPolicy,
                inheritsFromId: editForm.inheritsFromId || undefined,
                inheritanceEnabled: editForm.inheritanceEnabled,
                extendedKeyUsageCritical: editForm.extendedKeyUsageCritical,
                policyQualifiersJson: rawQ.length > 0 ? rawQ : undefined,
                // Folded into the one step-up-gated update so the whole save is a single MFA prompt.
                allowedCertProfileIds: editForm.allowedCertProfileIds,
            };
            await apiPutWithMfa(`/api/v1/admin/signing-profiles/${id}`, body, requireStepUp, StepUpOps.UpdateSigningProfile, id!);
            showToast('success', 'Signing profile updated');
            setRefresh((r) => r + 1);
        } catch (err: any) {
            if (err.message !== 'Step-up MFA cancelled') showToast('error', err.message || 'Failed to update signing profile');
            throw err;
        }
    };

    const doDelete = async () => {
        setDeleting(true);
        try {
            await apiDeleteWithMfa(`/api/v1/admin/signing-profiles/${id}`, requireStepUp, StepUpOps.DeleteSigningProfile, id!);
            showToast('success', 'Signing profile deleted');
            navigate(SIGNING_TAB);
        } catch (err: any) {
            if (err.message !== 'Step-up MFA cancelled') showToast('error', err.message || 'Failed to delete signing profile');
        } finally {
            setDeleting(false);
            setConfirmDelete(false);
        }
    };

    if (loading) return <div className="p-6 text-sm text-gray-600 dark:text-gray-400">Loading…</div>;
    if (error) return <div className="p-6 text-sm text-red-800 dark:text-red-400">{error}</div>;
    if (!profile) return (
        <div className="p-6 space-y-3">
            <p className="text-sm text-gray-600 dark:text-gray-400">Signing profile not found.</p>
            <button onClick={() => navigate(SIGNING_TAB)} className="px-3 py-1.5 text-sm bg-gray-200 dark:bg-gray-700 rounded">Back to Signing Profiles</button>
        </div>
    );

    const p = profile;
    const toggleEku = (oid: string) => setEditForm({ ...editForm, allowedEkus: editForm.allowedEkus.includes(oid) ? editForm.allowedEkus.filter((o) => o !== oid) : [...editForm.allowedEkus, oid] });

    return (
        <DetailPage
            breadcrumbs={[{ label: 'Profile Management', to: SIGNING_TAB }, { label: 'Signing Profiles', to: SIGNING_TAB }, { label: p.name }]}
            title={p.name}
            status={p.isDefault ? <StatusBadge status="active" label="Default" /> : undefined}
            subtitle={authorityName(p.issuerId)}
            backTo={SIGNING_TAB}
            editable
            onSave={handleSave}
            onCancel={handleCancel}
            saveDisabled={!dirty || !editForm.name}
            actions={<button onClick={() => setConfirmDelete(true)} disabled={deleting} className="px-3 py-1.5 text-xs bg-red-50 dark:bg-red-900/50 text-red-800 dark:text-red-300 border border-red-300 dark:border-red-700 rounded hover:bg-red-900 disabled:opacity-50 transition-colors">Delete</button>}
        >
            {(mode) => mode === 'edit' ? (
                <DetailSection title="Edit Signing Profile">
                    <div className="space-y-3 max-w-3xl">
                        <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                            <div><label className={labelClass}>Name</label><input type="text" value={editForm.name} onChange={(e) => setEditForm({ ...editForm, name: e.target.value })} className={inputClass} /></div>
                            <div><label className={labelClass}>Description</label><input type="text" value={editForm.description} onChange={(e) => setEditForm({ ...editForm, description: e.target.value })} className={inputClass} /></div>
                            <div>
                                <label className={labelClass}>Issuer</label>
                                <select value={editForm.issuerId} onChange={(e) => setEditForm({ ...editForm, issuerId: e.target.value })} className={inputClass}>
                                    <option value="">-- Select Issuing Authority --</option>
                                    {authorities.map((a) => <option key={caCertId(a)} value={caCertId(a)}>{caDisplayName(a)}</option>)}
                                </select>
                            </div>
                            <div><label className={labelClass}>Max Path Length</label><input type="text" inputMode="numeric" value={editForm.maxPathLength} onChange={(e) => setEditForm({ ...editForm, maxPathLength: e.target.value.replace(/\D/g, '') })} className={inputClass} /></div>
                            <div><label className={labelClass}>Name Constraints Permitted (JSON)</label><input type="text" value={editForm.nameConstraintsPermitted} onChange={(e) => setEditForm({ ...editForm, nameConstraintsPermitted: e.target.value })} className={inputClass} /></div>
                            <div><label className={labelClass}>Name Constraints Excluded (JSON)</label><input type="text" value={editForm.nameConstraintsExcluded} onChange={(e) => setEditForm({ ...editForm, nameConstraintsExcluded: e.target.value })} className={inputClass} /></div>
                            <div><label className={labelClass}>Policy OIDs (comma-separated)</label><input type="text" value={editForm.policyOids} onChange={(e) => setEditForm({ ...editForm, policyOids: e.target.value })} className={inputClass} /></div>
                        </div>
                        <div>
                            <label className={labelClass}>Allowed EKUs</label>
                            <div className="flex flex-wrap gap-2">
                                {ekuCatalog.options.map((oid) => { const eku = { oid, label: ekuCatalog.label(oid) };
                                    const selected = editForm.allowedEkus.includes(eku.oid);
                                    return <button key={eku.oid} type="button" onClick={() => toggleEku(eku.oid)} className={`px-2 py-1 text-xs rounded border transition-colors ${selected ? 'bg-blue-600/30 text-blue-800 dark:text-blue-300 border-blue-300 dark:border-blue-600' : 'bg-gray-50 dark:bg-gray-900 text-gray-600 dark:text-gray-400 border-gray-300 dark:border-gray-700 hover:border-gray-500'}`}>{eku.label} <span className="text-[10px] text-gray-600 ml-1">{eku.oid}</span></button>;
                                })}
                            </div>
                        </div>
                        <div className="flex flex-wrap gap-4">
                            <label className="flex items-center gap-2 text-xs text-gray-700 dark:text-gray-300"><input type="checkbox" checked={editForm.isDefault} onChange={(e) => setEditForm({ ...editForm, isDefault: e.target.checked })} className="w-4 h-4 rounded" />Default Profile</label>
                            <label className="flex items-center gap-2 text-xs text-gray-700 dark:text-gray-300"><input type="checkbox" checked={editForm.inhibitAnyPolicy} onChange={(e) => setEditForm({ ...editForm, inhibitAnyPolicy: e.target.checked })} className="w-4 h-4 rounded" />Inhibit Any Policy</label>
                            <label className="flex items-center gap-2 text-xs text-gray-700 dark:text-gray-300"><input type="checkbox" checked={editForm.inheritanceEnabled} onChange={(e) => setEditForm({ ...editForm, inheritanceEnabled: e.target.checked })} className="w-4 h-4 rounded" />Enable Inheritance</label>
                        </div>
                        <div>
                            <label className="flex items-center gap-2 text-xs text-gray-700 dark:text-gray-300"><input type="checkbox" checked={!!editForm.extendedKeyUsageCritical} onChange={(e) => setEditForm({ ...editForm, extendedKeyUsageCritical: e.target.checked })} className="w-4 h-4 rounded" />Mark Extended Key Usage extension as critical</label>
                            <p className="text-[11px] text-gray-600 dark:text-gray-400 mt-1 ml-6">RFC 5280 §4.2.1.12 recommends marking the EKU extension critical when the certificate's purpose is restricted (e.g. a cert that must only be used for client auth).</p>
                        </div>
                        <div>
                            <label className={labelClass}>Policy qualifiers (JSON)</label>
                            <textarea value={editForm.policyQualifiersJson ?? '{}'} onChange={(e) => { setEditForm({ ...editForm, policyQualifiersJson: e.target.value }); if (qualifiersError) setQualifiersError(null); }} rows={8} placeholder={QUALIFIERS_PLACEHOLDER} className={`${inputClass} font-mono text-xs resize-y`} />
                            {qualifiersError && <p className="text-[11px] text-red-800 dark:text-red-400 mt-1">{qualifiersError}</p>}
                        </div>
                        <div><label className={labelClass}>Allowed Algorithms</label><MultiToggle options={SIGNING_ALLOWED_ALGORITHM_OPTIONS} selected={editForm.allowedAlgorithms} onChange={(next) => setEditForm({ ...editForm, allowedAlgorithms: next })} /></div>
                        <div className="last:mb-0">
                            <label className={labelClass}>Allowed Cert Profiles</label>
                            <div className="max-h-40 overflow-y-auto bg-gray-50 dark:bg-gray-900 border border-gray-300 dark:border-gray-700 rounded p-2 space-y-1">
                                {certProfiles.length === 0 && <span className="text-xs text-gray-600">No cert profiles available</span>}
                                {certProfiles.map((cp) => {
                                    const cid = cp.id || cp.certProfileId;
                                    return (
                                        <label key={cid} className="flex items-center gap-2 text-sm text-gray-900 dark:text-white cursor-pointer hover:bg-gray-100 dark:hover:bg-gray-800 px-1 rounded">
                                            <input type="checkbox" checked={editForm.allowedCertProfileIds.includes(cid)} onChange={(e) => setEditForm({ ...editForm, allowedCertProfileIds: e.target.checked ? [...editForm.allowedCertProfileIds, cid] : editForm.allowedCertProfileIds.filter((x) => x !== cid) })} className="accent-blue-500" />
                                            <span>{cp.name}</span>
                                            {cp.isCaProfile && <StatusBadge status="active" label="CA" />}
                                        </label>
                                    );
                                })}
                            </div>
                        </div>
                    </div>
                </DetailSection>
            ) : (<>
                <DetailSection title="Signing Profile">
                    <DetailField label="Name" value={p.name} />
                    <DetailField label="Description" value={p.description} />
                    <DetailField label="Default" value={p.isDefault ? 'Yes' : 'No'} />
                    <DetailField label="Issuer" value={authorityName(p.issuerId)} />
                    <div className="py-1"><span className="text-xs text-gray-600 dark:text-gray-400">Allowed Algorithms</span><CeilingList items={p.allowedAlgorithms} noun="algorithm" /></div>
                    <div className="py-1"><span className="text-xs text-gray-600 dark:text-gray-400">Allowed EKUs</span><CeilingList noun="EKU" raw={parseListField(p.allowedEKUs ?? p.allowedEkus)} items={canonicalizeUsages(parseListField(p.allowedEKUs ?? p.allowedEkus), ekuCatalog.options, ekuCatalog.aliases).map(ekuCatalog.label)} /></div>
                    <DetailField label="Max Path Length" value={p.maxPathLength != null ? String(p.maxPathLength) : undefined} />
                    <DetailField label="Name Constraints Permitted" value={typeof p.nameConstraintsPermitted === 'object' ? JSON.stringify(p.nameConstraintsPermitted) : p.nameConstraintsPermitted} />
                    <DetailField label="Name Constraints Excluded" value={typeof p.nameConstraintsExcluded === 'object' ? JSON.stringify(p.nameConstraintsExcluded) : p.nameConstraintsExcluded} />
                    <div className="py-1"><span className="text-xs text-gray-600 dark:text-gray-400">Policy OIDs</span><BadgeList items={p.policyOids} /></div>
                    <DetailField label="Inhibit Any Policy" value={p.inhibitAnyPolicy ? 'Yes' : 'No'} />
                    <DetailField label="EKU Extension Critical" value={p.extendedKeyUsageCritical ? 'Yes' : 'No'} />
                    <DetailField label="Policy Qualifiers (JSON)" value={typeof p.policyQualifiersJson === 'string' ? p.policyQualifiersJson : (p.policyQualifiersJson ? JSON.stringify(p.policyQualifiersJson) : undefined)} mono />
                    <div className="py-1">
                        <span className="text-xs text-gray-600 dark:text-gray-400">Allowed Cert Profiles</span>
                        {allowedCpIds.length > 0 ? (
                            <div className="flex flex-wrap gap-1 mt-1">
                                {allowedCpIds.map((cid, i) => <span key={i} className="px-2 py-0.5 text-xs rounded bg-blue-50 dark:bg-blue-900/40 text-blue-800 dark:text-blue-300 border border-blue-300 dark:border-blue-800">{cpName(cid)}</span>)}
                            </div>
                        ) : <span className="text-xs text-gray-600 ml-2">None</span>}
                    </div>
                </DetailSection>

                <ConfirmModal
                    isOpen={confirmDelete}
                    title="Delete Signing Profile"
                    message={`Delete signing profile "${p.name}"? This cannot be undone.`}
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

export default SigningProfileDetail;
