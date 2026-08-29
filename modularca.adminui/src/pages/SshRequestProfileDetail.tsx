import React, { useEffect, useState } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { apiGet, apiPutWithMfa, apiDelete, apiDeleteWithMfa } from '../api/client';
import { useStepUp } from '../components/StepUpMfaContext';
import { useToast } from '@shared/context/ToastContext';
import { StatusBadge } from '@shared/components/cards/StatusBadge';
import { DetailField } from '@shared/components/cards/DetailField';
import ConfirmModal from '../components/ConfirmModal';
import { DetailPage, DetailSection } from '../components/DetailPage';
import { inputClass, labelClass, parseJsonArray, caRowId, caDisplayName,
} from './profileHelpers';
import { StepUpOps } from '@shared/generated';

const SSH_REQUEST_TAB = `/profiles?tab=${encodeURIComponent('SSH Request')}`;

/// <summary>
/// Editable detail page for a single SSH request profile (a tab on Profile Management). View shows the
/// allowed signing/cert profiles, approval requirement and CA scope; Edit changes all fields (step-up MFA).
/// </summary>
const SshRequestProfileDetail: React.FC = () => {
    const { id } = useParams<{ id: string }>();
    const navigate = useNavigate();
    const { requireStepUp } = useStepUp();
    const { showToast } = useToast();

    const [profile, setProfile] = useState<any | null>(null);
    const [signingProfiles, setSigningProfiles] = useState<any[]>([]);
    const [certProfiles, setCertProfiles] = useState<any[]>([]);
    const [authorities, setAuthorities] = useState<any[]>([]);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState<string | null>(null);
    const [refresh, setRefresh] = useState(0);
    const [confirmDelete, setConfirmDelete] = useState(false);
    const [deleting, setDeleting] = useState(false);

    const emptyForm = {
        name: '', description: '', allowedSshSigningProfileIds: [] as string[],
        allowedSshCertProfileIds: [] as string[], requireApproval: false,
        maxValidityHours: '720', certificateAuthorityId: '',
    };
    const [editForm, setEditForm] = useState(emptyForm);
    const [initialForm, setInitialForm] = useState(emptyForm);

    useEffect(() => {
        let cancelled = false;
        setLoading(true);
        setError(null);
        Promise.all([
            apiGet<any>('/api/v1/admin/ssh/profiles/request'),
            apiGet<any>('/api/v1/admin/ssh/profiles/signing').catch(() => []),
            apiGet<any>('/api/v1/admin/ssh/profiles/cert').catch(() => []),
            apiGet<any>('/api/v1/admin/authorities').catch(() => []),
        ]).then(([data, spData, cpData, authData]) => {
            if (cancelled) return;
            const list = Array.isArray(data) ? data : [];
            const p = list.find((x: any) => x.id === id) || null;
            setProfile(p);
            setSigningProfiles(Array.isArray(spData) ? spData : []);
            setCertProfiles(Array.isArray(cpData) ? cpData : []);
            setAuthorities(Array.isArray(authData) ? authData : (authData.items || authData.authorities || []));
            if (p) {
                const seeded = {
                    name: p.name || '', description: p.description || '',
                    allowedSshSigningProfileIds: parseJsonArray(p.allowedSshSigningProfileIds),
                    allowedSshCertProfileIds: parseJsonArray(p.allowedSshCertProfileIds),
                    requireApproval: !!p.requireApproval, maxValidityHours: String(p.maxValidityHours ?? 720),
                    certificateAuthorityId: p.certificateAuthorityId || '',
                };
                setEditForm(seeded);
                setInitialForm(seeded);
            }
            setLoading(false);
        }).catch((err) => { if (!cancelled) { setError(err.message || 'Failed to load SSH request profile'); setLoading(false); } });
        return () => { cancelled = true; };
    }, [id, refresh]);

    const resolveNames = (idsJson: any, items: any[]) => parseJsonArray(idsJson).map((x) => items.find((i) => i.id === x)?.name || x);
    const caName = (caId: string) => {
        const a = authorities.find((x) => caRowId(x) === caId);
        return a ? (a.name || a.commonName || caId) : caId;
    };

    const dirty = JSON.stringify(editForm) !== JSON.stringify(initialForm);

    const handleSave = async () => {
        try {
            await apiPutWithMfa(`/api/v1/admin/ssh/profiles/request/${id}`, {
                name: editForm.name, description: editForm.description || undefined,
                allowedSshSigningProfileIds: JSON.stringify(editForm.allowedSshSigningProfileIds),
                allowedSshCertProfileIds: JSON.stringify(editForm.allowedSshCertProfileIds),
                requireApproval: editForm.requireApproval,
                maxValidityHours: parseInt(editForm.maxValidityHours) || 720,
                certificateAuthorityId: editForm.certificateAuthorityId || undefined,
            }, requireStepUp, StepUpOps.UpdateSshProfile, id!);
            showToast('success', 'SSH request profile updated');
            setRefresh((r) => r + 1);
        } catch (err: any) {
            if (err.message !== 'Step-up MFA cancelled') showToast('error', err.message || 'Failed to update SSH request profile');
            throw err;
        }
    };

    const handleCancel = () => setEditForm(initialForm);

    const doDelete = async () => {
        setDeleting(true);
        try {
            await apiDeleteWithMfa(`/api/v1/admin/ssh/profiles/request/${id}`, requireStepUp, StepUpOps.DeleteSshProfile, id);
            showToast('success', 'SSH request profile deleted');
            navigate(SSH_REQUEST_TAB);
        } catch (err: any) {
            showToast('error', err.message || 'Failed to delete');
        } finally {
            setDeleting(false);
            setConfirmDelete(false);
        }
    };

    const toggleId = (key: 'allowedSshSigningProfileIds' | 'allowedSshCertProfileIds', val: string) =>
        setEditForm({ ...editForm, [key]: editForm[key].includes(val) ? editForm[key].filter((x) => x !== val) : [...editForm[key], val] });

    if (loading) return <div className="p-6 text-sm text-gray-600 dark:text-gray-400">Loading…</div>;
    if (error) return <div className="p-6 text-sm text-red-800 dark:text-red-400">{error}</div>;
    if (!profile) return (
        <div className="p-6 space-y-3">
            <p className="text-sm text-gray-600 dark:text-gray-400">SSH request profile not found.</p>
            <button onClick={() => navigate(SSH_REQUEST_TAB)} className="px-3 py-1.5 text-sm bg-gray-200 dark:bg-gray-700 rounded">Back to SSH Request Profiles</button>
        </div>
    );

    const p = profile;
    const checkboxList = (items: any[], emptyText: string, key: 'allowedSshSigningProfileIds' | 'allowedSshCertProfileIds') => (
        <div className="max-h-40 overflow-y-auto bg-gray-50 dark:bg-gray-900 border border-gray-300 dark:border-gray-700 rounded p-2 space-y-1">
            {items.length === 0 && <span className="text-xs text-gray-600">{emptyText}</span>}
            {items.map((it) => (
                <label key={it.id} className="flex items-center gap-2 text-sm text-gray-900 dark:text-white cursor-pointer hover:bg-gray-100 dark:hover:bg-gray-800 px-1 rounded">
                    <input type="checkbox" checked={editForm[key].includes(it.id)} onChange={() => toggleId(key, it.id)} className="accent-blue-500" />
                    <span>{it.name}</span>
                </label>
            ))}
        </div>
    );

    return (
        <DetailPage
            breadcrumbs={[{ label: 'Profile Management', to: SSH_REQUEST_TAB }, { label: 'SSH Request Profiles', to: SSH_REQUEST_TAB }, { label: p.name }]}
            title={p.name}
            status={p.requireApproval ? <StatusBadge status="pending" label="Approval" /> : undefined}
            subtitle={`${p.maxValidityHours}h max`}
            backTo={SSH_REQUEST_TAB}
            editable
            onSave={handleSave}
            onCancel={handleCancel}
            saveDisabled={!dirty || !editForm.name}
            actions={<button onClick={() => setConfirmDelete(true)} disabled={deleting} className="px-3 py-1.5 text-xs bg-red-50 dark:bg-red-900/50 text-red-800 dark:text-red-300 border border-red-300 dark:border-red-700 rounded hover:bg-red-900 disabled:opacity-50 transition-colors">Delete</button>}
        >
            {(mode) => mode === 'edit' ? (
                <DetailSection title="Edit SSH Request Profile">
                    <div className="space-y-3 max-w-3xl">
                        <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                            <div><label className={labelClass}>Name</label><input type="text" value={editForm.name} onChange={(e) => setEditForm({ ...editForm, name: e.target.value })} className={inputClass} /></div>
                            <div><label className={labelClass}>Description</label><input type="text" value={editForm.description} onChange={(e) => setEditForm({ ...editForm, description: e.target.value })} className={inputClass} /></div>
                            <div><label className={labelClass}>Max Validity Hours</label><input type="text" inputMode="numeric" value={editForm.maxValidityHours} onChange={(e) => setEditForm({ ...editForm, maxValidityHours: e.target.value.replace(/\D/g, '') })} className={inputClass} /></div>
                            <div>
                                <label className={labelClass}>CA Scope</label>
                                <select value={editForm.certificateAuthorityId} onChange={(e) => setEditForm({ ...editForm, certificateAuthorityId: e.target.value })} className={inputClass}>
                                    <option value="">-- Any CA --</option>
                                    {authorities.map((a) => <option key={caRowId(a)} value={caRowId(a)}>{caDisplayName(a)}</option>)}
                                </select>
                            </div>
                        </div>
                        <div className="flex flex-wrap gap-4">
                            <label className="flex items-center gap-2 text-xs text-gray-700 dark:text-gray-300"><input type="checkbox" checked={editForm.requireApproval} onChange={(e) => setEditForm({ ...editForm, requireApproval: e.target.checked })} className="w-4 h-4 rounded" />Require Approval</label>
                        </div>
                        <div><label className={labelClass}>Allowed SSH Signing Profiles</label>{checkboxList(signingProfiles, 'No signing profiles available', 'allowedSshSigningProfileIds')}</div>
                        <div><label className={labelClass}>Allowed SSH Cert Profiles</label>{checkboxList(certProfiles, 'No cert profiles available', 'allowedSshCertProfileIds')}</div>
                    </div>
                </DetailSection>
            ) : (<>
                <DetailSection title="SSH Request Profile">
                    <DetailField label="ID" value={p.id} mono />
                    <DetailField label="Name" value={p.name} />
                    <DetailField label="Description" value={p.description} />
                    <DetailField label="CA Scope" value={p.certificateAuthorityId ? caName(p.certificateAuthorityId) : 'Any CA'} />
                    <DetailField label="Require Approval" value={p.requireApproval ? 'Yes' : 'No'} />
                    <DetailField label="Max Validity Hours" value={String(p.maxValidityHours)} />
                    <div className="py-1">
                        <span className="text-xs text-gray-600 dark:text-gray-400">Allowed Signing Profiles</span>
                        <div className="flex flex-wrap gap-1 mt-1">
                            {resolveNames(p.allowedSshSigningProfileIds, signingProfiles).map((name, i) => <span key={i} className="px-2 py-0.5 text-xs rounded bg-blue-50 dark:bg-blue-900/40 text-blue-800 dark:text-blue-300 border border-blue-300 dark:border-blue-800">{name}</span>)}
                            {resolveNames(p.allowedSshSigningProfileIds, signingProfiles).length === 0 && <span className="text-gray-600 text-xs">Any</span>}
                        </div>
                    </div>
                    <div className="py-1">
                        <span className="text-xs text-gray-600 dark:text-gray-400">Allowed Cert Profiles</span>
                        <div className="flex flex-wrap gap-1 mt-1">
                            {resolveNames(p.allowedSshCertProfileIds, certProfiles).map((name, i) => <span key={i} className="px-2 py-0.5 text-xs rounded bg-blue-50 dark:bg-blue-900/40 text-blue-800 dark:text-blue-300 border border-blue-300 dark:border-blue-800">{name}</span>)}
                            {resolveNames(p.allowedSshCertProfileIds, certProfiles).length === 0 && <span className="text-gray-600 text-xs">Any</span>}
                        </div>
                    </div>
                    {p.createdAt && <DetailField label="Created" value={new Date(p.createdAt).toLocaleString()} />}
                </DetailSection>

                <ConfirmModal
                    isOpen={confirmDelete}
                    title="Delete SSH Request Profile"
                    message={`Delete SSH request profile "${p.name}"? This cannot be undone.`}
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

export default SshRequestProfileDetail;
