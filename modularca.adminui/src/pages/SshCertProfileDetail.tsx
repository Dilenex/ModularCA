import React, { useEffect, useState } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { apiGet, apiPutWithMfa, apiDelete, apiDeleteWithMfa } from '../api/client';
import { useStepUp } from '../components/StepUpMfaContext';
import { useToast } from '@shared/context/ToastContext';
import { DetailField } from '@shared/components/cards/DetailField';
import ConfirmModal from '../components/ConfirmModal';
import { DetailPage, DetailSection } from '../components/DetailPage';
import { SSH_EXTENSION_OPTIONS, parseJsonArray, BadgeList, MultiToggle } from './profileHelpers';
import { inputClass, labelClass } from '@shared/components/forms';
import { StepUpOps } from '@shared/generated';

const SSH_CERT_TAB = `/profiles?tab=${encodeURIComponent('SSH Cert')}`;

/// <summary>
/// Editable detail page for a single SSH cert profile (a tab on Profile Management). View shows the
/// principal patterns, limits and allowed/required extensions; Edit changes all fields (step-up MFA).
/// </summary>
const SshCertProfileDetail: React.FC = () => {
    const { id } = useParams<{ id: string }>();
    const navigate = useNavigate();
    const { requireStepUp } = useStepUp();
    const { showToast } = useToast();

    const [profile, setProfile] = useState<any | null>(null);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState<string | null>(null);
    const [refresh, setRefresh] = useState(0);
    const [confirmDelete, setConfirmDelete] = useState(false);
    const [deleting, setDeleting] = useState(false);

    const emptyForm = {
        name: '', description: '', allowedPrincipalPatterns: '', maxPrincipals: '10',
        allowedExtensions: [] as string[], requiredExtensions: [] as string[], maxValidityHours: '720',
    };
    const [editForm, setEditForm] = useState(emptyForm);
    const [initialForm, setInitialForm] = useState(emptyForm);

    const dirty = JSON.stringify(editForm) !== JSON.stringify(initialForm);

    useEffect(() => {
        let cancelled = false;
        setLoading(true);
        setError(null);
        apiGet<any>('/api/v1/admin/ssh/profiles/cert')
            .then((data) => {
                if (cancelled) return;
                const list = Array.isArray(data) ? data : [];
                const p = list.find((x: any) => x.id === id) || null;
                setProfile(p);
                if (p) {
                    const seeded = {
                        name: p.name || '', description: p.description || '',
                        allowedPrincipalPatterns: parseJsonArray(p.allowedPrincipalPatterns).join('\n'),
                        maxPrincipals: String(p.maxPrincipals ?? 10),
                        allowedExtensions: parseJsonArray(p.allowedExtensions),
                        requiredExtensions: parseJsonArray(p.requiredExtensions),
                        maxValidityHours: String(p.maxValidityHours ?? 720),
                    };
                    setEditForm(seeded);
                    setInitialForm(seeded);
                }
                setLoading(false);
            })
            .catch((err) => { if (!cancelled) { setError(err.message || 'Failed to load SSH cert profile'); setLoading(false); } });
        return () => { cancelled = true; };
    }, [id, refresh]);

    const handleSave = async () => {
        try {
            const patterns = editForm.allowedPrincipalPatterns.trim()
                ? editForm.allowedPrincipalPatterns.split('\n').map((s) => s.trim()).filter(Boolean)
                : [];
            await apiPutWithMfa(`/api/v1/admin/ssh/profiles/cert/${id}`, {
                name: editForm.name, description: editForm.description || undefined,
                allowedPrincipalPatterns: JSON.stringify(patterns),
                maxPrincipals: parseInt(editForm.maxPrincipals) || 10,
                allowedExtensions: JSON.stringify(editForm.allowedExtensions),
                requiredExtensions: JSON.stringify(editForm.requiredExtensions),
                maxValidityHours: parseInt(editForm.maxValidityHours) || 720,
            }, requireStepUp, StepUpOps.UpdateSshProfile, id!);
            showToast('success', 'SSH cert profile updated');
            setRefresh((r) => r + 1);
        } catch (err: any) {
            if (err.message !== 'Step-up MFA cancelled') showToast('error', err.message || 'Failed to update SSH cert profile');
            throw err;
        }
    };

    const handleCancel = () => setEditForm(initialForm);

    const doDelete = async () => {
        setDeleting(true);
        try {
            await apiDeleteWithMfa(`/api/v1/admin/ssh/profiles/cert/${id}`, requireStepUp, StepUpOps.DeleteSshProfile, id);
            showToast('success', 'SSH cert profile deleted');
            navigate(SSH_CERT_TAB);
        } catch (err: any) {
            showToast('error', err.message || 'Failed to delete');
        } finally {
            setDeleting(false);
            setConfirmDelete(false);
        }
    };

    if (loading) return <div className="p-6 text-sm text-gray-600 dark:text-gray-400">Loading…</div>;
    if (error) return <div className="p-6 text-sm text-red-800 dark:text-red-400">{error}</div>;
    if (!profile) return (
        <div className="p-6 space-y-3">
            <p className="text-sm text-gray-600 dark:text-gray-400">SSH cert profile not found.</p>
            <button onClick={() => navigate(SSH_CERT_TAB)} className="px-3 py-1.5 text-sm bg-gray-200 dark:bg-gray-700 rounded">Back to SSH Cert Profiles</button>
        </div>
    );

    const p = profile;

    return (
        <DetailPage
            breadcrumbs={[{ label: 'Profile Management', to: SSH_CERT_TAB }, { label: 'SSH Cert Profiles', to: SSH_CERT_TAB }, { label: p.name }]}
            title={p.name}
            subtitle={`Max ${p.maxPrincipals} principals · ${p.maxValidityHours}h`}
            backTo={SSH_CERT_TAB}
            editable
            onSave={handleSave}
            onCancel={handleCancel}
            saveDisabled={!dirty || !editForm.name}
            actions={<button onClick={() => setConfirmDelete(true)} disabled={deleting} className="px-3 py-1.5 text-xs bg-red-50 dark:bg-red-900/50 text-red-800 dark:text-red-300 border border-red-300 dark:border-red-700 rounded hover:bg-red-900 disabled:opacity-50 transition-colors">Delete</button>}
        >
            {(mode) => mode === 'edit' ? (
                <DetailSection title="Edit SSH Cert Profile">
                    <div className="space-y-3 max-w-3xl">
                        <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                            <div><label className={labelClass}>Name</label><input type="text" value={editForm.name} onChange={(e) => setEditForm({ ...editForm, name: e.target.value })} className={inputClass} /></div>
                            <div><label className={labelClass}>Description</label><input type="text" value={editForm.description} onChange={(e) => setEditForm({ ...editForm, description: e.target.value })} className={inputClass} /></div>
                            <div><label className={labelClass}>Max Principals</label><input type="text" inputMode="numeric" value={editForm.maxPrincipals} onChange={(e) => setEditForm({ ...editForm, maxPrincipals: e.target.value.replace(/\D/g, '') })} className={inputClass} /></div>
                            <div><label className={labelClass}>Max Validity Hours</label><input type="text" inputMode="numeric" value={editForm.maxValidityHours} onChange={(e) => setEditForm({ ...editForm, maxValidityHours: e.target.value.replace(/\D/g, '') })} className={inputClass} /></div>
                        </div>
                        <div><label className={labelClass}>Allowed Principal Patterns (one regex per line)</label><textarea rows={3} value={editForm.allowedPrincipalPatterns} onChange={(e) => setEditForm({ ...editForm, allowedPrincipalPatterns: e.target.value })} className={inputClass} /></div>
                        <div><label className={labelClass}>Allowed Extensions</label><MultiToggle options={SSH_EXTENSION_OPTIONS} selected={editForm.allowedExtensions} onChange={(next) => setEditForm({ ...editForm, allowedExtensions: next })} /></div>
                        <div><label className={labelClass}>Required Extensions</label><MultiToggle options={SSH_EXTENSION_OPTIONS} selected={editForm.requiredExtensions} onChange={(next) => setEditForm({ ...editForm, requiredExtensions: next })} /></div>
                    </div>
                </DetailSection>
            ) : (<>
                <DetailSection title="SSH Cert Profile">
                    <DetailField label="ID" value={p.id} mono />
                    <DetailField label="Name" value={p.name} />
                    <DetailField label="Description" value={p.description} />
                    <DetailField label="Max Principals" value={String(p.maxPrincipals)} />
                    <DetailField label="Max Validity Hours" value={String(p.maxValidityHours)} />
                    <div className="py-1"><span className="text-xs text-gray-600 dark:text-gray-400">Allowed Principal Patterns</span><BadgeList items={p.allowedPrincipalPatterns} /></div>
                    <div className="py-1"><span className="text-xs text-gray-600 dark:text-gray-400">Allowed Extensions</span><BadgeList items={p.allowedExtensions} /></div>
                    <div className="py-1"><span className="text-xs text-gray-600 dark:text-gray-400">Required Extensions</span><BadgeList items={p.requiredExtensions} /></div>
                    {p.createdAt && <DetailField label="Created" value={new Date(p.createdAt).toLocaleString()} />}
                </DetailSection>

                <ConfirmModal
                    isOpen={confirmDelete}
                    title="Delete SSH Cert Profile"
                    message={`Delete SSH cert profile "${p.name}"? This cannot be undone.`}
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

export default SshCertProfileDetail;
