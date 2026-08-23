import React, { useEffect, useState } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { apiGet, apiPutWithMfa, apiDelete, apiDeleteWithMfa } from '../api/client';
import { useStepUp } from '../components/StepUpMfaContext';
import { useToast } from '../context/ToastContext';
import StatusBadge from '../components/cards/StatusBadge';
import DetailField from '../components/cards/DetailField';
import ConfirmModal from '../components/ConfirmModal';
import { DetailPage, DetailSection } from '../components/DetailPage';
import { SSH_EXTENSION_OPTIONS, inputClass, labelClass, parseJsonArray, BadgeList, MultiToggle } from './profileHelpers';

const SSH_SIGNING_TAB = `/profiles?tab=${encodeURIComponent('SSH Signing')}`;

/// <summary>
/// Editable detail page for a single SSH signing profile (a tab on Profile Management). View shows
/// the bound CA key, validity, allow flags and extensions; Edit changes all fields (step-up MFA save).
/// </summary>
const SshSigningProfileDetail: React.FC = () => {
    const { id } = useParams<{ id: string }>();
    const navigate = useNavigate();
    const { requireStepUp } = useStepUp();
    const { showToast } = useToast();

    const [profile, setProfile] = useState<any | null>(null);
    const [caKeys, setCaKeys] = useState<any[]>([]);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState<string | null>(null);
    const [refresh, setRefresh] = useState(0);
    const [confirmDelete, setConfirmDelete] = useState(false);
    const [deleting, setDeleting] = useState(false);

    const emptyForm = {
        name: '', description: '', sshCaKeyId: '', maxValidityHours: '720',
        allowUserCerts: true, allowHostCerts: false, forceCommand: '', sourceAddressRestrictions: '',
        defaultExtensions: [] as string[],
    };
    const [editForm, setEditForm] = useState(emptyForm);
    const [initialForm, setInitialForm] = useState(emptyForm);

    useEffect(() => {
        let cancelled = false;
        setLoading(true);
        setError(null);
        Promise.all([
            apiGet<any>('/api/v1/admin/ssh/profiles/signing'),
            apiGet<any>('/api/v1/admin/ssh/ca-keys').catch(() => []),
        ]).then(([data, keyData]) => {
            if (cancelled) return;
            const list = Array.isArray(data) ? data : [];
            const p = list.find((x: any) => x.id === id) || null;
            setProfile(p);
            setCaKeys(Array.isArray(keyData) ? keyData : []);
            if (p) {
                const seeded = {
                    name: p.name || '', description: p.description || '', sshCaKeyId: p.sshCaKeyId || '',
                    maxValidityHours: String(p.maxValidityHours ?? 720),
                    allowUserCerts: !!p.allowUserCerts, allowHostCerts: !!p.allowHostCerts,
                    forceCommand: p.forceCommand || '',
                    sourceAddressRestrictions: parseJsonArray(p.sourceAddressRestrictions).join(', '),
                    defaultExtensions: parseJsonArray(p.defaultExtensions),
                };
                setEditForm(seeded);
                setInitialForm(seeded);
            }
            setLoading(false);
        }).catch((err) => { if (!cancelled) { setError(err.message || 'Failed to load SSH signing profile'); setLoading(false); } });
        return () => { cancelled = true; };
    }, [id, refresh]);

    const caKeyName = (kid: string) => caKeys.find((k) => k.id === kid)?.name || kid;

    const dirty = JSON.stringify(editForm) !== JSON.stringify(initialForm);

    const handleSave = async () => {
        try {
            await apiPutWithMfa(`/api/v1/admin/ssh/profiles/signing/${id}`, {
                name: editForm.name, description: editForm.description || undefined, sshCaKeyId: editForm.sshCaKeyId,
                maxValidityHours: parseInt(editForm.maxValidityHours) || 720,
                allowUserCerts: editForm.allowUserCerts, allowHostCerts: editForm.allowHostCerts,
                forceCommand: editForm.forceCommand || undefined,
                sourceAddressRestrictions: JSON.stringify(editForm.sourceAddressRestrictions ? editForm.sourceAddressRestrictions.split(',').map((s) => s.trim()).filter(Boolean) : []),
                defaultExtensions: JSON.stringify(editForm.defaultExtensions),
            }, requireStepUp, 'update-ssh-profile', id!);
            showToast('success', 'SSH signing profile updated');
            setRefresh((r) => r + 1);
        } catch (err: any) {
            if (err.message !== 'Step-up MFA cancelled') showToast('error', err.message || 'Failed to update SSH signing profile');
            throw err;
        }
    };

    const handleCancel = () => setEditForm(initialForm);

    const doDelete = async () => {
        setDeleting(true);
        try {
            await apiDeleteWithMfa(`/api/v1/admin/ssh/profiles/signing/${id}`, requireStepUp, 'delete-ssh-profile', id);
            showToast('success', 'SSH signing profile deleted');
            navigate(SSH_SIGNING_TAB);
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
            <p className="text-sm text-gray-600 dark:text-gray-400">SSH signing profile not found.</p>
            <button onClick={() => navigate(SSH_SIGNING_TAB)} className="px-3 py-1.5 text-sm bg-gray-200 dark:bg-gray-700 rounded">Back to SSH Signing Profiles</button>
        </div>
    );

    const p = profile;

    return (
        <DetailPage
            breadcrumbs={[{ label: 'Profile Management', to: SSH_SIGNING_TAB }, { label: 'SSH Signing Profiles', to: SSH_SIGNING_TAB }, { label: p.name }]}
            title={p.name}
            status={<span className="flex items-center gap-2">{p.allowUserCerts && <StatusBadge status="active" label="User" />}{p.allowHostCerts && <StatusBadge status="pending" label="Host" />}</span>}
            subtitle={caKeyName(p.sshCaKeyId)}
            backTo={SSH_SIGNING_TAB}
            editable
            onSave={handleSave}
            onCancel={handleCancel}
            saveDisabled={!dirty || !editForm.name || !editForm.sshCaKeyId}
            actions={<button onClick={() => setConfirmDelete(true)} disabled={deleting} className="px-3 py-1.5 text-xs bg-red-50 dark:bg-red-900/50 text-red-800 dark:text-red-300 border border-red-300 dark:border-red-700 rounded hover:bg-red-900 disabled:opacity-50 transition-colors">Delete</button>}
        >
            {(mode) => mode === 'edit' ? (
                <DetailSection title="Edit SSH Signing Profile">
                    <div className="space-y-3 max-w-3xl">
                        <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                            <div><label className={labelClass}>Name</label><input type="text" value={editForm.name} onChange={(e) => setEditForm({ ...editForm, name: e.target.value })} className={inputClass} /></div>
                            <div><label className={labelClass}>Description</label><input type="text" value={editForm.description} onChange={(e) => setEditForm({ ...editForm, description: e.target.value })} className={inputClass} /></div>
                            <div>
                                <label className={labelClass}>SSH CA Key</label>
                                <select value={editForm.sshCaKeyId} onChange={(e) => setEditForm({ ...editForm, sshCaKeyId: e.target.value })} className={inputClass}>
                                    <option value="">-- Select CA Key --</option>
                                    {caKeys.map((k) => <option key={k.id} value={k.id}>{k.name} ({k.keyType})</option>)}
                                </select>
                            </div>
                            <div><label className={labelClass}>Max Validity Hours</label><input type="text" inputMode="numeric" value={editForm.maxValidityHours} onChange={(e) => setEditForm({ ...editForm, maxValidityHours: e.target.value.replace(/\D/g, '') })} className={inputClass} /></div>
                            <div><label className={labelClass}>Force Command (optional)</label><input type="text" value={editForm.forceCommand} onChange={(e) => setEditForm({ ...editForm, forceCommand: e.target.value })} className={inputClass} /></div>
                            <div><label className={labelClass}>Source Address Restrictions (comma-separated)</label><input type="text" value={editForm.sourceAddressRestrictions} onChange={(e) => setEditForm({ ...editForm, sourceAddressRestrictions: e.target.value })} className={inputClass} /></div>
                        </div>
                        <div className="flex flex-wrap gap-4">
                            <label className="flex items-center gap-2 text-xs text-gray-700 dark:text-gray-300"><input type="checkbox" checked={editForm.allowUserCerts} onChange={(e) => setEditForm({ ...editForm, allowUserCerts: e.target.checked })} className="w-4 h-4 rounded" />Allow User Certs</label>
                            <label className="flex items-center gap-2 text-xs text-gray-700 dark:text-gray-300"><input type="checkbox" checked={editForm.allowHostCerts} onChange={(e) => setEditForm({ ...editForm, allowHostCerts: e.target.checked })} className="w-4 h-4 rounded" />Allow Host Certs</label>
                        </div>
                        <div><label className={labelClass}>Default Extensions</label><MultiToggle options={SSH_EXTENSION_OPTIONS} selected={editForm.defaultExtensions} onChange={(next) => setEditForm({ ...editForm, defaultExtensions: next })} /></div>
                    </div>
                </DetailSection>
            ) : (<>
                <DetailSection title="SSH Signing Profile">
                    <DetailField label="ID" value={p.id} mono />
                    <DetailField label="Name" value={p.name} />
                    <DetailField label="Description" value={p.description} />
                    <DetailField label="SSH CA Key" value={caKeyName(p.sshCaKeyId)} />
                    <DetailField label="Max Validity Hours" value={String(p.maxValidityHours)} />
                    <DetailField label="Allow User Certs" value={p.allowUserCerts ? 'Yes' : 'No'} />
                    <DetailField label="Allow Host Certs" value={p.allowHostCerts ? 'Yes' : 'No'} />
                    <DetailField label="Force Command" value={p.forceCommand || 'None'} />
                    <div className="py-1"><span className="text-xs text-gray-600 dark:text-gray-400">Source Address Restrictions</span><BadgeList items={p.sourceAddressRestrictions} /></div>
                    <div className="py-1"><span className="text-xs text-gray-600 dark:text-gray-400">Default Extensions</span><BadgeList items={p.defaultExtensions} /></div>
                    {p.createdAt && <DetailField label="Created" value={new Date(p.createdAt).toLocaleString()} />}
                </DetailSection>

                <ConfirmModal
                    isOpen={confirmDelete}
                    title="Delete SSH Signing Profile"
                    message={`Delete SSH signing profile "${p.name}"? This cannot be undone.`}
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

export default SshSigningProfileDetail;
