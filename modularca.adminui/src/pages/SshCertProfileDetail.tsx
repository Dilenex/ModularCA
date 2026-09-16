import React, { useEffect, useState } from 'react';
import type { NoticeInput } from '@shared/notifications/notice';
import { InlineNotice } from '@shared/components/InlineNotice';
import { errorNotice } from '@shared-auth/api/notices';
import { useParams, useNavigate } from 'react-router-dom';
import { apiGet, apiPutWithMfa, apiDelete, apiDeleteWithMfa } from '../api/client';
import { useStepUp } from '../components/StepUpMfaContext';
import { useToast } from '@shared/context/ToastContext';
import { DetailField } from '@shared/components/cards/DetailField';
import ConfirmModal from '../components/ConfirmModal';
import { DetailPage, DetailSection } from '../components/DetailPage';
import { SSH_EXTENSION_OPTIONS, parseJsonArray, BadgeList, CeilingList } from './profileHelpers';
import { inputClass, labelClass, FieldHint } from '@shared/components/forms';
import { StepUpOps } from '@shared/generated';

const SSH_CERT_TAB = `/profiles?tab=${encodeURIComponent('SSH Cert')}`;

/**
 * What each OpenSSH certificate extension permits, shown as hover text on the toggle chips. The
 * `permit-*` names are the extensions OpenSSH actually writes into a certificate; the `no-*` names
 * mirror ssh-keygen's -O flags and mean "issue without the matching permit-* extension".
 */
const SSH_EXTENSION_HELP: Record<string, string> = {
    'permit-pty': 'Allows the session to allocate a pseudo-terminal. Without it the user gets no interactive shell, only non-interactive commands.',
    'permit-port-forwarding': 'Allows -L, -R and -D tunnels, so the certificate holder can reach other hosts through the server.',
    'permit-agent-forwarding': 'Allows the user\'s ssh-agent to be forwarded to the server, where root could use their keys while the session lasts.',
    'permit-X11-forwarding': 'Allows X11 display forwarding from the server back to the client.',
    'permit-user-rc': 'Allows ~/.ssh/rc on the server to run at login, a common persistence spot.',
    'no-touch-required': 'For FIDO/U2F security-key certificates: the server does not demand a physical touch on each authentication.',
    'no-pty': 'Issue without permit-pty: the certificate cannot open an interactive shell.',
    'no-port-forwarding': 'Issue without permit-port-forwarding: no tunnels through the server.',
    'no-agent-forwarding': 'Issue without permit-agent-forwarding: the user\'s agent is never exposed to the server.',
    'no-X11-forwarding': 'Issue without permit-X11-forwarding.',
    'no-user-rc': 'Issue without permit-user-rc: ~/.ssh/rc is not executed at login.',
};

/**
 * The MultiToggle from profileHelpers with hover help per chip. Allowed and Required share one
 * option list, so a chip that is required but not allowed is highlighted as a conflict.
 */
const ExtensionToggle: React.FC<{
    options: readonly string[];
    selected: string[];
    conflicts?: string[];
    onChange: (next: string[]) => void;
}> = ({ options, selected, conflicts = [], onChange }) => (
    <div className="flex flex-wrap gap-2">
        {options.map((opt) => {
            const active = selected.includes(opt);
            const conflict = conflicts.includes(opt);
            const help = SSH_EXTENSION_HELP[opt] || `OpenSSH extension ${opt}.`;
            return (
                <button key={opt} type="button"
                    title={conflict ? `${help} Required but not allowed: this profile can never issue until it is allowed too.` : help}
                    aria-pressed={active}
                    onClick={() => onChange(active ? selected.filter((v) => v !== opt) : [...selected, opt])}
                    className={`px-2 py-1 text-xs rounded border transition-colors ${conflict
                        ? 'bg-amber-50 dark:bg-amber-900/40 text-amber-800 dark:text-amber-300 border-amber-400 dark:border-amber-600'
                        : active ? 'bg-blue-50 dark:bg-blue-900/50 text-blue-800 dark:text-blue-300 border-blue-300 dark:border-blue-700' : 'bg-gray-50 dark:bg-gray-900 text-gray-600 dark:text-gray-400 border-gray-300 dark:border-gray-700 hover:border-gray-500'}`}>
                    {opt}
                </button>
            );
        })}
    </div>
);

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
    const [error, setError] = useState<NoticeInput | null>(null);
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
    // Required must be a subset of Allowed; anything required-but-not-allowed can never be issued.
    const requiredNotAllowed = editForm.requiredExtensions.filter((x) => !editForm.allowedExtensions.includes(x));

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
            .catch((err) => { if (!cancelled) { setError(errorNotice(err, 'Failed to load SSH cert profile')); setLoading(false); } });
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
    if (error) return <InlineNotice notice={error} />;
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
            saveDisabled={!dirty || !editForm.name || requiredNotAllowed.length > 0}
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
                        <div>
                            <label className={labelClass}>Allowed Extensions</label>
                            <ExtensionToggle options={SSH_EXTENSION_OPTIONS} selected={editForm.allowedExtensions} onChange={(next) => setEditForm({ ...editForm, allowedExtensions: next })} />
                            <FieldHint>The ceiling: a certificate from this profile may carry these extensions and no others. Hover a chip for what it permits.</FieldHint>
                        </div>
                        <div>
                            <label className={labelClass}>Required Extensions</label>
                            <ExtensionToggle options={SSH_EXTENSION_OPTIONS} selected={editForm.requiredExtensions} conflicts={requiredNotAllowed} onChange={(next) => setEditForm({ ...editForm, requiredExtensions: next })} />
                            <FieldHint tone={requiredNotAllowed.length > 0 ? 'warn' : 'muted'}>
                                Required must be a subset of Allowed. An extension required here but not allowed produces a profile that can never issue.
                                {requiredNotAllowed.length > 0 && <> Not allowed: <span className="font-mono">{requiredNotAllowed.join(', ')}</span>. Allow them above or unrequire them before saving.</>}
                            </FieldHint>
                        </div>
                    </div>
                </DetailSection>
            ) : (<>
                <DetailSection title="SSH Cert Profile">
                    <DetailField label="ID" value={p.id} mono />
                    <DetailField label="Name" value={p.name} />
                    <DetailField label="Description" value={p.description} />
                    <DetailField label="Max Principals" value={String(p.maxPrincipals)} />
                    <DetailField label="Max Validity Hours" value={String(p.maxValidityHours)} />
                    <div className="py-1"><span className="text-xs text-gray-600 dark:text-gray-400">Allowed Principal Patterns</span><CeilingList items={p.allowedPrincipalPatterns} noun="principal" /></div>
                    <div className="py-1"><span className="text-xs text-gray-600 dark:text-gray-400">Allowed Extensions</span><CeilingList items={p.allowedExtensions} noun="extension" /></div>
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
