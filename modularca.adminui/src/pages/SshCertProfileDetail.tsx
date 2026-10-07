import React, { useEffect, useState } from 'react';
import type { NoticeInput } from '@shared/notifications/notice';
import { InlineNotice } from '@shared/components/InlineNotice';
import { errorNotice } from '@shared-auth/api/notices';
import { useParams, useNavigate } from 'react-router-dom';
import { apiGet, apiPostWithMfa, apiPutWithMfa, apiDeleteWithMfa } from '../api/client';
import { useStepUp } from '../components/StepUpMfaContext';
import { useToast } from '@shared/context/ToastContext';
import { DetailField } from '@shared/components/cards/DetailField';
import ConfirmModal from '../components/ConfirmModal';
import { DetailPage, DetailSection } from '../components/DetailPage';
import { BadgeList, CeilingList, SubmitBlockedHint } from './profileHelpers';
import { StepUpOps } from '@shared/generated';
import { SshCertProfileForm } from './profiles/SshCertProfileForm';
import { emptyForm, formFromProfile, formToCreateBody, formToUpdateBody, validate } from './profiles/sshCertProfile';
import { PROFILE_TYPES, profileDetailPath } from './profiles/profileRoutes';
import { actionButtonDanger } from '@shared/components/actionButtons';

const SSH_CERT_TAB = PROFILE_TYPES['ssh-cert'].listPath;

/// <summary>
/// Detail page for a single SSH cert profile (a tab on Profile Management), and with <c>isNew</c>
/// the page that creates one. View shows the login name patterns, limits and allowed/required
/// extensions; edit and create share SshCertProfileForm. Both create and update need step-up MFA.
/// </summary>
const SshCertProfileDetail: React.FC<{ isNew?: boolean }> = ({ isNew = false }) => {
    const { id } = useParams<{ id: string }>();
    const navigate = useNavigate();
    const { requireStepUp } = useStepUp();
    const { showToast } = useToast();

    const [profile, setProfile] = useState<any | null>(null);
    const [loading, setLoading] = useState(!isNew);
    const [error, setError] = useState<NoticeInput | null>(null);
    const [refresh, setRefresh] = useState(0);
    const [confirmDelete, setConfirmDelete] = useState(false);
    const [deleting, setDeleting] = useState(false);

    const [editForm, setEditForm] = useState(emptyForm);
    const [initialForm, setInitialForm] = useState(emptyForm);

    const mode = isNew ? 'create' : 'edit';
    const dirty = JSON.stringify(editForm) !== JSON.stringify(initialForm);
    const blockedReasons = validate(editForm, mode);

    useEffect(() => {
        if (isNew) return;
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
                    const seeded = formFromProfile(p);
                    setEditForm(seeded);
                    setInitialForm(seeded);
                }
                setLoading(false);
            })
            .catch((err) => { if (!cancelled) { setError(errorNotice(err, 'Failed to load SSH cert profile')); setLoading(false); } });
        return () => { cancelled = true; };
    }, [id, refresh, isNew]);

    const handleSave = async () => {
        try {
            if (isNew) {
                const created = await apiPostWithMfa<any>('/api/v1/admin/ssh/profiles/cert', formToCreateBody(editForm), requireStepUp, StepUpOps.CreateSshProfile);
                showToast('success', 'SSH cert profile created');
                navigate(created?.id ? profileDetailPath('ssh-cert', created.id) : SSH_CERT_TAB, { replace: true });
                return;
            }
            await apiPutWithMfa(`/api/v1/admin/ssh/profiles/cert/${id}`, formToUpdateBody(editForm), requireStepUp, StepUpOps.UpdateSshProfile, id!);
            showToast('success', 'SSH cert profile updated');
            setRefresh((r) => r + 1);
        } catch (err: any) {
            if (err.message !== 'Step-up MFA cancelled') showToast('error', err.message || (isNew ? 'Failed to create SSH cert profile' : 'Failed to update SSH cert profile'));
            throw err;
        }
    };

    const handleCancel = () => {
        if (isNew) navigate(SSH_CERT_TAB);
        else setEditForm(initialForm);
    };

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

    if (loading) return <div className="p-6 text-sm text-ink-muted">Loading…</div>;
    if (error) return <InlineNotice notice={error} />;
    if (!isNew && !profile) return (
        <div className="p-6 space-y-3">
            <p className="text-sm text-ink-muted">SSH cert profile not found.</p>
            <button onClick={() => navigate(SSH_CERT_TAB)} className="px-3 py-1.5 text-sm bg-sunken rounded">Back to SSH Cert Profiles</button>
        </div>
    );

    const p = profile ?? {};
    const title = isNew ? 'New SSH cert profile' : p.name;

    return (
        <DetailPage
            breadcrumbs={[{ label: 'Profile Management', to: SSH_CERT_TAB }, { label: 'SSH Cert Profiles', to: SSH_CERT_TAB }, { label: title }]}
            title={title}
            subtitle={isNew ? undefined : `Up to ${p.maxPrincipals} login names · ${p.maxValidityHours}h`}
            backTo={SSH_CERT_TAB}
            editable
            initialMode={isNew ? 'edit' : 'view'}
            modeToggle={!isNew}
            saveLabel={isNew ? 'Create' : 'Save'}
            onSave={handleSave}
            onCancel={handleCancel}
            saveDisabled={blockedReasons.length > 0 || (!isNew && !dirty)}
            actions={isNew ? undefined : <button onClick={() => setConfirmDelete(true)} disabled={deleting} className={actionButtonDanger}>Delete</button>}
        >
            {(viewMode) => viewMode === 'edit' ? (
                <DetailSection title={isNew ? 'New SSH Cert Profile' : 'Edit SSH Cert Profile'}>
                    <SubmitBlockedHint reasons={blockedReasons} />
                    <SshCertProfileForm value={editForm} onChange={setEditForm} mode={mode} />
                </DetailSection>
            ) : (<>
                <DetailSection title="SSH Cert Profile">
                    <DetailField label="ID" value={p.id} mono />
                    <DetailField label="Name" value={p.name} />
                    <DetailField label="Description" value={p.description} />
                    <DetailField label="Most login names" value={String(p.maxPrincipals)} />
                    <DetailField label="Max Validity Hours" value={String(p.maxValidityHours)} />
                    <div className="py-1"><span className="text-xs text-ink-muted">Login name patterns (the outer limit; who may use which name is set on the SSH CA key)</span><CeilingList items={p.allowedPrincipalPatterns} noun="login name" /></div>
                    <div className="py-1"><span className="text-xs text-ink-muted">Allowed Extensions</span><CeilingList items={p.allowedExtensions} noun="extension" /></div>
                    <div className="py-1"><span className="text-xs text-ink-muted">Required Extensions</span><BadgeList items={p.requiredExtensions} /></div>
                    {p.createdAt && <DetailField label="Created" value={new Date(p.createdAt).toLocaleString()} />}
                </DetailSection>

                <ConfirmModal
                    isOpen={confirmDelete}
                    title="Delete SSH Cert Profile"
                    message={`Delete SSH cert profile "${p.name}"? This cannot be undone.`}
                    confirmLabel="Delete"
                    tone="crit"
                    loading={deleting}
                    onConfirm={doDelete}
                    onCancel={() => setConfirmDelete(false)}
                />
            </>)}
        </DetailPage>
    );
};

export default SshCertProfileDetail;
