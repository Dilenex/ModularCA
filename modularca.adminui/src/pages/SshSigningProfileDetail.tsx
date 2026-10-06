import React, { useEffect, useState } from 'react';
import type { NoticeInput } from '@shared/notifications/notice';
import { InlineNotice } from '@shared/components/InlineNotice';
import { errorNotice } from '@shared-auth/api/notices';
import { useParams, useNavigate } from 'react-router-dom';
import { apiGet, apiPostWithMfa, apiPutWithMfa, apiDeleteWithMfa } from '../api/client';
import { useStepUp } from '../components/StepUpMfaContext';
import { useToast } from '@shared/context/ToastContext';
import { Tag } from '@shared/components/cards/StatusBadge';
import { DetailField } from '@shared/components/cards/DetailField';
import ConfirmModal from '../components/ConfirmModal';
import { DetailPage, DetailSection } from '../components/DetailPage';
import { BadgeList, SubmitBlockedHint } from './profileHelpers';
import { StepUpOps } from '@shared/generated';
import { SshSigningProfileForm } from './profiles/SshSigningProfileForm';
import { emptyForm, formFromProfile, formToCreateBody, formToUpdateBody, validate } from './profiles/sshSigningProfile';
import { PROFILE_TYPES, profileDetailPath } from './profiles/profileRoutes';
import { actionButtonDanger } from '@shared/components/actionButtons';

const SSH_SIGNING_TAB = PROFILE_TYPES['ssh-signing'].listPath;

/// <summary>
/// Detail page for a single SSH signing profile (a tab on Profile Management), and with
/// <c>isNew</c> the page that creates one. View shows the bound CA key, validity, allow flags and
/// extensions; edit and create share SshSigningProfileForm. Both create and update need step-up MFA.
/// </summary>
const SshSigningProfileDetail: React.FC<{ isNew?: boolean }> = ({ isNew = false }) => {
    const { id } = useParams<{ id: string }>();
    const navigate = useNavigate();
    const { requireStepUp } = useStepUp();
    const { showToast } = useToast();

    const [profile, setProfile] = useState<any | null>(null);
    const [caKeys, setCaKeys] = useState<any[]>([]);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState<NoticeInput | null>(null);
    const [refresh, setRefresh] = useState(0);
    const [confirmDelete, setConfirmDelete] = useState(false);
    const [deleting, setDeleting] = useState(false);

    const [editForm, setEditForm] = useState(emptyForm);
    const [initialForm, setInitialForm] = useState(emptyForm);

    useEffect(() => {
        let cancelled = false;
        setLoading(true);
        setError(null);
        Promise.all([
            isNew ? Promise.resolve([]) : apiGet<any>('/api/v1/admin/ssh/profiles/signing'),
            apiGet<any>('/api/v1/admin/ssh/ca-keys').catch(() => []),
        ]).then(([data, keyData]) => {
            if (cancelled) return;
            const list = Array.isArray(data) ? data : [];
            const p = isNew ? null : list.find((x: any) => x.id === id) || null;
            setProfile(p);
            setCaKeys(Array.isArray(keyData) ? keyData : []);
            if (p) {
                const seeded = formFromProfile(p);
                setEditForm(seeded);
                setInitialForm(seeded);
            }
            setLoading(false);
        }).catch((err) => { if (!cancelled) { setError(errorNotice(err, 'Failed to load SSH signing profile')); setLoading(false); } });
        return () => { cancelled = true; };
    }, [id, refresh, isNew]);

    const caKeyName = (kid: string) => caKeys.find((k) => k.id === kid)?.name || kid;

    const mode = isNew ? 'create' : 'edit';
    const dirty = JSON.stringify(editForm) !== JSON.stringify(initialForm);
    const blockedReasons = validate(editForm, mode);

    const handleSave = async () => {
        try {
            if (isNew) {
                const created = await apiPostWithMfa<any>('/api/v1/admin/ssh/profiles/signing', formToCreateBody(editForm), requireStepUp, StepUpOps.CreateSshProfile);
                showToast('success', 'SSH signing profile created');
                navigate(created?.id ? profileDetailPath('ssh-signing', created.id) : SSH_SIGNING_TAB, { replace: true });
                return;
            }
            await apiPutWithMfa(`/api/v1/admin/ssh/profiles/signing/${id}`, formToUpdateBody(editForm), requireStepUp, StepUpOps.UpdateSshProfile, id!);
            showToast('success', 'SSH signing profile updated');
            setRefresh((r) => r + 1);
        } catch (err: any) {
            if (err.message !== 'Step-up MFA cancelled') showToast('error', err.message || (isNew ? 'Failed to create SSH signing profile' : 'Failed to update SSH signing profile'));
            throw err;
        }
    };

    const handleCancel = () => {
        if (isNew) navigate(SSH_SIGNING_TAB);
        else setEditForm(initialForm);
    };

    const doDelete = async () => {
        setDeleting(true);
        try {
            await apiDeleteWithMfa(`/api/v1/admin/ssh/profiles/signing/${id}`, requireStepUp, StepUpOps.DeleteSshProfile, id);
            showToast('success', 'SSH signing profile deleted');
            navigate(SSH_SIGNING_TAB);
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
            <p className="text-sm text-ink-muted">SSH signing profile not found.</p>
            <button onClick={() => navigate(SSH_SIGNING_TAB)} className="px-3 py-1.5 text-sm bg-sunken rounded">Back to SSH Signing Profiles</button>
        </div>
    );

    const p = profile ?? {};
    const title = isNew ? 'New SSH signing profile' : p.name;

    return (
        <DetailPage
            breadcrumbs={[{ label: 'Profile Management', to: SSH_SIGNING_TAB }, { label: 'SSH Signing Profiles', to: SSH_SIGNING_TAB }, { label: title }]}
            title={title}
            status={isNew ? undefined : <span className="flex items-center gap-2">{p.allowUserCerts && <Tag label="User" />}{p.allowHostCerts && <Tag label="Host" />}</span>}
            subtitle={isNew ? undefined : caKeyName(p.sshCaKeyId)}
            backTo={SSH_SIGNING_TAB}
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
                <DetailSection title={isNew ? 'New SSH Signing Profile' : 'Edit SSH Signing Profile'}>
                    <SubmitBlockedHint reasons={blockedReasons} />
                    <SshSigningProfileForm value={editForm} onChange={setEditForm} mode={mode} caKeys={caKeys} />
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
                    <div className="py-1"><span className="text-xs text-ink-muted">Source Address Restrictions</span><BadgeList items={p.sourceAddressRestrictions} /></div>
                    <div className="py-1"><span className="text-xs text-ink-muted">Default Extensions</span><BadgeList items={p.defaultExtensions} /></div>
                    {p.createdAt && <DetailField label="Created" value={new Date(p.createdAt).toLocaleString()} />}
                </DetailSection>

                <ConfirmModal
                    isOpen={confirmDelete}
                    title="Delete SSH Signing Profile"
                    message={`Delete SSH signing profile "${p.name}"? This cannot be undone.`}
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

export default SshSigningProfileDetail;
