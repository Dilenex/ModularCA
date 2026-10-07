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
import { parseJsonArray, caRowId, SubmitBlockedHint } from './profileHelpers';
import { StepUpOps } from '@shared/generated';
import { SshRequestProfileForm } from './profiles/SshRequestProfileForm';
import { emptyForm, formFromProfile, formToCreateBody, formToUpdateBody, validate } from './profiles/sshRequestProfile';
import { PROFILE_TYPES, profileDetailPath } from './profiles/profileRoutes';
import { actionButtonDanger } from '@shared/components/actionButtons';

const SSH_REQUEST_TAB = PROFILE_TYPES['ssh-request'].listPath;

/// <summary>
/// Detail page for a single SSH request profile (a tab on Profile Management), and with
/// <c>isNew</c> the page that creates one. View shows the allowed signing/cert profiles, approval
/// requirement and CA scope; edit and create share SshRequestProfileForm. Both create and update
/// need step-up MFA.
/// </summary>
const SshRequestProfileDetail: React.FC<{ isNew?: boolean }> = ({ isNew = false }) => {
    const { id } = useParams<{ id: string }>();
    const navigate = useNavigate();
    const { requireStepUp } = useStepUp();
    const { showToast } = useToast();

    const [profile, setProfile] = useState<any | null>(null);
    const [signingProfiles, setSigningProfiles] = useState<any[]>([]);
    const [certProfiles, setCertProfiles] = useState<any[]>([]);
    const [authorities, setAuthorities] = useState<any[]>([]);
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
            isNew ? Promise.resolve([]) : apiGet<any>('/api/v1/admin/ssh/profiles/request'),
            apiGet<any>('/api/v1/admin/ssh/profiles/signing').catch(() => []),
            apiGet<any>('/api/v1/admin/ssh/profiles/cert').catch(() => []),
            apiGet<any>('/api/v1/admin/authorities').catch(() => []),
        ]).then(([data, spData, cpData, authData]) => {
            if (cancelled) return;
            const list = Array.isArray(data) ? data : [];
            const p = isNew ? null : list.find((x: any) => x.id === id) || null;
            setProfile(p);
            setSigningProfiles(Array.isArray(spData) ? spData : []);
            setCertProfiles(Array.isArray(cpData) ? cpData : []);
            setAuthorities(Array.isArray(authData) ? authData : (authData.items || authData.authorities || []));
            if (p) {
                const seeded = formFromProfile(p);
                setEditForm(seeded);
                setInitialForm(seeded);
            }
            setLoading(false);
        }).catch((err) => { if (!cancelled) { setError(errorNotice(err, 'Failed to load SSH request profile')); setLoading(false); } });
        return () => { cancelled = true; };
    }, [id, refresh, isNew]);

    const resolveNames = (idsJson: any, items: any[]) => parseJsonArray(idsJson).map((x) => items.find((i) => i.id === x)?.name || x);
    const caName = (caId: string) => {
        const a = authorities.find((x) => caRowId(x) === caId);
        return a ? (a.name || a.commonName || caId) : caId;
    };

    const mode = isNew ? 'create' : 'edit';
    const dirty = JSON.stringify(editForm) !== JSON.stringify(initialForm);
    const blockedReasons = validate(editForm, mode);

    const handleSave = async () => {
        try {
            if (isNew) {
                const created = await apiPostWithMfa<any>('/api/v1/admin/ssh/profiles/request', formToCreateBody(editForm), requireStepUp, StepUpOps.CreateSshProfile);
                showToast('success', 'SSH request profile created');
                navigate(created?.id ? profileDetailPath('ssh-request', created.id) : SSH_REQUEST_TAB, { replace: true });
                return;
            }
            await apiPutWithMfa(`/api/v1/admin/ssh/profiles/request/${id}`, formToUpdateBody(editForm), requireStepUp, StepUpOps.UpdateSshProfile, id!);
            showToast('success', 'SSH request profile updated');
            setRefresh((r) => r + 1);
        } catch (err: any) {
            if (err.message !== 'Step-up MFA cancelled') showToast('error', err.message || (isNew ? 'Failed to create SSH request profile' : 'Failed to update SSH request profile'));
            throw err;
        }
    };

    const handleCancel = () => {
        if (isNew) navigate(SSH_REQUEST_TAB);
        else setEditForm(initialForm);
    };

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

    if (loading) return <div className="p-6 text-sm text-ink-muted">Loading…</div>;
    if (error) return <InlineNotice notice={error} />;
    if (!isNew && !profile) return (
        <div className="p-6 space-y-3">
            <p className="text-sm text-ink-muted">SSH request profile not found.</p>
            <button onClick={() => navigate(SSH_REQUEST_TAB)} className="px-3 py-1.5 text-sm bg-sunken rounded">Back to SSH Request Profiles</button>
        </div>
    );

    const p = profile ?? {};
    const title = isNew ? 'New SSH request profile' : p.name;

    return (
        <DetailPage
            breadcrumbs={[{ label: 'Profile Management', to: SSH_REQUEST_TAB }, { label: 'SSH Request Profiles', to: SSH_REQUEST_TAB }, { label: title }]}
            title={title}
            status={!isNew && p.requireApproval ? <Tag label="Approval" /> : undefined}
            subtitle={isNew ? undefined : `${p.maxValidityHours}h max`}
            backTo={SSH_REQUEST_TAB}
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
                <DetailSection title={isNew ? 'New SSH Request Profile' : 'Edit SSH Request Profile'}>
                    <SubmitBlockedHint reasons={blockedReasons} />
                    <SshRequestProfileForm value={editForm} onChange={setEditForm} mode={mode}
                        signingProfiles={signingProfiles} certProfiles={certProfiles} authorities={authorities} />
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
                        <span className="text-xs text-ink-muted">Allowed Signing Profiles</span>
                        <div className="flex flex-wrap gap-1 mt-1">
                            {resolveNames(p.allowedSshSigningProfileIds, signingProfiles).map((name, i) => <span key={i} className="px-2 py-0.5 text-xs rounded bg-accent-soft text-accent-ink border border-accent/40">{name}</span>)}
                            {resolveNames(p.allowedSshSigningProfileIds, signingProfiles).length === 0 && <span className="text-ink-muted text-xs">Any</span>}
                        </div>
                    </div>
                    <div className="py-1">
                        <span className="text-xs text-ink-muted">Allowed Cert Profiles</span>
                        <div className="flex flex-wrap gap-1 mt-1">
                            {resolveNames(p.allowedSshCertProfileIds, certProfiles).map((name, i) => <span key={i} className="px-2 py-0.5 text-xs rounded bg-accent-soft text-accent-ink border border-accent/40">{name}</span>)}
                            {resolveNames(p.allowedSshCertProfileIds, certProfiles).length === 0 && <span className="text-ink-muted text-xs">Any</span>}
                        </div>
                    </div>
                    {p.createdAt && <DetailField label="Created" value={new Date(p.createdAt).toLocaleString()} />}
                </DetailSection>

                <ConfirmModal
                    isOpen={confirmDelete}
                    title="Delete SSH Request Profile"
                    message={`Delete SSH request profile "${p.name}"? This cannot be undone.`}
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

export default SshRequestProfileDetail;
