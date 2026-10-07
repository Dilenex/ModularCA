import React, { useEffect, useState } from 'react';
import type { NoticeInput } from '@shared/notifications/notice';
import { InlineNotice } from '@shared/components/InlineNotice';
import { errorNotice } from '@shared-auth/api/notices';
import { useParams, useNavigate } from 'react-router-dom';
import { apiGet, apiPutWithMfa, apiDeleteWithMfa, apiPostWithMfa } from '../api/client';
import { useStepUp } from '../components/StepUpMfaContext';
import { useToast } from '@shared/context/ToastContext';
import { Tag } from '@shared/components/cards/StatusBadge';
import { DetailField } from '@shared/components/cards/DetailField';
import ConfirmModal from '../components/ConfirmModal';
import { DetailPage, DetailSection } from '../components/DetailPage';
import { Capabilities, StepUpOps } from '@shared/generated';
import { useAuth } from '../context/AuthContext';
import { isUnboundSigningProfile, mayChangeProfile, INSTANCE_WIDE_READ_ONLY } from './profiles/instanceWide';
import { parseListField, CeilingList, canonicalizeUsages, SubmitBlockedHint } from './profileHelpers';
import { AlgorithmSummary } from './profiles/KeyPolicyEditor';
import { useEkuCatalog } from '../hooks/useOidCatalog';
import { SigningProfileForm } from './profiles/SigningProfileForm';
import { CertificatePoliciesView } from './profiles/CertificatePoliciesTable';
import { NameConstraintsView } from '@shared/components/NameConstraintsEditor';
import { emptyForm, formFromProfile, formToCreateBody, formToUpdateBody, validate } from './profiles/signingProfile';
import { PROFILE_TYPES, profileDetailPath } from './profiles/profileRoutes';
import { actionButtonDanger } from '@shared/components/actionButtons';

const SIGNING_TAB = PROFILE_TYPES.signing.listPath;
const spId = (p: any): string => p.id || p.signingProfileId;

/// <summary>
/// Detail page for a single signing profile (a tab on Profile Management), and with <c>isNew</c>
/// the page that creates one. View shows the allowed algorithms/EKUs, name constraints, policy
/// config and allowed cert profiles; edit and create share SigningProfileForm. The allowed cert
/// profiles travel in the same body on both POST and PUT, so either is a single call.
/// </summary>
const SigningProfileDetail: React.FC<{ isNew?: boolean }> = ({ isNew = false }) => {
    // Extended key usages come from the OID catalog, not a hardcoded list — see useEkuCatalog.
    const ekuCatalog = useEkuCatalog();
    const { id } = useParams<{ id: string }>();
    const navigate = useNavigate();
    const { requireStepUp } = useStepUp();
    const { can } = useAuth();
    const { showToast } = useToast();

    const [profile, setProfile] = useState<any | null>(null);
    // Every signing profile, kept for the Inherits From select.
    const [profiles, setProfiles] = useState<any[]>([]);
    const [authorities, setAuthorities] = useState<any[]>([]);
    const [certProfiles, setCertProfiles] = useState<any[]>([]);
    const [allowedCpIds, setAllowedCpIds] = useState<string[]>([]);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState<NoticeInput | null>(null);
    const [refresh, setRefresh] = useState(0);

    const [confirmDelete, setConfirmDelete] = useState(false);
    const [deleting, setDeleting] = useState(false);

    const [editForm, setEditForm] = useState(emptyForm);
    // Snapshot of the loaded values — drives dirty-detection and Cancel-reset for the unified save.
    const [initialForm, setInitialForm] = useState(emptyForm);

    useEffect(() => {
        let cancelled = false;
        setLoading(true);
        setError(null);
        Promise.all([
            apiGet<any>('/api/v1/admin/signing-profiles'),
            apiGet<any>('/api/v1/admin/authorities').catch(() => []),
            apiGet<any>('/api/v1/admin/cert-profiles').catch(() => []),
            isNew ? Promise.resolve([]) : apiGet<any>(`/api/v1/admin/signing-profiles/${id}/allowed-cert-profiles`).catch(() => []),
        ]).then(([data, authData, cpData, allowedData]) => {
            if (cancelled) return;
            const list = Array.isArray(data) ? data : (data.items || data.profiles || []);
            setProfiles(list);
            const p = isNew ? null : list.find((x: any) => spId(x) === id) || null;
            setProfile(p);
            setAuthorities(Array.isArray(authData) ? authData : (authData.items || authData.authorities || []));
            setCertProfiles(Array.isArray(cpData) ? cpData : (cpData.items || cpData.profiles || []));
            const allowed = (Array.isArray(allowedData) ? allowedData : []).map((x: any) => x.id || x.certProfileId || x);
            setAllowedCpIds(allowed);
            if (p) {
                const seeded = formFromProfile(p, ekuCatalog, allowed);
                setEditForm(seeded);
                setInitialForm(seeded);
            }
            setLoading(false);
        }).catch((err) => { if (!cancelled) { setError(errorNotice(err, 'Failed to load signing profile')); setLoading(false); } });
        return () => { cancelled = true; };
    }, [id, refresh, isNew]); // eslint-disable-line react-hooks/exhaustive-deps

    const authorityName = (issuerId: string | undefined) => {
        if (!issuerId) return undefined;
        const a = authorities.find((x) => x.certificateId === issuerId || x.id === issuerId);
        return a ? (a.name || a.commonName || issuerId) : issuerId;
    };
    const cpName = (cpId: string) => {
        const cp = certProfiles.find((c) => (c.id || c.certProfileId) === cpId);
        return cp ? cp.name : cpId;
    };

    const mode = isNew ? 'create' : 'edit';
    const dirty = JSON.stringify(editForm) !== JSON.stringify(initialForm);
    const blockedReasons = validate(editForm, mode);

    const handleCancel = () => {
        if (isNew) navigate(SIGNING_TAB);
        else setEditForm(initialForm);
    };

    const handleSave = async () => {
        try {
            if (isNew) {
                const created = await apiPostWithMfa<any>('/api/v1/admin/signing-profiles', formToCreateBody(editForm), requireStepUp, StepUpOps.CreateSigningProfile);
                showToast('success', 'Signing profile created');
                const newId = created ? spId(created) : undefined;
                navigate(newId ? profileDetailPath('signing', newId) : SIGNING_TAB, { replace: true });
                return;
            }
            await apiPutWithMfa(`/api/v1/admin/signing-profiles/${id}`, formToUpdateBody(editForm), requireStepUp, StepUpOps.UpdateSigningProfile, id!);
            showToast('success', 'Signing profile updated');
            setRefresh((r) => r + 1);
        } catch (err: any) {
            if (err.message !== 'Step-up MFA cancelled') showToast('error', err.message || (isNew ? 'Failed to create signing profile' : 'Failed to update signing profile'));
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

    if (loading) return <div className="p-6 text-sm text-ink-muted">Loading…</div>;
    if (error) return <InlineNotice notice={error} />;
    if (!isNew && !profile) return (
        <div className="p-6 space-y-3">
            <p className="text-sm text-ink-muted">Signing profile not found.</p>
            <button onClick={() => navigate(SIGNING_TAB)} className="px-3 py-1.5 text-sm bg-sunken rounded">Back to Signing Profiles</button>
        </div>
    );

    const p = profile ?? {};
    // An instance-wide profile is read-only without CaManage at system scope, as the server requires.
    const readOnly = !isNew && !mayChangeProfile(isUnboundSigningProfile(p), can(Capabilities.CaManage));
    const title = isNew ? 'New signing profile' : p.name;

    return (
        <DetailPage
            breadcrumbs={[{ label: 'Profile Management', to: SIGNING_TAB }, { label: 'Signing Profiles', to: SIGNING_TAB }, { label: title }]}
            title={title}
            status={!isNew && p.isDefault ? <Tag label="Default" tone="accent" /> : undefined}
            subtitle={isNew ? undefined : <>{authorityName(p.issuerId)}{readOnly && <span className="block text-xs">{INSTANCE_WIDE_READ_ONLY}</span>}</>}
            backTo={SIGNING_TAB}
            editable={!readOnly}
            initialMode={isNew ? 'edit' : 'view'}
            modeToggle={!isNew}
            saveLabel={isNew ? 'Create' : 'Save'}
            onSave={handleSave}
            onCancel={handleCancel}
            saveDisabled={blockedReasons.length > 0 || (!isNew && !dirty)}
            actions={isNew || readOnly ? undefined : <button onClick={() => setConfirmDelete(true)} disabled={deleting} className={actionButtonDanger}>Delete</button>}
        >
            {(viewMode) => viewMode === 'edit' ? (
                <DetailSection title={isNew ? 'New Signing Profile' : 'Edit Signing Profile'}>
                    <SubmitBlockedHint reasons={blockedReasons} />
                    <SigningProfileForm value={editForm} onChange={setEditForm} mode={mode}
                        profileId={isNew ? undefined : id} parentProfiles={profiles} authorities={authorities}
                        certProfiles={certProfiles} ekuCatalog={ekuCatalog} />
                </DetailSection>
            ) : (<>
                <DetailSection title="Signing Profile">
                    <DetailField label="Name" value={p.name} />
                    <DetailField label="Description" value={p.description} />
                    <DetailField label="Default" value={p.isDefault ? 'Yes' : 'No'} />
                    <DetailField label="Issuer" value={authorityName(p.issuerId)} />
                    <div className="py-1"><span className="text-xs text-ink-muted">Allowed Algorithms</span><AlgorithmSummary items={p.allowedAlgorithms} /></div>
                    <div className="py-1"><span className="text-xs text-ink-muted">Allowed EKUs</span><CeilingList noun="EKU" raw={parseListField(p.allowedEKUs ?? p.allowedEkus)} items={canonicalizeUsages(parseListField(p.allowedEKUs ?? p.allowedEkus), ekuCatalog.options, ekuCatalog.aliases).map(ekuCatalog.label)} /></div>
                    <DetailField label="Max Path Length" value={p.maxPathLength != null ? String(p.maxPathLength) : undefined} />
                    <div className="py-1">
                        <span className="block text-xs text-ink-muted mb-1">Name Constraints</span>
                        <NameConstraintsView permitted={p.nameConstraintsPermitted} excluded={p.nameConstraintsExcluded} />
                    </div>
                    <div className="py-1">
                        <span className="block text-xs text-ink-muted mb-1">Certificate Policies</span>
                        <CertificatePoliciesView policyOids={p.policyOids} policyQualifiersJson={p.policyQualifiersJson} />
                    </div>
                    <DetailField label="Inhibit Any Policy" value={p.inhibitAnyPolicy ? 'Yes' : 'No'} />
                    <DetailField label="EKU Extension Critical" value={p.extendedKeyUsageCritical ? 'Yes' : 'No'} />
                    <div className="py-1">
                        <span className="text-xs text-ink-muted">Allowed Cert Profiles</span>
                        {allowedCpIds.length > 0 ? (
                            <div className="flex flex-wrap gap-1 mt-1">
                                {allowedCpIds.map((cid, i) => <span key={i} className="px-2 py-0.5 text-xs rounded bg-accent-soft text-accent-ink border border-accent/40">{cpName(cid)}</span>)}
                            </div>
                        ) : <span className="text-xs text-ink-muted ml-2">None</span>}
                    </div>
                </DetailSection>

                <ConfirmModal
                    isOpen={confirmDelete}
                    title="Delete Signing Profile"
                    message={`Delete signing profile "${p.name}"? This cannot be undone.`}
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

export default SigningProfileDetail;
