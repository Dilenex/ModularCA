import React, { useEffect, useState } from 'react';
import type { NoticeInput } from '@shared/notifications/notice';
import { InlineNotice } from '@shared/components/InlineNotice';
import { errorNotice } from '@shared-auth/api/notices';
import { useParams, useNavigate } from 'react-router-dom';
import { apiGet, apiPost, apiPutWithMfa, apiDeleteWithMfa, apiPostWithMfa } from '../api/client';
import { useStepUp } from '../components/StepUpMfaContext';
import { useToast } from '@shared/context/ToastContext';
import { DetailField } from '@shared/components/cards/DetailField';
import ConfirmModal from '../components/ConfirmModal';
import { DetailPage, DetailSection } from '../components/DetailPage';
import { Capabilities, StepUpOps } from '@shared/generated';
import { useAuth } from '../context/AuthContext';
import { isInstanceWideCertProfile, mayChangeProfile, INSTANCE_WIDE_READ_ONLY } from './profiles/instanceWide';
import { KEY_USAGE_OPTIONS, keyUsageLabel, canonicalizeUsages, parseListField, FieldSourceBadge, SourceBorderedField, SubmitBlockedHint } from './profileHelpers';
import { useEkuCatalog, useKeyUsageCatalog } from '../hooks/useOidCatalog';
import { CertProfileForm } from './profiles/CertProfileForm';
import { KeyPolicySummary } from './profiles/KeyPolicyEditor';
import { emptyForm, formFromProfile, formToCreateBody, formToUpdateBody, validate } from './profiles/certProfile';
import { PROFILE_TYPES, profileDetailPath } from './profiles/profileRoutes';
import { type CtLogChoice, ctLogChoicesFromResponse, ctLogDisplay, ctLogIdsFromStored } from './profiles/ctLogChoices';
import { actionButtonDanger } from '@shared/components/actionButtons';
import { periodText } from '@shared/periodText';
import { certProfileInUse } from './infrastructureProfiles';
import { CaScopeName } from '../components/CaScopeName';

const CERT_TAB = PROFILE_TYPES.cert.listPath;

const CT_TONE = { ok: 'bg-accent-soft text-accent-ink border-accent/40', muted: 'bg-sunken text-ink-muted border-line-strong', crit: 'bg-crit-soft text-crit border-crit/40' } as const;

/** A profile's stored CT log ids as log names; blank reads as every enabled log. */
const CtLogList: React.FC<{ stored: unknown; logs: CtLogChoice[] | null }> = ({ stored, logs }) => {
    const ids = ctLogIdsFromStored(stored);
    if (ids.length === 0) return <span className="text-xs text-ink ml-2">Every enabled log</span>;
    return (
        <div className="flex flex-wrap gap-1 mt-1">
            {ids.map((id) => {
                const d = ctLogDisplay(id, logs);
                return <span key={id} className={`px-2 py-0.5 text-xs rounded border ${CT_TONE[d.tone]} ${logs ? '' : 'font-mono'}`}>{d.text}</span>;
            })}
        </div>
    );
};
const cpId = (p: any): string => p.id || p.certProfileId;

/// <summary>
/// Detail page for a single certificate profile (a tab on Profile Management), and with
/// <c>isNew</c> the page that creates one. View shows usages/algorithm allow-lists and inheritance;
/// edit and create share CertProfileForm. Updates go through step-up MFA; the server does not ask
/// for it on create.
/// </summary>
const CertProfileDetail: React.FC<{ isNew?: boolean }> = ({ isNew = false }) => {
    // Extended key usages come from the OID catalog, not a hardcoded list — see useEkuCatalog.
    const ekuCatalog = useEkuCatalog();
    // Standard key usages are catalog-checked too, so a catalog with no Standard rows is reported
    // under the picker instead of surfacing as a refusal at issuance.
    const keyUsageCatalog = useKeyUsageCatalog();
    const { id } = useParams<{ id: string }>();
    const navigate = useNavigate();
    const { requireStepUp } = useStepUp();
    const { can } = useAuth();
    const { showToast } = useToast();

    const [profile, setProfile] = useState<any | null>(null);
    const [profiles, setProfiles] = useState<any[]>([]);
    const [authorities, setAuthorities] = useState<any[]>([]);
    const [ctLogs, setCtLogs] = useState<CtLogChoice[] | null>(null);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState<NoticeInput | null>(null);
    const [refresh, setRefresh] = useState(0);

    const [resolvedProfile, setResolvedProfile] = useState<any | null>(null);
    const [resolvedLoading, setResolvedLoading] = useState(false);
    const [validationResult, setValidationResult] = useState<{ isValid: boolean; errors: string[] } | null>(null);
    const [validationLoading, setValidationLoading] = useState(false);

    const [confirmDelete, setConfirmDelete] = useState(false);
    const [deleting, setDeleting] = useState(false);

    const [editForm, setEditForm] = useState(emptyForm);
    const [initialForm, setInitialForm] = useState(emptyForm);

    useEffect(() => {
        let cancelled = false;
        setLoading(true);
        setError(null);
        Promise.all([
            apiGet<any>('/api/v1/admin/cert-profiles'),
            apiGet<any>('/api/v1/admin/authorities').catch(() => []),
            apiGet<any>('/api/v1/admin/ct-logs/options').then(ctLogChoicesFromResponse).catch(() => null),
        ]).then(([data, authData, logs]) => {
            if (cancelled) return;
            setCtLogs(logs);
            const list = Array.isArray(data) ? data : (data.items || data.profiles || []);
            setProfiles(list);
            const p = isNew ? null : list.find((x: any) => cpId(x) === id) || null;
            setProfile(p);
            if (p) {
                const seeded = formFromProfile(p, ekuCatalog);
                setEditForm(seeded);
                setInitialForm(seeded);
            }
            setAuthorities(Array.isArray(authData) ? authData : (authData.items || authData.authorities || []));
            setLoading(false);
        }).catch((err) => { if (!cancelled) { setError(errorNotice(err, 'Failed to load profile')); setLoading(false); } });
        return () => { cancelled = true; };
    }, [id, refresh, isNew]); // eslint-disable-line react-hooks/exhaustive-deps

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

    const mode = isNew ? 'create' : 'edit';
    const dirty = JSON.stringify(editForm) !== JSON.stringify(initialForm);
    const blockedReasons = validate(editForm, mode, ctLogs);

    const handleSave = async () => {
        try {
            if (isNew) {
                const created = await apiPostWithMfa<any>('/api/v1/admin/cert-profiles', formToCreateBody(editForm), requireStepUp, StepUpOps.CreateCertProfile);
                showToast('success', 'Certificate profile created');
                const newId = created ? cpId(created) : undefined;
                navigate(newId ? profileDetailPath('cert', newId) : CERT_TAB, { replace: true });
                return;
            }
            await apiPutWithMfa(`/api/v1/admin/cert-profiles/${id}`, formToUpdateBody(editForm), requireStepUp, StepUpOps.UpdateCertProfile, id!);
            showToast('success', 'Certificate profile updated');
            setRefresh((r) => r + 1);
        } catch (err: any) {
            if (err.message !== 'Step-up MFA cancelled') showToast('error', err.message || (isNew ? 'Failed to create profile' : 'Failed to update profile'));
            throw err;
        }
    };

    const handleCancel = () => {
        if (isNew) navigate(CERT_TAB);
        else setEditForm(initialForm);
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

    if (loading) return <div className="p-6 text-sm text-ink-muted">Loading…</div>;
    if (error) return <InlineNotice notice={error} />;
    if (!isNew && !profile) return (
        <div className="p-6 space-y-3">
            <p className="text-sm text-ink-muted">Certificate profile not found.</p>
            <button onClick={() => navigate(CERT_TAB)} className="px-3 py-1.5 text-sm bg-sunken rounded">Back to Certificate Profiles</button>
        </div>
    );

    const p = profile ?? {};
    // An instance-wide profile is read-only without CertRevoke at system scope, as the server requires.
    const readOnly = !isNew && !mayChangeProfile(isInstanceWideCertProfile(p), can(Capabilities.CertRevoke));
    const title = isNew ? 'New certificate profile' : p.name;
    // The server refuses to delete a profile it finds by name or one a CA issues its own signers from.
    const usedBy: string[] = p.infrastructureUses ?? [];
    const undeletable = certProfileInUse(p);

    return (
        <DetailPage
            breadcrumbs={[{ label: 'Profile Management', to: CERT_TAB }, { label: 'Certificate Profiles', to: CERT_TAB }, { label: title }]}
            title={title}
            subtitle={isNew ? undefined : <>{p.isCaProfile ? 'CA Profile' : 'Leaf Profile'}{readOnly && <span className="block text-xs">{INSTANCE_WIDE_READ_ONLY}</span>}</>}
            backTo={CERT_TAB}
            editable={!readOnly}
            initialMode={isNew ? 'edit' : 'view'}
            modeToggle={!isNew}
            saveLabel={isNew ? 'Create' : 'Save'}
            onSave={handleSave}
            onCancel={handleCancel}
            saveDisabled={blockedReasons.length > 0 || (!isNew && !dirty)}
            actions={isNew || readOnly || undeletable ? undefined : <button onClick={() => setConfirmDelete(true)} disabled={deleting} className={actionButtonDanger}>Delete</button>}
        >
            {(viewMode) => viewMode === 'edit' ? (
                <DetailSection title={isNew ? 'New Certificate Profile' : 'Edit Certificate Profile'}>
                    <SubmitBlockedHint reasons={blockedReasons} />
                    <CertProfileForm value={editForm} onChange={setEditForm} mode={mode}
                        profileId={isNew ? undefined : id} parentProfiles={profiles} authorities={authorities}
                        ekuCatalog={ekuCatalog} keyUsageCatalog={keyUsageCatalog} ctLogs={ctLogs}
                        systemPurpose={isNew ? null : p.systemPurpose} />
                </DetailSection>
            ) : (<>
                {undeletable && (
                    <DetailSection title="In Use">
                        {p.systemPurpose && (
                            <p className="text-xs text-ink-muted max-w-3xl">
                                The application finds this profile by its name: {p.systemPurpose}. It cannot be renamed,
                                deleted, bound to one CA or changed in kind.
                            </p>
                        )}
                        {usedBy.length > 0 && (
                            <p className="text-xs text-ink-muted max-w-3xl">
                                Named for a CA's own certificate by: {usedBy.join('; ')}. It cannot be deleted until
                                those CAs name another profile on their own pages.
                            </p>
                        )}
                    </DetailSection>
                )}
                <DetailSection title="Certificate Profile">
                    <DetailField label="Name" value={p.name} />
                    <DetailField label="Description" value={p.description} />
                    <DetailField label="Type" value={p.isCaProfile ? 'CA Profile' : 'Leaf Profile'} />
                    <DetailField label="Key Usages" value={canonicalizeUsages(parseListField(p.keyUsages), KEY_USAGE_OPTIONS).map(keyUsageLabel).join(', ')} />
                    <DetailField label="Extended Key Usages" value={canonicalizeUsages(parseListField(p.extendedKeyUsages), ekuCatalog.options, ekuCatalog.aliases).map(ekuCatalog.label).join(', ')} />
                    <div className="py-1"><span className="text-xs text-ink-muted">Keys and signatures</span><KeyPolicySummary algorithms={p.allowedKeyAlgorithms} sizes={p.allowedKeySizes} signatures={p.allowedSignatureAlgorithms} /></div>
                    <DetailField label="Validity Period Min" value={periodText(p.validityPeriodMin)} />
                    <DetailField label="Validity Period Max" value={periodText(p.validityPeriodMax)} />
                    <DetailField label="CT Enabled" value={p.ctEnabled ? 'Yes' : 'No'} />
                    {p.ctEnabled && <div className="py-1"><span className="text-xs text-ink-muted">CT Logs</span><CtLogList stored={p.ctLogIds} logs={ctLogs} /></div>}
                    <DetailField label="Allow Wildcard SAN/CN" value={p.allowWildcard ? 'Yes' : 'No'} />
                    {p.inheritanceEnabled && <DetailField label="Inherits From" value={resolveParentName(p.inheritsFromId) || 'None'} />}
                    <DetailField label="CA Scope" value={<CaScopeName caId={p.certificateAuthorityId} fallback="System-wide" />} />
                </DetailSection>

                {p.inheritanceEnabled && p.inheritsFromId && (
                    <DetailSection title="Inheritance">
                        <div className="flex gap-2">
                            <button onClick={fetchResolvedProfile} disabled={resolvedLoading} className="px-3 py-1 text-xs bg-accent-soft text-accent-ink border border-accent/40 rounded hover:bg-accent/15 transition-colors disabled:opacity-50">{resolvedLoading ? 'Loading...' : 'Resolved Profile'}</button>
                            <button onClick={fetchValidation} disabled={validationLoading} className="px-3 py-1 text-xs bg-warn-soft text-warn border border-warn/40 rounded hover:bg-warn/15 transition-colors disabled:opacity-50">{validationLoading ? 'Validating...' : 'Validate Inheritance'}</button>
                        </div>
                        {validationResult && (
                            <div className={`mt-3 p-3 rounded border text-sm ${validationResult.isValid ? 'bg-ok-soft border-ok/40 text-ok' : 'bg-crit-soft border-crit/40 text-crit'}`}>
                                {validationResult.isValid ? <span>Inheritance is valid. No constraint violations found.</span> : (
                                    <div><span className="font-semibold">Validation errors:</span><ul className="mt-1 list-disc list-inside space-y-0.5">{validationResult.errors.map((err, i) => <li key={i} className="text-xs">{err}</li>)}</ul></div>
                                )}
                            </div>
                        )}
                        {resolvedProfile && (
                            <div className="mt-3 bg-raised border border-line rounded-lg p-3 space-y-2">
                                <h5 className="text-xs font-semibold text-ink mb-2">Resolved (Effective) Profile</h5>
                                {resolvedProfile.parentProfileId && <div className="text-xs text-ink-muted mb-2">Parent: {resolveParentName(resolvedProfile.parentProfileId)}</div>}
                                <SourceBorderedField source={resolvedProfile.fieldSources?.Name} label="Name" value={resolvedProfile.name} />
                                <SourceBorderedField source={resolvedProfile.fieldSources?.Description} label="Description" value={resolvedProfile.description} />
                                <SourceBorderedField source={resolvedProfile.fieldSources?.IsCaProfile} label="CA Profile" value={resolvedProfile.isCaProfile ? 'Yes' : 'No'} />
                                <SourceBorderedField source={resolvedProfile.fieldSources?.KeyUsages} label="Key Usages" value={canonicalizeUsages(parseListField(resolvedProfile.keyUsages), KEY_USAGE_OPTIONS).map(keyUsageLabel).join(', ')} />
                                <SourceBorderedField source={resolvedProfile.fieldSources?.ExtendedKeyUsages} label="Extended Key Usages" value={canonicalizeUsages(parseListField(resolvedProfile.extendedKeyUsages), ekuCatalog.options, ekuCatalog.aliases).map(ekuCatalog.label).join(', ')} />
                                <SourceBorderedField source={resolvedProfile.fieldSources?.ValidityPeriodMin} label="Validity Period Min" value={periodText(resolvedProfile.validityPeriodMin)} />
                                <SourceBorderedField source={resolvedProfile.fieldSources?.ValidityPeriodMax} label="Validity Period Max" value={periodText(resolvedProfile.validityPeriodMax)} />
                                <div className={`pl-3 border-l-2 ${['AllowedKeyAlgorithms', 'AllowedKeySizes', 'AllowedSignatureAlgorithms'].some((k) => resolvedProfile.fieldSources?.[k] === 'overridden') ? 'border-l-ok' : 'border-l-line-strong'}`}>
                                    <div className="flex flex-wrap items-center gap-y-1">
                                        <span className="text-xs text-ink-muted">Keys and signatures</span>
                                        {([['AllowedKeyAlgorithms', 'algorithms'], ['AllowedKeySizes', 'sizes'], ['AllowedSignatureAlgorithms', 'signatures']] as const).map(([k, noun]) => resolvedProfile.fieldSources?.[k] && (
                                            <span key={k} className="ml-2 text-[10px] text-ink-muted">{noun}<FieldSourceBadge source={resolvedProfile.fieldSources[k]} /></span>
                                        ))}
                                    </div>
                                    <KeyPolicySummary algorithms={resolvedProfile.allowedKeyAlgorithms} sizes={resolvedProfile.allowedKeySizes} signatures={resolvedProfile.allowedSignatureAlgorithms} />
                                </div>
                                <SourceBorderedField source={resolvedProfile.fieldSources?.CtEnabled} label="CT Enabled" value={resolvedProfile.ctEnabled ? 'Yes' : 'No'} />
                                <SourceBorderedField source={resolvedProfile.fieldSources?.CtLogIds} label="CT Logs" value={ctLogIdsFromStored(resolvedProfile.ctLogIds).map((x) => ctLogDisplay(x, ctLogs).text).join(', ') || 'Every enabled log'} />
                            </div>
                        )}
                    </DetailSection>
                )}

                <ConfirmModal
                    isOpen={confirmDelete}
                    title="Delete Certificate Profile"
                    message={`Delete certificate profile "${p.name}"? This cannot be undone.`}
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

export default CertProfileDetail;
