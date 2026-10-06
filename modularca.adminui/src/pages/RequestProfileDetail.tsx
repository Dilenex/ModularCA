import React, { useEffect, useState } from 'react';
import type { NoticeInput } from '@shared/notifications/notice';
import { InlineNotice } from '@shared/components/InlineNotice';
import { errorNotice } from '@shared-auth/api/notices';
import { useParams, useNavigate } from 'react-router-dom';
import { apiGet, apiPost, apiPutWithMfa, apiDeleteWithMfa } from '../api/client';
import { DataTable, type DataTableColumn } from '@shared/components/DataTable';
import { useStepUp } from '../components/StepUpMfaContext';
import { useToast } from '@shared/context/ToastContext';
import { DetailField } from '@shared/components/cards/DetailField';
import ConfirmModal from '../components/ConfirmModal';
import { DetailPage, DetailSection } from '../components/DetailPage';
import { Capabilities, StepUpOps } from '@shared/generated';
import { useAuth } from '../context/AuthContext';
import { isUnboundRequestProfile, mayChangeProfile, INSTANCE_WIDE_READ_ONLY } from './profiles/instanceWide';
import { SourceBorderedField as ReqSourceBorderedField, SubmitBlockedHint } from './profileHelpers';
import { RequestProfileForm } from './profiles/RequestProfileForm';
import { emptyForm, formFromProfile, formToCreateBody, formToUpdateBody, validate } from './profiles/requestProfile';
import { PROFILE_TYPES, profileDetailPath } from './profiles/profileRoutes';
import { actionButtonDanger } from '@shared/components/actionButtons';

const REQUEST_TAB = PROFILE_TYPES.request.listPath;

/// <summary>
/// Detail page for a single enrollment request profile (a tab on Profile Management), and with
/// <c>isNew</c> the page that creates one. View shows DN/SAN rules and inheritance; edit and
/// create share RequestProfileForm. Updates go through step-up MFA; the server does not ask for
/// it on create. Delete and the resolve/validate inheritance actions are in-page.
/// </summary>
const RequestProfileDetail: React.FC<{ isNew?: boolean }> = ({ isNew = false }) => {
    const { id } = useParams<{ id: string }>();
    const navigate = useNavigate();
    const { requireStepUp } = useStepUp();
    const { can } = useAuth();
    const { showToast } = useToast();

    const [profile, setProfile] = useState<any | null>(null);
    const [profiles, setProfiles] = useState<any[]>([]);
    const [certProfiles, setCertProfiles] = useState<any[]>([]);
    const [authorities, setAuthorities] = useState<any[]>([]);
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

    const mode = isNew ? 'create' : 'edit';
    const dirty = JSON.stringify(editForm) !== JSON.stringify(initialForm);
    const blockedReasons = validate(editForm, mode);

    useEffect(() => {
        let cancelled = false;
        setLoading(true);
        setError(null);
        Promise.all([
            apiGet<any>('/api/v1/admin/request-profiles'),
            apiGet<any>('/api/v1/admin/cert-profiles').catch(() => []),
            apiGet<any>('/api/v1/admin/authorities').catch(() => []),
        ]).then(([profData, cpData, authData]) => {
            if (cancelled) return;
            const list = Array.isArray(profData) ? profData : (profData.items || profData.profiles || []);
            setProfiles(list);
            const p = isNew ? null : list.find((x: any) => x.id === id) || null;
            setProfile(p);
            if (p) {
                const seeded = formFromProfile(p);
                setEditForm(seeded);
                setInitialForm(seeded);
            }
            setCertProfiles(Array.isArray(cpData) ? cpData : (cpData.items || cpData.profiles || []));
            setAuthorities(Array.isArray(authData) ? authData : (authData.items || authData.authorities || []));
            setLoading(false);
        }).catch((err) => { if (!cancelled) { setError(errorNotice(err, 'Failed to load request profile')); setLoading(false); } });
        return () => { cancelled = true; };
    }, [id, refresh, isNew]);

    const resolveParentName = (pid: string | undefined | null) => {
        if (!pid) return undefined;
        const p = profiles.find((pr) => pr.id === pid);
        return p ? p.name : pid;
    };
    const resolveProfileName = (cpId: string) => {
        const cp = certProfiles.find((c) => (c.id || c.certProfileId) === cpId);
        return cp ? cp.name : cpId;
    };

    const fetchResolvedProfile = async () => {
        setResolvedLoading(true); setResolvedProfile(null);
        try { setResolvedProfile(await apiGet<any>(`/api/v1/admin/request-profiles/${id}/resolved`)); }
        catch (err: any) { showToast('error', err.message || 'Failed to fetch resolved profile'); }
        finally { setResolvedLoading(false); }
    };
    const fetchValidation = async () => {
        setValidationLoading(true); setValidationResult(null);
        try { setValidationResult(await apiPost<any>(`/api/v1/admin/request-profiles/${id}/validate-inheritance`, {})); }
        catch (err: any) { showToast('error', err.message || 'Failed to validate inheritance'); }
        finally { setValidationLoading(false); }
    };

    const handleSave = async () => {
        try {
            if (isNew) {
                const created = await apiPost<any>('/api/v1/admin/request-profiles', formToCreateBody(editForm));
                showToast('success', 'Request profile created');
                navigate(created?.id ? profileDetailPath('request', created.id) : REQUEST_TAB, { replace: true });
                return;
            }
            await apiPutWithMfa(`/api/v1/admin/request-profiles/${id}`, formToUpdateBody(editForm), requireStepUp, StepUpOps.UpdateRequestProfile, id!);
            showToast('success', 'Request profile updated');
            setRefresh((r) => r + 1);
        } catch (err: any) {
            if (err.message !== 'Step-up MFA cancelled') showToast('error', err.message || (isNew ? 'Failed to create request profile' : 'Failed to update request profile'));
            throw err;
        }
    };

    const handleCancel = () => {
        if (isNew) navigate(REQUEST_TAB);
        else setEditForm(initialForm);
    };

    const doDelete = async () => {
        setDeleting(true);
        try {
            await apiDeleteWithMfa(`/api/v1/admin/request-profiles/${id}`, requireStepUp, StepUpOps.DeleteRequestProfile, id!);
            showToast('success', 'Request profile deleted');
            navigate(REQUEST_TAB);
        } catch (err: any) {
            if (err.message !== 'Step-up MFA cancelled') showToast('error', err.message || 'Failed to delete request profile');
        } finally {
            setDeleting(false);
            setConfirmDelete(false);
        }
    };

    if (loading) return <div className="p-6 text-sm text-ink-muted">Loading…</div>;
    if (error) return <InlineNotice notice={error} />;
    if (!isNew && !profile) return (
        <div className="p-6 space-y-3">
            <p className="text-sm text-ink-muted">Request profile not found.</p>
            <button onClick={() => navigate(REQUEST_TAB)} className="px-3 py-1.5 text-sm bg-sunken rounded">Back to Request Profiles</button>
        </div>
    );

    const p = profile ?? {};
    // An instance-wide profile is read-only without CertRevoke at system scope, as the server requires.
    const readOnly = !isNew && !mayChangeProfile(isUnboundRequestProfile(p), can(Capabilities.CertRevoke));
    const dnRules: any[] = p.subjectDnRules || [];
    const title = isNew ? 'New request profile' : p.name;

    return (
        <DetailPage
            breadcrumbs={[{ label: 'Profile Management', to: REQUEST_TAB }, { label: 'Request Profiles', to: REQUEST_TAB }, { label: title }]}
            title={title}
            subtitle={isNew ? undefined : <>{p.description}{readOnly && <span className="block text-xs">{INSTANCE_WIDE_READ_ONLY}</span>}</>}
            backTo={REQUEST_TAB}
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
                <DetailSection title={isNew ? 'New Request Profile' : 'Edit Request Profile'}>
                    <SubmitBlockedHint reasons={blockedReasons} />
                    <RequestProfileForm value={editForm} onChange={setEditForm} mode={mode}
                        profileId={isNew ? undefined : id} parentProfiles={profiles} certProfiles={certProfiles}
                        authorities={authorities} />
                </DetailSection>
            ) : (<>
                <DetailSection title="Request Profile">
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-x-8">
                        <DetailField label="ID" value={p.id} mono />
                        <DetailField label="Name" value={p.name} />
                        <DetailField label="Description" value={p.description} />
                        <DetailField label="Require Approval" value={p.requireApproval ? 'Yes' : 'No'} />
                        <DetailField label="Default Cert Profile" value={p.defaultCertProfileId ? resolveProfileName(p.defaultCertProfileId) : 'None'} />
                        <DetailField label="Created" value={p.createdAt ? new Date(p.createdAt).toLocaleString() : undefined} />
                        <DetailField label="Updated" value={p.updatedAt ? new Date(p.updatedAt).toLocaleString() : undefined} />
                        <DetailField label="CA Scope" value={p.certificateAuthorityId ? String(p.certificateAuthorityId) : 'System-wide'} />
                        {p.inheritanceEnabled && <DetailField label="Inherits From" value={resolveParentName(p.inheritsFromId) || 'None'} />}
                    </div>
                    {p.allowedCertProfileIds && p.allowedCertProfileIds.length > 0 && (
                        <div className="py-2">
                            <span className="text-xs text-ink-muted">Allowed Cert Profiles</span>
                            <div className="flex flex-wrap gap-1 mt-1">
                                {p.allowedCertProfileIds.map((cpId: string, i: number) => (
                                    <span key={i} className="px-2 py-0.5 text-xs rounded bg-accent-soft text-accent-ink border border-accent/40">{resolveProfileName(cpId)}</span>
                                ))}
                            </div>
                        </div>
                    )}
                </DetailSection>

                <DetailSection title="Subject DN Rules">
                    {dnRules.length > 0 ? (
                        <div className="overflow-x-auto">
                            <DataTable<any>
                                tableId="request-profile-dn-rules"
                                rows={dnRules}
                                rowKey={(rule, ) => rule.field}
                                empty="No DN rules"
                                disableExport
                                columns={[
                                    { key: 'field', header: 'Field', defaultWidth: 120, sortable: true, exportValue: (rule) => rule.field, render: (rule) => <span className="text-ink font-medium">{rule.field}</span> },
                                    { key: 'requirement', header: 'Requirement', defaultWidth: 120, truncate: false, sortable: true, exportValue: (rule) => rule.requirement, render: (rule) => <span className={`px-2 py-0.5 rounded text-xs border ${rule.requirement === 'Required' ? 'bg-ok-soft text-ok border-ok/40' : rule.requirement === 'Forbidden' ? 'bg-crit-soft text-crit border-crit/40' : 'bg-sunken text-ink border-line-strong'}`}>{rule.requirement}</span> },
                                    { key: 'fixed', header: 'Fixed Value', defaultWidth: 160, exportValue: (rule) => rule.fixedValue || '', render: (rule) => <span className="text-ink truncate">{rule.fixedValue || '-'}</span> },
                                    { key: 'regex', header: 'Regex', flex: true, exportValue: (rule) => rule.regex || '', render: (rule) => <span className="text-ink font-mono truncate">{rule.regex || '-'}</span> },
                                    { key: 'maxLength', header: 'Max Length', defaultWidth: 100, align: 'right', exportValue: (rule) => rule.maxLength ?? '', render: (rule) => <span className="text-ink tabular-nums">{rule.maxLength ?? '-'}</span> },
                                    { key: 'default', header: 'Default', defaultWidth: 140, exportValue: (rule) => rule.defaultValue || '', render: (rule) => <span className="text-ink truncate">{rule.defaultValue || '-'}</span> },
                                ] as DataTableColumn<any>[]}
                            />
                        </div>
                    ) : <span className="text-xs text-ink-muted">No DN rules defined</span>}
                </DetailSection>

                <DetailSection title="SAN Rules">
                    <div>
                        <span className="text-xs text-ink-muted mr-2">Allowed Types:</span>
                        <div className="inline-flex flex-wrap gap-1 mt-1">
                            {(p.sanRules?.allowedTypes || []).map((type: string, i: number) => (
                                <span key={i} className="px-2 py-0.5 text-xs rounded bg-accent-soft text-accent-ink border border-accent/40">{type}</span>
                            ))}
                            {(!p.sanRules?.allowedTypes || p.sanRules.allowedTypes.length === 0) && <span className="text-xs text-ink-muted">None</span>}
                        </div>
                        <div className="mt-2"><DetailField label="SAN Required" value={p.sanRules?.required ? 'Yes' : 'No'} /></div>
                    </div>
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
                                <ReqSourceBorderedField source={resolvedProfile.fieldSources?.Name} label="Name" value={resolvedProfile.name} />
                                <ReqSourceBorderedField source={resolvedProfile.fieldSources?.Description} label="Description" value={resolvedProfile.description} />
                                <ReqSourceBorderedField source={resolvedProfile.fieldSources?.RequireApproval} label="Require Approval" value={resolvedProfile.requireApproval ? 'Yes' : 'No'} />
                                <ReqSourceBorderedField source={resolvedProfile.fieldSources?.DefaultCertProfileId} label="Default Cert Profile" value={resolvedProfile.defaultCertProfileId ? resolveProfileName(resolvedProfile.defaultCertProfileId) : 'None'} />
                            </div>
                        )}
                    </DetailSection>
                )}

                <ConfirmModal
                    isOpen={confirmDelete}
                    title="Delete Request Profile"
                    message={`Delete request profile "${p.name}"? This cannot be undone.`}
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

export default RequestProfileDetail;
