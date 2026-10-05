import React, { useState, useEffect } from 'react';
import type { NoticeInput } from '@shared/notifications/notice';
import { errorNotice } from '@shared-auth/api/notices';
import { useSearchParams } from 'react-router-dom';
import { apiGet, apiDeleteWithMfa } from '../api/client';
import { useScope } from '../context/ScopeContext';
import { useStepUp } from '../components/StepUpMfaContext';
import { useToast } from '@shared/context/ToastContext';
import { StatusBadge } from '@shared/components/cards/StatusBadge';
import { DetailField } from '@shared/components/cards/DetailField';
import ConfirmModal from '../components/ConfirmModal';
import { DataTable, DataTableColumn, DataTableBulkAction } from '@shared/components/DataTable';
import { canonicalizeUsages, parseListField, parseJsonArray, BadgeList, CeilingList, caRowId } from './profileHelpers';
import { AlgorithmSummary, KeyPolicySummary } from './profiles/KeyPolicyEditor';
import RequestProfilesTab from './RequestProfiles';
import { Capabilities, StepUpOps } from '@shared/generated';
import { useAuth } from '../context/AuthContext';
import { isInstanceWideCertProfile, isUnboundSigningProfile, mayChangeProfile } from './profiles/instanceWide';
import { useEkuCatalog } from '../hooks/useOidCatalog';
import { NewProfileButton } from './profiles/NewProfileButton';
import { PROFILE_TABS as TABS, type ProfileTab as Tab } from './profiles/profileRoutes';

/* ─── Certificate Profiles Tab ─── */
const CertProfilesTab: React.FC = () => {
    const { requireStepUp } = useStepUp();
    const { showToast } = useToast();
    const [profiles, setProfiles] = useState<any[]>([]);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState<NoticeInput | null>(null);
    const [confirmDelete, setConfirmDelete] = useState<any | null>(null);
    const [deleting, setDeleting] = useState(false);
    const { caQuery, caId: scopeCaId } = useScope();
    const { can } = useAuth();
    const systemCertRevoke = can(Capabilities.CertRevoke);

    const load = () => {
        setLoading(true);
        setError(null);
        apiGet<any>(`/api/v1/admin/cert-profiles${caQuery()}`)
            .then((data) => setProfiles(Array.isArray(data) ? data : (data.items || data.profiles || [])))
            .catch((err) => setError(errorNotice(err, 'The request failed.')))
            .finally(() => setLoading(false));
    };

    useEffect(() => {
        load();
    }, [scopeCaId]); // eslint-disable-line react-hooks/exhaustive-deps

    /** Resolve parent profile name from ID */
    const resolveParentName = (id: string | undefined | null) => {
        if (!id) return undefined;
        const p = profiles.find((pr) => (pr.id || pr.certProfileId) === id);
        return p ? p.name : id;
    };

    const performDelete = async () => {
        if (!confirmDelete) return;
        setDeleting(true);
        const profileId = confirmDelete.id || confirmDelete.certProfileId;
        try {
            await apiDeleteWithMfa(`/api/v1/admin/cert-profiles/${profileId}`, requireStepUp, StepUpOps.DeleteCertProfile, profileId);
            showToast('success', 'Certificate profile deleted');
            load();
        } catch (err: any) {
            if (err.message !== 'Step-up MFA cancelled') showToast('error', err.message || 'Failed to delete profile');
        } finally {
            setDeleting(false);
            setConfirmDelete(null);
        }
    };

    const columns: DataTableColumn<any>[] = [
        {
            key: 'name', header: 'Name', defaultWidth: 240, minWidth: 160, truncate: false, exportValue: (p) => p.name,
            render: (p) => (
                <span className="flex items-center gap-2 min-w-0">
                    <span className="text-ink font-medium truncate">{p.name}</span>
                    {p.inheritanceEnabled && p.inheritsFromId && (
                        <span className="px-2 py-0.5 text-[10px] rounded bg-accent-soft text-accent-ink border border-accent/40 shrink-0">Inherits: {resolveParentName(p.inheritsFromId)}</span>
                    )}
                </span>
            ),
        },
        { key: 'type', header: 'Type', defaultWidth: 100, truncate: false, exportValue: (p) => (p.isCaProfile ? 'CA' : 'Leaf'), render: (p) => <StatusBadge status={p.isCaProfile ? 'active' : 'enabled'} label={p.isCaProfile ? 'CA' : 'Leaf'} /> },
        { key: 'ct', header: 'CT', defaultWidth: 80, truncate: false, exportValue: (p) => (p.ctEnabled ? 'Yes' : 'No'), render: (p) => p.ctEnabled ? <StatusBadge status="active" label="CT" /> : <span className="text-xs text-ink-muted">-</span> },
        { key: 'validity', header: 'Validity', defaultWidth: 160, exportValue: (p) => (p.validityPeriodMin || p.validityPeriodMax ? `${p.validityPeriodMin || '?'} – ${p.validityPeriodMax || '?'}` : ''), render: (p) => <span className="text-xs text-ink-muted">{p.validityPeriodMin || p.validityPeriodMax ? `${p.validityPeriodMin || '?'} – ${p.validityPeriodMax || '?'}` : '-'}</span> },
    ];

    const bulkActions: DataTableBulkAction<any>[] = [
        { label: 'Delete', single: true, variant: 'danger', onClick: (rows) => setConfirmDelete(rows[0]), enabledFor: (p) => mayChangeProfile(isInstanceWideCertProfile(p), systemCertRevoke) },
    ];

    const drawer = (p: any) => (
        <div className="text-sm">
            <DetailField label="Name" value={p.name} />
            <DetailField label="Description" value={p.description} />
            <DetailField label="Type" value={p.isCaProfile ? 'CA Profile' : 'Leaf Profile'} />
            <div className="py-1"><span className="text-xs text-ink-muted">Keys and signatures</span><KeyPolicySummary algorithms={p.allowedKeyAlgorithms} sizes={p.allowedKeySizes} signatures={p.allowedSignatureAlgorithms} /></div>
            <DetailField label="Validity Min" value={p.validityPeriodMin} />
            <DetailField label="Validity Max" value={p.validityPeriodMax} />
            <DetailField label="CT Enabled" value={p.ctEnabled ? 'Yes' : 'No'} />
            {p.inheritanceEnabled && <DetailField label="Inherits From" value={resolveParentName(p.inheritsFromId) || 'None'} />}
            <DetailField label="CA Scope" value={p.certificateAuthorityId ? String(p.certificateAuthorityId) : 'System-wide'} />
            <p className="text-[11px] text-ink-muted pt-3">Open the full page to view all rules or edit.</p>
        </div>
    );

    return (
        <div className="space-y-4">
            <div className="flex items-center justify-between">
                <h3 className="text-sm font-semibold text-ink">Certificate Profiles</h3>
                <NewProfileButton type="cert" />
            </div>

            {/* Profile List */}
            <DataTable<any>
                tableId="cert-profiles"
                title="Certificate Profiles"
                rows={profiles}
                rowKey={(p) => p.id || p.certProfileId || p.name}
                loading={loading}
                error={error}
                empty="No certificate profiles found"
                columns={columns}
                selectable
                bulkActions={bulkActions}
                exportFileName="cert-profiles"
                renderDrawer={drawer}
                drawerTitle={(p) => p.name}
                detailPath={(p) => `/profiles/cert/${p.id || p.certProfileId}`}
            />

            <ConfirmModal
                isOpen={!!confirmDelete}
                title="Delete Certificate Profile"
                message={confirmDelete ? `Delete certificate profile "${confirmDelete.name}"? This cannot be undone.` : ''}
                confirmLabel="Delete"
                tone="crit"
                loading={deleting}
                onConfirm={performDelete}
                onCancel={() => setConfirmDelete(null)}
            />
        </div>
    );
};

/* ─── Signing Profiles Tab ─── */
const SigningProfilesTab: React.FC = () => {
    const { can } = useAuth();
    const systemCaManage = can(Capabilities.CaManage);
    // Extended key usages come from the OID catalog, not a hardcoded list — see useEkuCatalog.
    const ekuCatalog = useEkuCatalog();
    const { requireStepUp } = useStepUp();
    const { showToast } = useToast();
    const [profiles, setProfiles] = useState<any[]>([]);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState<NoticeInput | null>(null);
    const [authorities, setAuthorities] = useState<any[]>([]);
    const [confirmDelete, setConfirmDelete] = useState<any | null>(null);
    const [deleting, setDeleting] = useState(false);
    // A signing profile belongs to the CA whose certificate it issues under; a CA scope keeps
    // the ones issued by the scoped CA (and any with no issuer yet).
    const { caId: scopeCaId } = useScope();
    const scopedCa = scopeCaId ? authorities.find((a) => a.id === scopeCaId) : null;
    const visibleProfiles = scopedCa
        ? profiles.filter((p) => !p.issuerId || p.issuerId === scopedCa.certificateId || p.issuerId === scopedCa.id)
        : profiles;

    const load = () => {
        setLoading(true);
        setError(null);
        apiGet<any>('/api/v1/admin/signing-profiles')
            .then((data) => setProfiles(Array.isArray(data) ? data : (data.items || data.profiles || [])))
            .catch((err) => setError(errorNotice(err, 'The request failed.')))
            .finally(() => setLoading(false));
    };

    useEffect(() => {
        load();
        apiGet<any>('/api/v1/admin/authorities')
            .then((data) => setAuthorities(Array.isArray(data) ? data : (data.items || data.authorities || [])))
            .catch(() => {});
    }, []);

    const performDelete = async () => {
        if (!confirmDelete) return;
        setDeleting(true);
        const profileId = confirmDelete.id || confirmDelete.signingProfileId;
        try {
            await apiDeleteWithMfa(`/api/v1/admin/signing-profiles/${profileId}`, requireStepUp, StepUpOps.DeleteSigningProfile, profileId);
            showToast('success', 'Signing profile deleted');
            load();
        } catch (err: any) {
            if (err.message !== 'Step-up MFA cancelled') showToast('error', err.message || 'Failed to delete signing profile');
        } finally {
            setDeleting(false);
            setConfirmDelete(null);
        }
    };

    /** Resolve authority name from ID */
    const authorityName = (issuerId: string | undefined) => {
        if (!issuerId) return undefined;
        const auth = authorities.find((a) => a.certificateId === issuerId || a.id === issuerId);
        return auth ? auth.name || auth.commonName || issuerId : issuerId;
    };

    const columns: DataTableColumn<any>[] = [
        {
            key: 'name', header: 'Name', defaultWidth: 220, minWidth: 150, truncate: false, exportValue: (p) => p.name,
            render: (p) => (
                <span className="flex items-center gap-2 min-w-0">
                    <span className="text-ink font-medium truncate">{p.name}</span>
                    {p.isDefault && <StatusBadge status="active" label="Default" />}
                </span>
            ),
        },
        { key: 'issuer', header: 'Issuer', defaultWidth: 180, exportValue: (p) => authorityName(p.issuerId) || '', render: (p) => <span className="text-xs text-ink-muted truncate">{authorityName(p.issuerId) || '-'}</span> },
        { key: 'algorithms', header: 'Algorithms', defaultWidth: 200, exportValue: (p) => parseListField(p.allowedAlgorithms).join(', ') || 'unrestricted', render: (p) => <span className="text-xs text-ink-muted truncate">{parseListField(p.allowedAlgorithms).join(', ') || 'unrestricted'}</span> },
        { key: 'maxPath', header: 'Max Path', defaultWidth: 90, exportValue: (p) => (p.maxPathLength != null ? String(p.maxPathLength) : ''), render: (p) => <span className="text-xs text-ink-muted">{p.maxPathLength != null ? p.maxPathLength : '-'}</span> },
    ];

    const bulkActions: DataTableBulkAction<any>[] = [
        { label: 'Delete', single: true, variant: 'danger', onClick: (rows) => setConfirmDelete(rows[0]), enabledFor: (p) => mayChangeProfile(isUnboundSigningProfile(p), systemCaManage) },
    ];

    const drawer = (p: any) => (
        <div className="text-sm">
            <DetailField label="Name" value={p.name} />
            <DetailField label="Description" value={p.description} />
            <DetailField label="Default" value={p.isDefault ? 'Yes' : 'No'} />
            <DetailField label="Issuer" value={authorityName(p.issuerId)} />
            <div className="py-1"><span className="text-xs text-ink-muted">Allowed Algorithms</span><AlgorithmSummary items={p.allowedAlgorithms} /></div>
            <div className="py-1"><span className="text-xs text-ink-muted">Allowed EKUs</span><CeilingList noun="EKU" raw={parseListField(p.allowedEKUs ?? p.allowedEkus)} items={canonicalizeUsages(parseListField(p.allowedEKUs ?? p.allowedEkus), ekuCatalog.options, ekuCatalog.aliases).map(ekuCatalog.label)} /></div>
            <DetailField label="Max Path Length" value={p.maxPathLength != null ? String(p.maxPathLength) : undefined} />
            <p className="text-[11px] text-ink-muted pt-3">Open the full page for all settings or to edit.</p>
        </div>
    );

    return (
        <div className="space-y-4">
            <div className="flex items-center justify-between">
                <h3 className="text-sm font-semibold text-ink">Signing Profiles</h3>
                <NewProfileButton type="signing" />
            </div>

            <DataTable<any>
                tableId="signing-profiles"
                title="Signing Profiles"
                rows={visibleProfiles}
                rowKey={(p) => p.id || p.signingProfileId || p.name}
                loading={loading}
                error={error}
                empty="No signing profiles found"
                columns={columns}
                selectable
                bulkActions={bulkActions}
                exportFileName="signing-profiles"
                renderDrawer={drawer}
                drawerTitle={(p) => p.name}
                detailPath={(p) => `/profiles/signing/${p.id || p.signingProfileId}`}
            />

            <ConfirmModal
                isOpen={!!confirmDelete}
                title="Delete Signing Profile"
                message={confirmDelete ? `Delete signing profile "${confirmDelete.name}"? This cannot be undone.` : ''}
                confirmLabel="Delete"
                tone="crit"
                loading={deleting}
                onConfirm={performDelete}
                onCancel={() => setConfirmDelete(null)}
            />
        </div>
    );
};

/* ─── SSH Signing Profiles Tab ─── */
const SshSigningProfilesTab: React.FC = () => {
    const { requireStepUp } = useStepUp();
    const { showToast } = useToast();
    const [profiles, setProfiles] = useState<any[]>([]);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState<NoticeInput | null>(null);
    const [caKeys, setCaKeys] = useState<any[]>([]);
    const [confirmDelete, setConfirmDelete] = useState<any | null>(null);
    const [deleting, setDeleting] = useState(false);

    const load = () => {
        setLoading(true);
        setError(null);
        apiGet<any>('/api/v1/admin/ssh/profiles/signing')
            .then((data) => setProfiles(Array.isArray(data) ? data : []))
            .catch((err) => setError(errorNotice(err, 'The request failed.')))
            .finally(() => setLoading(false));
    };

    useEffect(() => {
        load();
        apiGet<any>('/api/v1/admin/ssh/ca-keys')
            .then((data) => setCaKeys(Array.isArray(data) ? data : []))
            .catch(() => {});
    }, []);

    const performDelete = async () => {
        if (!confirmDelete) return;
        setDeleting(true);
        try {
            await apiDeleteWithMfa(`/api/v1/admin/ssh/profiles/signing/${confirmDelete.id}`, requireStepUp, StepUpOps.DeleteSshProfile, confirmDelete.id);
            showToast('success', 'SSH signing profile deleted');
            load();
        } catch (err: any) {
            showToast('error', err.message || 'Failed to delete');
        } finally {
            setDeleting(false);
            setConfirmDelete(null);
        }
    };

    const caKeyName = (id: string) => caKeys.find(k => k.id === id)?.name || id;

    const columns: DataTableColumn<any>[] = [
        { key: 'name', header: 'Name', defaultWidth: 220, minWidth: 150, truncate: false, exportValue: (p) => p.name, render: (p) => <span className="text-ink font-medium truncate">{p.name}</span> },
        {
            key: 'allows', header: 'Allows', defaultWidth: 130, truncate: false,
            exportValue: (p) => [p.allowUserCerts ? 'User' : null, p.allowHostCerts ? 'Host' : null].filter(Boolean).join(', '),
            render: (p) => (
                <span className="flex gap-1">
                    {p.allowUserCerts && <StatusBadge status="active" label="User" />}
                    {p.allowHostCerts && <StatusBadge status="pending" label="Host" />}
                    {!p.allowUserCerts && !p.allowHostCerts && <span className="text-xs text-ink-muted">-</span>}
                </span>
            ),
        },
        { key: 'caKey', header: 'CA Key', defaultWidth: 170, exportValue: (p) => caKeyName(p.sshCaKeyId), render: (p) => <span className="text-xs text-ink-muted truncate">{caKeyName(p.sshCaKeyId)}</span> },
        { key: 'validity', header: 'Max Validity', defaultWidth: 120, exportValue: (p) => `${p.maxValidityHours}h`, render: (p) => <span className="text-xs text-ink-muted">{p.maxValidityHours}h</span> },
    ];

    const bulkActions: DataTableBulkAction<any>[] = [
        { label: 'Delete', single: true, variant: 'danger', onClick: (rows) => setConfirmDelete(rows[0]) },
    ];

    const drawer = (p: any) => (
        <div className="text-sm">
            <DetailField label="Name" value={p.name} />
            <DetailField label="Description" value={p.description} />
            <DetailField label="SSH CA Key" value={caKeyName(p.sshCaKeyId)} />
            <DetailField label="Max Validity Hours" value={String(p.maxValidityHours)} />
            <DetailField label="Allow User Certs" value={p.allowUserCerts ? 'Yes' : 'No'} />
            <DetailField label="Allow Host Certs" value={p.allowHostCerts ? 'Yes' : 'No'} />
            <DetailField label="Force Command" value={p.forceCommand || 'None'} />
            <div className="py-1"><span className="text-xs text-ink-muted">Default Extensions</span><BadgeList items={p.defaultExtensions} /></div>
            <p className="text-[11px] text-ink-muted pt-3">Open the full page to view all settings or edit.</p>
        </div>
    );

    return (
        <div className="space-y-4">
            <div className="flex items-center justify-between">
                <h3 className="text-sm font-semibold text-ink">SSH Signing Profiles</h3>
                <NewProfileButton type="ssh-signing" />
            </div>

            <DataTable<any>
                tableId="ssh-signing-profiles"
                title="SSH Signing Profiles"
                rows={profiles}
                rowKey={(p) => p.id}
                loading={loading}
                error={error}
                empty="No SSH signing profiles found"
                columns={columns}
                selectable
                bulkActions={bulkActions}
                exportFileName="ssh-signing-profiles"
                renderDrawer={drawer}
                drawerTitle={(p) => p.name}
                detailPath={(p) => `/profiles/ssh-signing/${p.id}`}
            />

            <ConfirmModal
                isOpen={!!confirmDelete}
                title="Delete SSH Signing Profile"
                message={confirmDelete ? `Delete SSH signing profile "${confirmDelete.name}"? This cannot be undone.` : ''}
                confirmLabel="Delete"
                tone="crit"
                loading={deleting}
                onConfirm={performDelete}
                onCancel={() => setConfirmDelete(null)}
            />
        </div>
    );
};

/* ─── SSH Cert Profiles Tab ─── */
const SshCertProfilesTab: React.FC = () => {
    const { requireStepUp } = useStepUp();
    const { showToast } = useToast();
    const [profiles, setProfiles] = useState<any[]>([]);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState<NoticeInput | null>(null);
    const [confirmDelete, setConfirmDelete] = useState<any | null>(null);
    const [deleting, setDeleting] = useState(false);

    const load = () => {
        setLoading(true);
        setError(null);
        apiGet<any>('/api/v1/admin/ssh/profiles/cert')
            .then((data) => setProfiles(Array.isArray(data) ? data : []))
            .catch((err) => setError(errorNotice(err, 'The request failed.')))
            .finally(() => setLoading(false));
    };

    useEffect(() => { load(); }, []);

    const performDelete = async () => {
        if (!confirmDelete) return;
        setDeleting(true);
        try {
            await apiDeleteWithMfa(`/api/v1/admin/ssh/profiles/cert/${confirmDelete.id}`, requireStepUp, StepUpOps.DeleteSshProfile, confirmDelete.id);
            showToast('success', 'SSH cert profile deleted');
            load();
        } catch (err: any) {
            showToast('error', err.message || 'Failed to delete');
        } finally {
            setDeleting(false);
            setConfirmDelete(null);
        }
    };

    const columns: DataTableColumn<any>[] = [
        { key: 'name', header: 'Name', defaultWidth: 240, minWidth: 160, truncate: false, exportValue: (p) => p.name, render: (p) => <span className="text-ink font-medium truncate">{p.name}</span> },
        { key: 'maxPrincipals', header: 'Max Principals', defaultWidth: 130, exportValue: (p) => (p.maxPrincipals ?? ''), render: (p) => <span className="text-xs text-ink-muted">{p.maxPrincipals}</span> },
        { key: 'validity', header: 'Max Validity', defaultWidth: 120, exportValue: (p) => `${p.maxValidityHours}h`, render: (p) => <span className="text-xs text-ink-muted">{p.maxValidityHours}h</span> },
    ];

    const bulkActions: DataTableBulkAction<any>[] = [
        { label: 'Delete', single: true, variant: 'danger', onClick: (rows) => setConfirmDelete(rows[0]) },
    ];

    const drawer = (p: any) => (
        <div className="text-sm">
            <DetailField label="Name" value={p.name} />
            <DetailField label="Description" value={p.description} />
            <DetailField label="Max Principals" value={String(p.maxPrincipals)} />
            <DetailField label="Max Validity Hours" value={String(p.maxValidityHours)} />
            <div className="py-1"><span className="text-xs text-ink-muted">Allowed Extensions</span><CeilingList items={p.allowedExtensions} noun="extension" /></div>
            <div className="py-1"><span className="text-xs text-ink-muted">Required Extensions</span><BadgeList items={p.requiredExtensions} /></div>
            <p className="text-[11px] text-ink-muted pt-3">Open the full page to view principal patterns or edit.</p>
        </div>
    );

    return (
        <div className="space-y-4">
            <div className="flex items-center justify-between">
                <h3 className="text-sm font-semibold text-ink">SSH Cert Profiles</h3>
                <NewProfileButton type="ssh-cert" />
            </div>

            <DataTable<any>
                tableId="ssh-cert-profiles"
                title="SSH Cert Profiles"
                rows={profiles}
                rowKey={(p) => p.id}
                loading={loading}
                error={error}
                empty="No SSH cert profiles found"
                columns={columns}
                selectable
                bulkActions={bulkActions}
                exportFileName="ssh-cert-profiles"
                renderDrawer={drawer}
                drawerTitle={(p) => p.name}
                detailPath={(p) => `/profiles/ssh-cert/${p.id}`}
            />

            <ConfirmModal
                isOpen={!!confirmDelete}
                title="Delete SSH Cert Profile"
                message={confirmDelete ? `Delete SSH cert profile "${confirmDelete.name}"? This cannot be undone.` : ''}
                confirmLabel="Delete"
                tone="crit"
                loading={deleting}
                onConfirm={performDelete}
                onCancel={() => setConfirmDelete(null)}
            />
        </div>
    );
};

/* ─── SSH Request Profiles Tab ─── */
const SshRequestProfilesTab: React.FC = () => {
    const { requireStepUp } = useStepUp();
    const { showToast } = useToast();
    const [profiles, setProfiles] = useState<any[]>([]);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState<NoticeInput | null>(null);
    const [signingProfiles, setSigningProfiles] = useState<any[]>([]);
    const [certProfiles, setCertProfiles] = useState<any[]>([]);
    const [authorities, setAuthorities] = useState<any[]>([]);
    const [confirmDelete, setConfirmDelete] = useState<any | null>(null);
    const [deleting, setDeleting] = useState(false);

    const load = () => {
        setLoading(true);
        setError(null);
        apiGet<any>('/api/v1/admin/ssh/profiles/request')
            .then((data) => setProfiles(Array.isArray(data) ? data : []))
            .catch((err) => setError(errorNotice(err, 'The request failed.')))
            .finally(() => setLoading(false));
    };

    useEffect(() => {
        load();
        apiGet<any>('/api/v1/admin/ssh/profiles/signing')
            .then((data) => setSigningProfiles(Array.isArray(data) ? data : []))
            .catch(() => {});
        apiGet<any>('/api/v1/admin/ssh/profiles/cert')
            .then((data) => setCertProfiles(Array.isArray(data) ? data : []))
            .catch(() => {});
        apiGet<any>('/api/v1/admin/authorities')
            .then((data) => setAuthorities(Array.isArray(data) ? data : (data.items || data.authorities || [])))
            .catch(() => {});
    }, []);

    const performDelete = async () => {
        if (!confirmDelete) return;
        setDeleting(true);
        try {
            await apiDeleteWithMfa(`/api/v1/admin/ssh/profiles/request/${confirmDelete.id}`, requireStepUp, StepUpOps.DeleteSshProfile, confirmDelete.id);
            showToast('success', 'SSH request profile deleted');
            load();
        } catch (err: any) {
            showToast('error', err.message || 'Failed to delete');
        } finally {
            setDeleting(false);
            setConfirmDelete(null);
        }
    };

    const caName = (caId: string) => {
        const a = authorities.find((x) => caRowId(x) === caId);
        return a ? (a.name || a.commonName || caId) : caId;
    };

    const columns: DataTableColumn<any>[] = [
        { key: 'name', header: 'Name', defaultWidth: 220, minWidth: 150, truncate: false, exportValue: (p) => p.name, render: (p) => <span className="text-ink font-medium truncate">{p.name}</span> },
        { key: 'approval', header: 'Approval', defaultWidth: 110, truncate: false, exportValue: (p) => (p.requireApproval ? 'Required' : 'Auto'), render: (p) => <StatusBadge status={p.requireApproval ? 'pending' : 'enabled'} label={p.requireApproval ? 'Required' : 'Auto'} /> },
        { key: 'caScope', header: 'CA Scope', defaultWidth: 170, exportValue: (p) => (p.certificateAuthorityId ? caName(p.certificateAuthorityId) : 'Any CA'), render: (p) => <span className="text-xs text-ink-muted truncate">{p.certificateAuthorityId ? caName(p.certificateAuthorityId) : 'Any CA'}</span> },
        { key: 'validity', header: 'Max Validity', defaultWidth: 120, exportValue: (p) => `${p.maxValidityHours}h`, render: (p) => <span className="text-xs text-ink-muted">{p.maxValidityHours}h</span> },
    ];

    const bulkActions: DataTableBulkAction<any>[] = [
        { label: 'Delete', single: true, variant: 'danger', onClick: (rows) => setConfirmDelete(rows[0]) },
    ];

    const resolveNames = (idsJson: any, items: any[]) => parseJsonArray(idsJson).map((id) => items.find((i) => i.id === id)?.name || id);

    const drawer = (p: any) => {
        const sps = resolveNames(p.allowedSshSigningProfileIds, signingProfiles);
        const cps = resolveNames(p.allowedSshCertProfileIds, certProfiles);
        return (
            <div className="text-sm">
                <DetailField label="Name" value={p.name} />
                <DetailField label="Description" value={p.description} />
                <DetailField label="CA Scope" value={p.certificateAuthorityId ? caName(p.certificateAuthorityId) : 'Any CA'} />
                <DetailField label="Require Approval" value={p.requireApproval ? 'Yes' : 'No'} />
                <DetailField label="Max Validity Hours" value={String(p.maxValidityHours)} />
                <DetailField label="Allowed Signing Profiles" value={sps.length ? sps.join(', ') : 'Any'} />
                <DetailField label="Allowed Cert Profiles" value={cps.length ? cps.join(', ') : 'Any'} />
                <p className="text-[11px] text-ink-muted pt-3">Open the full page to edit.</p>
            </div>
        );
    };

    return (
        <div className="space-y-4">
            <div className="flex items-center justify-between">
                <h3 className="text-sm font-semibold text-ink">SSH Request Profiles</h3>
                <NewProfileButton type="ssh-request" />
            </div>

            <DataTable<any>
                tableId="ssh-request-profiles"
                title="SSH Request Profiles"
                rows={profiles}
                rowKey={(p) => p.id}
                loading={loading}
                error={error}
                empty="No SSH request profiles found"
                columns={columns}
                selectable
                bulkActions={bulkActions}
                exportFileName="ssh-request-profiles"
                renderDrawer={drawer}
                drawerTitle={(p) => p.name}
                detailPath={(p) => `/profiles/ssh-request/${p.id}`}
            />

            <ConfirmModal
                isOpen={!!confirmDelete}
                title="Delete SSH Request Profile"
                message={confirmDelete ? `Delete SSH request profile "${confirmDelete.name}"? This cannot be undone.` : ''}
                confirmLabel="Delete"
                tone="crit"
                loading={deleting}
                onConfirm={performDelete}
                onCancel={() => setConfirmDelete(null)}
            />
        </div>
    );
};

/* ─── Profile Management Page ─── */
const ProfileManagement: React.FC = () => {
    const [searchParams, setSearchParams] = useSearchParams();
    const requestedTab = searchParams.get('tab');
    const activeTab: Tab = (TABS as readonly string[]).includes(requestedTab || '') ? (requestedTab as Tab) : 'Certificate Profiles';
    const setActiveTab = (tab: Tab) => {
        const next = new URLSearchParams(searchParams);
        next.set('tab', tab);
        setSearchParams(next, { replace: true });
    };

    return (
        <div className="p-3 sm:p-6 space-y-4 sm:space-y-6">
            <h1 className="text-xl font-semibold text-ink">Profile Management</h1>

            <div className="flex gap-1 border-b border-line overflow-x-auto">
                {TABS.map((tab) => (
                    <button key={tab} onClick={() => setActiveTab(tab)}
                        className={`px-4 py-2 text-sm font-medium transition-colors border-b-2 whitespace-nowrap ${activeTab === tab
                            ? 'text-accent-ink border-accent'
                            : 'text-ink-muted border-transparent hover:text-ink'}`}>
                        {tab}
                    </button>
                ))}
            </div>

            {activeTab === 'Certificate Profiles' && <CertProfilesTab />}
            {activeTab === 'Signing Profiles' && <SigningProfilesTab />}
            {activeTab === 'Request Profiles' && <RequestProfilesTab />}
            {activeTab === 'SSH Signing' && <SshSigningProfilesTab />}
            {activeTab === 'SSH Cert' && <SshCertProfilesTab />}
            {activeTab === 'SSH Request' && <SshRequestProfilesTab />}
        </div>
    );
};

export default ProfileManagement;
