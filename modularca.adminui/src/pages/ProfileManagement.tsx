import React, { useState, useEffect } from 'react';
import { useSearchParams } from 'react-router-dom';
import { apiGet, apiPost, apiPostWithMfa, apiPut, apiDelete, apiPutWithMfa, apiDeleteWithMfa } from '../api/client';
import { useStepUp } from '../components/StepUpMfaContext';
import { useToast } from '@shared/context/ToastContext';
import { StatusBadge } from '@shared/components/cards/StatusBadge';
import { DetailField } from '@shared/components/cards/DetailField';
import ConfirmModal from '../components/ConfirmModal';
import { DataTable, DataTableColumn, DataTableBulkAction } from '@shared/components/DataTable';
import { KEY_USAGE_OPTIONS, keyUsageLabel, canonicalizeUsages, parseListField, ALLOWED_KEY_ALGORITHM_OPTIONS, ALLOWED_KEY_SIZE_OPTIONS, ALLOWED_SIGNATURE_ALGORITHM_OPTIONS, formatSignatureAlgorithmLabel, SIGNING_ALLOWED_ALGORITHM_OPTIONS, SSH_EXTENSION_OPTIONS, parseJsonArray, BadgeList, MultiToggle, formatKeySizeLabel, caRowId, caCertId, caDisplayName } from './profileHelpers';
import { inputClass, labelClass } from '@shared/components/forms';

import RequestProfilesTab from './RequestProfiles';
import { StepUpOps } from '@shared/generated';
import { useEkuCatalog } from '../hooks/useOidCatalog';

const TABS = ['Certificate Profiles', 'Signing Profiles', 'Request Profiles', 'SSH Signing', 'SSH Cert', 'SSH Request'] as const;
type Tab = typeof TABS[number];

/* ─── Certificate Profiles Tab ─── */
const CertProfilesTab: React.FC = () => {
    // Extended key usages come from the OID catalog, not a hardcoded list — see useEkuCatalog.
    const ekuCatalog = useEkuCatalog();
    const { requireStepUp } = useStepUp();
    const { showToast } = useToast();
    const [profiles, setProfiles] = useState<any[]>([]);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState<string | null>(null);
    const [showCreate, setShowCreate] = useState(false);
    const [creating, setCreating] = useState(false);
    const [authorities, setAuthorities] = useState<any[]>([]);
    const [confirmDelete, setConfirmDelete] = useState<any | null>(null);
    const [deleting, setDeleting] = useState(false);
    const [form, setForm] = useState({
        name: '',
        description: '',
        isCaProfile: false,
        keyUsages: [] as string[],
        extendedKeyUsages: [] as string[],
        allowedKeyAlgorithms: [] as string[],
        allowedKeySizes: [] as string[],
        allowedSignatureAlgorithms: [] as string[],
        validityPeriodMin: '',
        validityPeriodMax: '',
        ctEnabled: false,
        ctLogIds: '',
        inheritsFromId: '',
        inheritanceEnabled: false,
        certificateAuthorityId: '',
        allowWildcard: false,
    });

    const resetForm = () => setForm({
        name: '', description: '', isCaProfile: false,
        keyUsages: [], extendedKeyUsages: [],
        allowedKeyAlgorithms: [], allowedKeySizes: [], allowedSignatureAlgorithms: [],
        validityPeriodMin: '', validityPeriodMax: '',
        ctEnabled: false, ctLogIds: '',
        inheritsFromId: '', inheritanceEnabled: false, certificateAuthorityId: '',
        allowWildcard: false,
    });

    const load = () => {
        setLoading(true);
        setError(null);
        apiGet<any>('/api/v1/admin/cert-profiles')
            .then((data) => setProfiles(Array.isArray(data) ? data : (data.items || data.profiles || [])))
            .catch((err) => setError(err.message))
            .finally(() => setLoading(false));
    };

    useEffect(() => {
        load();
        apiGet<any>('/api/v1/admin/authorities')
            .then((data) => setAuthorities(Array.isArray(data) ? data : (data.items || data.authorities || [])))
            .catch(() => {});
    }, []);

    /** Resolve parent profile name from ID */
    const resolveParentName = (id: string | undefined | null) => {
        if (!id) return undefined;
        const p = profiles.find((pr) => (pr.id || pr.certProfileId) === id);
        return p ? p.name : id;
    };

    const handleCreate = async () => {
        setCreating(true);
        try {
            const body = {
                ...form,
                keyUsages: form.keyUsages.join(', '),
                extendedKeyUsages: form.extendedKeyUsages.join(', '),
                allowedKeyAlgorithms: JSON.stringify(form.allowedKeyAlgorithms),
                allowedKeySizes: JSON.stringify(form.allowedKeySizes),
                allowedSignatureAlgorithms: JSON.stringify(form.allowedSignatureAlgorithms),
                ctLogIds: form.ctLogIds || undefined,
                validityPeriodMin: form.validityPeriodMin || undefined,
                validityPeriodMax: form.validityPeriodMax || undefined,
                inheritsFromId: form.inheritsFromId || undefined,
                inheritanceEnabled: form.inheritanceEnabled,
                certificateAuthorityId: form.certificateAuthorityId || undefined,
                allowWildcard: form.allowWildcard,
            };
            await apiPost('/api/v1/admin/cert-profiles', body);
            setShowCreate(false);
            resetForm();
            load();
        } catch (err: any) {
            showToast('error', err.message || 'Failed to create profile');
        } finally {
            setCreating(false);
        }
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
                    <span className="text-gray-900 dark:text-white font-medium truncate">{p.name}</span>
                    {p.inheritanceEnabled && p.inheritsFromId && (
                        <span className="px-2 py-0.5 text-[10px] rounded bg-purple-100 dark:bg-purple-900/40 text-purple-700 dark:text-purple-300 border border-purple-300 dark:border-purple-700 shrink-0">Inherits: {resolveParentName(p.inheritsFromId)}</span>
                    )}
                </span>
            ),
        },
        { key: 'type', header: 'Type', defaultWidth: 100, truncate: false, exportValue: (p) => (p.isCaProfile ? 'CA' : 'Leaf'), render: (p) => <StatusBadge status={p.isCaProfile ? 'active' : 'enabled'} label={p.isCaProfile ? 'CA' : 'Leaf'} /> },
        { key: 'ct', header: 'CT', defaultWidth: 80, truncate: false, exportValue: (p) => (p.ctEnabled ? 'Yes' : 'No'), render: (p) => p.ctEnabled ? <StatusBadge status="active" label="CT" /> : <span className="text-xs text-gray-500">-</span> },
        { key: 'validity', header: 'Validity', defaultWidth: 160, exportValue: (p) => (p.validityPeriodMin || p.validityPeriodMax ? `${p.validityPeriodMin || '?'} – ${p.validityPeriodMax || '?'}` : ''), render: (p) => <span className="text-xs text-gray-600 dark:text-gray-400">{p.validityPeriodMin || p.validityPeriodMax ? `${p.validityPeriodMin || '?'} – ${p.validityPeriodMax || '?'}` : '-'}</span> },
    ];

    const bulkActions: DataTableBulkAction<any>[] = [
        { label: 'Delete', single: true, variant: 'danger', onClick: (rows) => setConfirmDelete(rows[0]) },
    ];

    const drawer = (p: any) => (
        <div className="text-sm">
            <DetailField label="Name" value={p.name} />
            <DetailField label="Description" value={p.description} />
            <DetailField label="Type" value={p.isCaProfile ? 'CA Profile' : 'Leaf Profile'} />
            <div className="py-1"><span className="text-xs text-gray-600 dark:text-gray-400">Allowed Key Algorithms</span><BadgeList items={p.allowedKeyAlgorithms} /></div>
            <DetailField label="Validity Min" value={p.validityPeriodMin} />
            <DetailField label="Validity Max" value={p.validityPeriodMax} />
            <DetailField label="CT Enabled" value={p.ctEnabled ? 'Yes' : 'No'} />
            {p.inheritanceEnabled && <DetailField label="Inherits From" value={resolveParentName(p.inheritsFromId) || 'None'} />}
            <DetailField label="CA Scope" value={p.certificateAuthorityId ? String(p.certificateAuthorityId) : 'System-wide'} />
            <p className="text-[11px] text-gray-500 pt-3">Open the full page to view all rules or edit.</p>
        </div>
    );

    return (
        <div className="space-y-4">
            <div className="flex items-center justify-between">
                <h3 className="text-sm font-semibold text-gray-900 dark:text-white">Certificate Profiles</h3>
                <button
                    onClick={() => setShowCreate(!showCreate)}
                    className="px-4 py-2 text-sm bg-blue-600 text-white rounded hover:bg-blue-700 transition-colors"
                >
                    {showCreate ? 'Cancel' : 'Create Profile'}
                </button>
            </div>

            {/* Create Form */}
            {showCreate && (
                <div className="bg-gray-100 dark:bg-gray-800 border border-gray-300 dark:border-gray-700 rounded-lg p-4 space-y-3">
                    <h4 className="text-sm font-semibold text-gray-900 dark:text-white">New Certificate Profile</h4>
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                        <div>
                            <label className={labelClass}>Name</label>
                            <input type="text" value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} className={inputClass} />
                        </div>
                        <div>
                            <label className={labelClass}>Description</label>
                            <input type="text" value={form.description} onChange={(e) => setForm({ ...form, description: e.target.value })} className={inputClass} />
                        </div>
                        <div>
                            <label className={labelClass}>Validity Period Min (ISO 8601)</label>
                            <input type="text" placeholder='e.g. P90D' value={form.validityPeriodMin} onChange={(e) => setForm({ ...form, validityPeriodMin: e.target.value })} className={inputClass} />
                        </div>
                        <div>
                            <label className={labelClass}>Validity Period Max (ISO 8601)</label>
                            <input type="text" placeholder='e.g. P1Y' value={form.validityPeriodMax} onChange={(e) => setForm({ ...form, validityPeriodMax: e.target.value })} className={inputClass} />
                        </div>
                        <div>
                            <label className={labelClass}>CT Log IDs</label>
                            <input type="text" placeholder="Comma-separated log IDs" value={form.ctLogIds} onChange={(e) => setForm({ ...form, ctLogIds: e.target.value })} className={inputClass} />
                        </div>
                        <div>
                            <label className={labelClass}>Inherits From</label>
                            <select value={form.inheritsFromId} onChange={(e) => setForm({ ...form, inheritsFromId: e.target.value })} className={inputClass}>
                                <option value="">-- None (standalone) --</option>
                                {profiles.map((pr) => {
                                    const prId = pr.id || pr.certProfileId;
                                    return <option key={prId} value={prId}>{pr.name}</option>;
                                })}
                            </select>
                        </div>
                        <div>
                            <label className={labelClass}>CA Scope</label>
                            <select value={form.certificateAuthorityId} onChange={(e) => setForm({ ...form, certificateAuthorityId: e.target.value })} className={inputClass}>
                                <option value="">-- System-wide --</option>
                                {authorities.map((a) => (
                                    <option key={caRowId(a)} value={caRowId(a)}>
                                        {caDisplayName(a)}
                                    </option>
                                ))}
                            </select>
                        </div>
                    </div>
                    <div className="flex flex-wrap gap-4">
                        <label className="flex items-center gap-2 text-xs text-gray-700 dark:text-gray-300">
                            <input type="checkbox" checked={form.isCaProfile} onChange={(e) => setForm({ ...form, isCaProfile: e.target.checked })} className="w-4 h-4 bg-gray-50 dark:bg-gray-900 border-gray-300 dark:border-gray-700 rounded" />
                            CA Profile
                        </label>
                        <label className="flex items-center gap-2 text-xs text-gray-700 dark:text-gray-300">
                            <input type="checkbox" checked={form.ctEnabled} onChange={(e) => setForm({ ...form, ctEnabled: e.target.checked })} className="w-4 h-4 bg-gray-50 dark:bg-gray-900 border-gray-300 dark:border-gray-700 rounded" />
                            CT Enabled
                        </label>
                        <label className="flex items-center gap-2 text-xs text-gray-700 dark:text-gray-300">
                            <input type="checkbox" checked={form.inheritanceEnabled} onChange={(e) => setForm({ ...form, inheritanceEnabled: e.target.checked })} className="w-4 h-4 bg-gray-50 dark:bg-gray-900 border-gray-300 dark:border-gray-700 rounded" />
                            Enable Inheritance
                        </label>
                    </div>
                    <div>
                        <label className="flex items-center gap-2 text-xs text-gray-700 dark:text-gray-300">
                            <input type="checkbox" checked={form.allowWildcard} onChange={(e) => setForm({ ...form, allowWildcard: e.target.checked })} className="w-4 h-4 bg-gray-50 dark:bg-gray-900 border-gray-300 dark:border-gray-700 rounded" />
                            Allow wildcard SAN/CN entries
                        </label>
                        <p className="text-[11px] text-gray-600 dark:text-gray-400 mt-1 ml-6">
                            When disabled, any DNS SAN or CN containing <code className="font-mono">*</code> is rejected at issuance.
                            Structural rules still apply when enabled: at most one <code className="font-mono">*</code>, in the
                            leftmost label, and the name must have at least two labels.
                        </p>
                    </div>
                    <div>
                        <label className={labelClass}>Key Usages</label>
                        <MultiToggle options={KEY_USAGE_OPTIONS} formatLabel={keyUsageLabel} selected={form.keyUsages}
                            onChange={(next) => setForm({ ...form, keyUsages: next })} />
                    </div>
                    <div>
                        <label className={labelClass}>Extended Key Usages</label>
                        <MultiToggle options={ekuCatalog.options} formatLabel={ekuCatalog.label} selected={form.extendedKeyUsages}
                            onChange={(next) => setForm({ ...form, extendedKeyUsages: next })} />
                    </div>
                    <div>
                        <label className={labelClass}>Allowed Key Algorithms</label>
                        <MultiToggle options={ALLOWED_KEY_ALGORITHM_OPTIONS} selected={form.allowedKeyAlgorithms}
                            onChange={(next) => setForm({ ...form, allowedKeyAlgorithms: next })} />
                    </div>
                    <div>
                        <label className={labelClass}>Allowed Key Sizes</label>
                        <MultiToggle options={ALLOWED_KEY_SIZE_OPTIONS} selected={form.allowedKeySizes}
                            onChange={(next) => setForm({ ...form, allowedKeySizes: next })}
                            formatLabel={formatKeySizeLabel} />
                    </div>
                    <div>
                        <label className={labelClass}>Allowed Signature Algorithms</label>
                        <MultiToggle options={ALLOWED_SIGNATURE_ALGORITHM_OPTIONS} selected={form.allowedSignatureAlgorithms}
                            onChange={(next) => setForm({ ...form, allowedSignatureAlgorithms: next })} formatLabel={formatSignatureAlgorithmLabel} />
                    </div>
                    <button onClick={handleCreate} disabled={creating || !form.name}
                        className="px-4 py-2 text-sm bg-blue-600 text-gray-900 dark:text-white rounded hover:bg-blue-700 disabled:opacity-50 transition-colors">
                        {creating ? 'Creating...' : 'Create'}
                    </button>
                </div>
            )}

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
                confirmClass="bg-red-600 hover:bg-red-700"
                loading={deleting}
                onConfirm={performDelete}
                onCancel={() => setConfirmDelete(null)}
            />
        </div>
    );
};

/* ─── Signing Profiles Tab ─── */
const SigningProfilesTab: React.FC = () => {
    // Extended key usages come from the OID catalog, not a hardcoded list — see useEkuCatalog.
    const ekuCatalog = useEkuCatalog();
    const { requireStepUp } = useStepUp();
    const { showToast } = useToast();
    const [profiles, setProfiles] = useState<any[]>([]);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState<string | null>(null);
    const [showCreate, setShowCreate] = useState(false);
    const [creating, setCreating] = useState(false);
    const [authorities, setAuthorities] = useState<any[]>([]);
    const [certProfiles, setCertProfiles] = useState<any[]>([]);
    const [confirmDelete, setConfirmDelete] = useState<any | null>(null);
    const [deleting, setDeleting] = useState(false);
    const [form, setForm] = useState({
        name: '',
        description: '',
        isDefault: false,
        issuerId: '',
        allowedAlgorithms: [] as string[],
        allowedEkus: [] as string[],
        maxPathLength: '',
        nameConstraintsPermitted: '',
        nameConstraintsExcluded: '',
        policyOids: '',
        inhibitAnyPolicy: false,
        allowedCertProfileIds: [] as string[],
        extendedKeyUsageCritical: false,
        policyQualifiersJson: '{}',
    });
    // Client-side validation errors for the policy qualifiers JSON textarea
    const [createPolicyQualifiersError, setCreatePolicyQualifiersError] = useState<string | null>(null);

    const resetForm = () => setForm({
        name: '', description: '', isDefault: false, issuerId: '',
        allowedAlgorithms: [], allowedEkus: [] as string[], maxPathLength: '',
        nameConstraintsPermitted: '', nameConstraintsExcluded: '',
        policyOids: '', inhibitAnyPolicy: false, allowedCertProfileIds: [],
        extendedKeyUsageCritical: false, policyQualifiersJson: '{}',
    });

    const load = () => {
        setLoading(true);
        setError(null);
        apiGet<any>('/api/v1/admin/signing-profiles')
            .then((data) => setProfiles(Array.isArray(data) ? data : (data.items || data.profiles || [])))
            .catch((err) => setError(err.message))
            .finally(() => setLoading(false));
    };

    useEffect(() => {
        load();
        apiGet<any>('/api/v1/admin/authorities')
            .then((data) => setAuthorities(Array.isArray(data) ? data : (data.items || data.authorities || [])))
            .catch(() => {});
        apiGet<any>('/api/v1/admin/cert-profiles')
            .then((data) => setCertProfiles(Array.isArray(data) ? data : (data.items || data.profiles || [])))
            .catch(() => {});
    }, []);

    const handleCreate = async () => {
        // Validate policy qualifiers JSON before submit
        setCreatePolicyQualifiersError(null);
        const rawPolicyQualifiers = (form.policyQualifiersJson ?? '').trim();
        if (rawPolicyQualifiers.length > 0) {
            try {
                const parsed = JSON.parse(rawPolicyQualifiers);
                if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) {
                    setCreatePolicyQualifiersError('Policy qualifiers must be a JSON object mapping OIDs to qualifiers.');
                    return;
                }
            } catch (err: any) {
                setCreatePolicyQualifiersError(`Invalid JSON: ${err.message || 'parse error'}`);
                return;
            }
        }
        setCreating(true);
        try {
            const body: any = {
                name: form.name,
                description: form.description,
                isDefault: form.isDefault,
                issuerId: form.issuerId || undefined,
                allowedAlgorithms: JSON.stringify(form.allowedAlgorithms),
                allowedEKUs: JSON.stringify(form.allowedEkus),
                maxPathLength: form.maxPathLength ? parseInt(form.maxPathLength) : null,
                nameConstraintsPermitted: form.nameConstraintsPermitted || undefined,
                nameConstraintsExcluded: form.nameConstraintsExcluded || undefined,
                policyOids: JSON.stringify(form.policyOids ? form.policyOids.split(',').map((s: string) => s.trim()).filter(Boolean) : []),
                inhibitAnyPolicy: form.inhibitAnyPolicy,
                extendedKeyUsageCritical: form.extendedKeyUsageCritical,
                policyQualifiersJson: rawPolicyQualifiers.length > 0 ? rawPolicyQualifiers : undefined,
            };
            const created = await apiPost<any>('/api/v1/admin/signing-profiles', body);
            // Link allowed cert profiles via the join endpoint
            if (form.allowedCertProfileIds.length > 0 && created?.id) {
                await apiPutWithMfa(`/api/v1/admin/signing-profiles/${created.id}/allowed-cert-profiles`,
                    form.allowedCertProfileIds, requireStepUp, StepUpOps.UpdateSigningProfile, created.id);
            }
            setShowCreate(false);
            resetForm();
            load();
        } catch (err: any) {
            showToast('error', err.message || 'Failed to create signing profile');
        } finally {
            setCreating(false);
        }
    };

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
                    <span className="text-gray-900 dark:text-white font-medium truncate">{p.name}</span>
                    {p.isDefault && <StatusBadge status="active" label="Default" />}
                </span>
            ),
        },
        { key: 'issuer', header: 'Issuer', defaultWidth: 180, exportValue: (p) => authorityName(p.issuerId) || '', render: (p) => <span className="text-xs text-gray-600 dark:text-gray-400 truncate">{authorityName(p.issuerId) || '-'}</span> },
        { key: 'algorithms', header: 'Algorithms', defaultWidth: 200, exportValue: (p) => parseJsonArray(p.allowedAlgorithms).join(', '), render: (p) => <span className="text-xs text-gray-600 dark:text-gray-400 truncate">{parseJsonArray(p.allowedAlgorithms).join(', ') || '-'}</span> },
        { key: 'maxPath', header: 'Max Path', defaultWidth: 90, exportValue: (p) => (p.maxPathLength != null ? String(p.maxPathLength) : ''), render: (p) => <span className="text-xs text-gray-600 dark:text-gray-400">{p.maxPathLength != null ? p.maxPathLength : '-'}</span> },
    ];

    const bulkActions: DataTableBulkAction<any>[] = [
        { label: 'Delete', single: true, variant: 'danger', onClick: (rows) => setConfirmDelete(rows[0]) },
    ];

    const drawer = (p: any) => (
        <div className="text-sm">
            <DetailField label="Name" value={p.name} />
            <DetailField label="Description" value={p.description} />
            <DetailField label="Default" value={p.isDefault ? 'Yes' : 'No'} />
            <DetailField label="Issuer" value={authorityName(p.issuerId)} />
            <div className="py-1"><span className="text-xs text-gray-600 dark:text-gray-400">Allowed Algorithms</span><BadgeList items={p.allowedAlgorithms} /></div>
            <div className="py-1"><span className="text-xs text-gray-600 dark:text-gray-400">Allowed EKUs</span><BadgeList items={canonicalizeUsages(parseListField(p.allowedEKUs ?? p.allowedEkus), ekuCatalog.options, ekuCatalog.aliases).map(ekuCatalog.label)} /></div>
            <DetailField label="Max Path Length" value={p.maxPathLength != null ? String(p.maxPathLength) : undefined} />
            <p className="text-[11px] text-gray-500 pt-3">Open the full page for all settings or to edit.</p>
        </div>
    );

    return (
        <div className="space-y-4">
            <div className="flex items-center justify-between">
                <h3 className="text-sm font-semibold text-gray-900 dark:text-white">Signing Profiles</h3>
                <button onClick={() => setShowCreate(!showCreate)}
                    className="px-4 py-2 text-sm bg-blue-600 text-gray-900 dark:text-white rounded hover:bg-blue-700 transition-colors">
                    {showCreate ? 'Cancel' : 'Create Profile'}
                </button>
            </div>

            {showCreate && (
                <div className="bg-gray-100 dark:bg-gray-800 border border-gray-300 dark:border-gray-700 rounded-lg p-4 space-y-3">
                    <h4 className="text-sm font-semibold text-gray-900 dark:text-white">New Signing Profile</h4>
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                        <div>
                            <label className={labelClass}>Name</label>
                            <input type="text" value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} className={inputClass} />
                        </div>
                        <div>
                            <label className={labelClass}>Description</label>
                            <input type="text" value={form.description} onChange={(e) => setForm({ ...form, description: e.target.value })} className={inputClass} />
                        </div>
                        <div>
                            <label className={labelClass}>Issuer</label>
                            <select value={form.issuerId} onChange={(e) => setForm({ ...form, issuerId: e.target.value })} className={inputClass}>
                                <option value="">-- Select Issuing Authority --</option>
                                {authorities.map((a) => (
                                    <option key={caCertId(a)} value={caCertId(a)}>
                                        {caDisplayName(a)}
                                    </option>
                                ))}
                            </select>
                        </div>
                        <div>
                            <label className={labelClass}>Max Path Length</label>
                            <input type="text" inputMode="numeric" value={form.maxPathLength} onChange={(e) => setForm({ ...form, maxPathLength: e.target.value.replace(/\D/g, '') })} className={inputClass} />
                        </div>
                        <div>
                            <label className={labelClass}>Name Constraints Permitted (JSON)</label>
                            <input type="text" placeholder='e.g. {"permitted":[".example.com"]}' value={form.nameConstraintsPermitted} onChange={(e) => setForm({ ...form, nameConstraintsPermitted: e.target.value })} className={inputClass} />
                        </div>
                        <div>
                            <label className={labelClass}>Name Constraints Excluded (JSON)</label>
                            <input type="text" placeholder='e.g. {"excluded":[".test.com"]}' value={form.nameConstraintsExcluded} onChange={(e) => setForm({ ...form, nameConstraintsExcluded: e.target.value })} className={inputClass} />
                        </div>
                        <div>
                            <label className={labelClass}>Allowed EKUs</label>
                            <div className="flex flex-wrap gap-2">
                                {ekuCatalog.options.map((oid) => { const eku = { oid, label: ekuCatalog.label(oid) };
                                    const selected = form.allowedEkus.includes(eku.oid);
                                    return (
                                        <button key={eku.oid} type="button"
                                            onClick={() => setForm({
                                                ...form,
                                                allowedEkus: selected
                                                    ? form.allowedEkus.filter((o: string) => o !== eku.oid)
                                                    : [...form.allowedEkus, eku.oid]
                                            })}
                                            className={`px-2 py-1 text-xs rounded border transition-colors ${
                                                selected
                                                    ? 'bg-blue-600/30 text-blue-800 dark:text-blue-300 border-blue-300 dark:border-blue-600'
                                                    : 'bg-gray-50 dark:bg-gray-900 text-gray-600 dark:text-gray-400 border-gray-300 dark:border-gray-700 hover:border-gray-500'
                                            }`}>
                                            {eku.label} <span className="text-[10px] text-gray-600 ml-1">{eku.oid}</span>
                                        </button>
                                    );
                                })}
                            </div>
                        </div>
                        <div>
                            <label className={labelClass}>Policy OIDs (comma-separated)</label>
                            <input type="text" placeholder="e.g. 2.23.140.1.2.1" value={form.policyOids} onChange={(e) => setForm({ ...form, policyOids: e.target.value })} className={inputClass} />
                        </div>
                    </div>
                    <div className="flex flex-wrap gap-4">
                        <label className="flex items-center gap-2 text-xs text-gray-700 dark:text-gray-300">
                            <input type="checkbox" checked={form.isDefault} onChange={(e) => setForm({ ...form, isDefault: e.target.checked })} className="w-4 h-4 bg-gray-50 dark:bg-gray-900 border-gray-300 dark:border-gray-700 rounded" />
                            Default Profile
                        </label>
                        <label className="flex items-center gap-2 text-xs text-gray-700 dark:text-gray-300">
                            <input type="checkbox" checked={form.inhibitAnyPolicy} onChange={(e) => setForm({ ...form, inhibitAnyPolicy: e.target.checked })} className="w-4 h-4 bg-gray-50 dark:bg-gray-900 border-gray-300 dark:border-gray-700 rounded" />
                            Inhibit Any Policy
                        </label>
                    </div>
                    <div>
                        <label className="flex items-center gap-2 text-xs text-gray-700 dark:text-gray-300">
                            <input type="checkbox" checked={form.extendedKeyUsageCritical} onChange={(e) => setForm({ ...form, extendedKeyUsageCritical: e.target.checked })} className="w-4 h-4 bg-gray-50 dark:bg-gray-900 border-gray-300 dark:border-gray-700 rounded" />
                            Mark Extended Key Usage extension as critical
                        </label>
                        <p className="text-[11px] text-gray-600 dark:text-gray-400 mt-1 ml-6">
                            RFC 5280 §4.2.1.12 recommends marking the EKU extension critical when the certificate's
                            purpose is restricted (e.g. a cert that must only be used for client auth).
                        </p>
                    </div>
                    <div>
                        <label className={labelClass}>Policy qualifiers (JSON)</label>
                        <textarea
                            value={form.policyQualifiersJson}
                            onChange={(e) => { setForm({ ...form, policyQualifiersJson: e.target.value }); if (createPolicyQualifiersError) setCreatePolicyQualifiersError(null); }}
                            rows={8}
                            placeholder={'{\n  "2.23.140.1.2.1": {\n    "cpsUri": "https://example.com/cps",\n    "userNotice": "Subscriber agrees to the relying party agreement.",\n    "critical": false\n  }\n}'}
                            className={`${inputClass} font-mono text-xs resize-y`}
                        />
                        {createPolicyQualifiersError && (
                            <p className="text-[11px] text-red-800 dark:text-red-400 mt-1">{createPolicyQualifiersError}</p>
                        )}
                        <p className="text-[11px] text-gray-600 dark:text-gray-400 mt-1">
                            Object mapping each policy OID listed above to its qualifiers. Each entry may include
                            <code className="font-mono"> cpsUri</code>, <code className="font-mono">userNotice</code>, and
                            <code className="font-mono"> critical</code>. Missing OIDs default to no qualifiers, non-critical.
                        </p>
                    </div>
                    <div>
                        <label className={labelClass}>Allowed Algorithms</label>
                        <MultiToggle options={SIGNING_ALLOWED_ALGORITHM_OPTIONS} selected={form.allowedAlgorithms}
                            onChange={(next) => setForm({ ...form, allowedAlgorithms: next })} />
                    </div>
                    <div>
                        <label className={labelClass}>Allowed Cert Profiles</label>
                        <div className="max-h-40 overflow-y-auto bg-gray-50 dark:bg-gray-900 border border-gray-300 dark:border-gray-700 rounded p-2 space-y-1">
                            {certProfiles.length === 0 && <span className="text-xs text-gray-600">No cert profiles available</span>}
                            {certProfiles.map((cp) => {
                                const cpId = cp.id || cp.certProfileId;
                                return (
                                    <label key={cpId} className="flex items-center gap-2 text-sm text-gray-900 dark:text-white cursor-pointer hover:bg-gray-100 dark:bg-gray-800 px-1 rounded">
                                        <input
                                            type="checkbox"
                                            checked={form.allowedCertProfileIds.includes(cpId)}
                                            onChange={(e) => {
                                                const updated = e.target.checked
                                                    ? [...form.allowedCertProfileIds, cpId]
                                                    : form.allowedCertProfileIds.filter((id) => id !== cpId);
                                                setForm({ ...form, allowedCertProfileIds: updated });
                                            }}
                                            className="accent-blue-500"
                                        />
                                        <span>{cp.name}</span>
                                        {cp.isCaProfile && <StatusBadge status="active" label="CA" />}
                                    </label>
                                );
                            })}
                        </div>
                    </div>
                    <button onClick={handleCreate} disabled={creating || !form.name}
                        className="px-4 py-2 text-sm bg-blue-600 text-gray-900 dark:text-white rounded hover:bg-blue-700 disabled:opacity-50 transition-colors">
                        {creating ? 'Creating...' : 'Create'}
                    </button>
                </div>
            )}

            <DataTable<any>
                tableId="signing-profiles"
                title="Signing Profiles"
                rows={profiles}
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
                confirmClass="bg-red-600 hover:bg-red-700"
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
    const [error, setError] = useState<string | null>(null);
    const [showCreate, setShowCreate] = useState(false);
    const [creating, setCreating] = useState(false);
    const [caKeys, setCaKeys] = useState<any[]>([]);
    const [confirmDelete, setConfirmDelete] = useState<any | null>(null);
    const [deleting, setDeleting] = useState(false);
    const [form, setForm] = useState({
        name: '', description: '', sshCaKeyId: '',
        maxValidityHours: '720', allowUserCerts: true, allowHostCerts: false,
        forceCommand: '', sourceAddressRestrictions: '',
        defaultExtensions: ['permit-pty'] as string[],
    });

    const resetForm = () => setForm({
        name: '', description: '', sshCaKeyId: '',
        maxValidityHours: '720', allowUserCerts: true, allowHostCerts: false,
        forceCommand: '', sourceAddressRestrictions: '',
        defaultExtensions: ['permit-pty'],
    });

    const load = () => {
        setLoading(true);
        setError(null);
        apiGet<any>('/api/v1/admin/ssh/profiles/signing')
            .then((data) => setProfiles(Array.isArray(data) ? data : []))
            .catch((err) => setError(err.message))
            .finally(() => setLoading(false));
    };

    useEffect(() => {
        load();
        apiGet<any>('/api/v1/admin/ssh/ca-keys')
            .then((data) => setCaKeys(Array.isArray(data) ? data : []))
            .catch(() => {});
    }, []);

    const handleCreate = async () => {
        setCreating(true);
        try {
            await apiPostWithMfa('/api/v1/admin/ssh/profiles/signing', {
                name: form.name,
                description: form.description || undefined,
                sshCaKeyId: form.sshCaKeyId,
                maxValidityHours: parseInt(form.maxValidityHours) || 720,
                allowUserCerts: form.allowUserCerts,
                allowHostCerts: form.allowHostCerts,
                forceCommand: form.forceCommand || undefined,
                sourceAddressRestrictions: JSON.stringify(form.sourceAddressRestrictions ? form.sourceAddressRestrictions.split(',').map(s => s.trim()).filter(Boolean) : []),
                defaultExtensions: JSON.stringify(form.defaultExtensions),
            }, requireStepUp, StepUpOps.CreateSshProfile);
            setShowCreate(false);
            resetForm();
            load();
        } catch (err: any) {
            showToast('error', err.message || 'Failed to create SSH signing profile');
        } finally {
            setCreating(false);
        }
    };

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
        { key: 'name', header: 'Name', defaultWidth: 220, minWidth: 150, truncate: false, exportValue: (p) => p.name, render: (p) => <span className="text-gray-900 dark:text-white font-medium truncate">{p.name}</span> },
        {
            key: 'allows', header: 'Allows', defaultWidth: 130, truncate: false,
            exportValue: (p) => [p.allowUserCerts ? 'User' : null, p.allowHostCerts ? 'Host' : null].filter(Boolean).join(', '),
            render: (p) => (
                <span className="flex gap-1">
                    {p.allowUserCerts && <StatusBadge status="active" label="User" />}
                    {p.allowHostCerts && <StatusBadge status="pending" label="Host" />}
                    {!p.allowUserCerts && !p.allowHostCerts && <span className="text-xs text-gray-500">-</span>}
                </span>
            ),
        },
        { key: 'caKey', header: 'CA Key', defaultWidth: 170, exportValue: (p) => caKeyName(p.sshCaKeyId), render: (p) => <span className="text-xs text-gray-600 dark:text-gray-400 truncate">{caKeyName(p.sshCaKeyId)}</span> },
        { key: 'validity', header: 'Max Validity', defaultWidth: 120, exportValue: (p) => `${p.maxValidityHours}h`, render: (p) => <span className="text-xs text-gray-600 dark:text-gray-400">{p.maxValidityHours}h</span> },
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
            <div className="py-1"><span className="text-xs text-gray-600 dark:text-gray-400">Default Extensions</span><BadgeList items={p.defaultExtensions} /></div>
            <p className="text-[11px] text-gray-500 pt-3">Open the full page to view all settings or edit.</p>
        </div>
    );

    return (
        <div className="space-y-4">
            <div className="flex items-center justify-between">
                <h3 className="text-sm font-semibold text-gray-900 dark:text-white">SSH Signing Profiles</h3>
                <button onClick={() => setShowCreate(!showCreate)}
                    className="px-4 py-2 text-sm bg-blue-600 text-gray-900 dark:text-white rounded hover:bg-blue-700 transition-colors">
                    {showCreate ? 'Cancel' : 'Create Profile'}
                </button>
            </div>

            {showCreate && (
                <div className="bg-gray-100 dark:bg-gray-800 border border-gray-300 dark:border-gray-700 rounded-lg p-4 space-y-3">
                    <h4 className="text-sm font-semibold text-gray-900 dark:text-white">New SSH Signing Profile</h4>
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                        <div>
                            <label className={labelClass}>Name</label>
                            <input type="text" value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} className={inputClass} placeholder="e.g. Default User Signing" />
                        </div>
                        <div>
                            <label className={labelClass}>Description</label>
                            <input type="text" value={form.description} onChange={(e) => setForm({ ...form, description: e.target.value })} className={inputClass} placeholder="Optional" />
                        </div>
                        <div>
                            <label className={labelClass}>SSH CA Key</label>
                            <select value={form.sshCaKeyId} onChange={(e) => setForm({ ...form, sshCaKeyId: e.target.value })} className={inputClass}>
                                <option value="">-- Select CA Key --</option>
                                {caKeys.map(k => <option key={k.id} value={k.id}>{k.name} ({k.keyType})</option>)}
                            </select>
                        </div>
                        <div>
                            <label className={labelClass}>Max Validity Hours</label>
                            <input type="text" inputMode="numeric" value={form.maxValidityHours} onChange={(e) => setForm({ ...form, maxValidityHours: e.target.value.replace(/\D/g, '') })} className={inputClass} />
                        </div>
                        <div>
                            <label className={labelClass}>Force Command (optional)</label>
                            <input type="text" value={form.forceCommand} onChange={(e) => setForm({ ...form, forceCommand: e.target.value })} className={inputClass} placeholder="e.g. /usr/bin/rsync" />
                        </div>
                        <div>
                            <label className={labelClass}>Source Address Restrictions (comma-separated)</label>
                            <input type="text" value={form.sourceAddressRestrictions} onChange={(e) => setForm({ ...form, sourceAddressRestrictions: e.target.value })} className={inputClass} placeholder="e.g. 10.0.0.0/8, 192.168.1.0/24" />
                        </div>
                    </div>
                    <div className="flex flex-wrap gap-4">
                        <label className="flex items-center gap-2 text-xs text-gray-700 dark:text-gray-300">
                            <input type="checkbox" checked={form.allowUserCerts} onChange={(e) => setForm({ ...form, allowUserCerts: e.target.checked })} className="w-4 h-4 bg-gray-50 dark:bg-gray-900 border-gray-300 dark:border-gray-700 rounded" />
                            Allow User Certs
                        </label>
                        <label className="flex items-center gap-2 text-xs text-gray-700 dark:text-gray-300">
                            <input type="checkbox" checked={form.allowHostCerts} onChange={(e) => setForm({ ...form, allowHostCerts: e.target.checked })} className="w-4 h-4 bg-gray-50 dark:bg-gray-900 border-gray-300 dark:border-gray-700 rounded" />
                            Allow Host Certs
                        </label>
                    </div>
                    <div>
                        <label className={labelClass}>Default Extensions</label>
                        <MultiToggle options={SSH_EXTENSION_OPTIONS} selected={form.defaultExtensions}
                            onChange={(next) => setForm({ ...form, defaultExtensions: next })} />
                    </div>
                    <button onClick={handleCreate} disabled={creating || !form.name || !form.sshCaKeyId}
                        className="px-4 py-2 text-sm bg-blue-600 text-gray-900 dark:text-white rounded hover:bg-blue-700 disabled:opacity-50 transition-colors">
                        {creating ? 'Creating...' : 'Create'}
                    </button>
                </div>
            )}

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
                confirmClass="bg-red-600 hover:bg-red-700"
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
    const [error, setError] = useState<string | null>(null);
    const [showCreate, setShowCreate] = useState(false);
    const [creating, setCreating] = useState(false);
    const [confirmDelete, setConfirmDelete] = useState<any | null>(null);
    const [deleting, setDeleting] = useState(false);
    const [form, setForm] = useState({
        name: '', description: '',
        allowedPrincipalPatterns: '',
        maxPrincipals: '10',
        allowedExtensions: ['permit-pty', 'permit-port-forwarding', 'permit-agent-forwarding', 'permit-X11-forwarding', 'permit-user-rc'] as string[],
        requiredExtensions: [] as string[],
        maxValidityHours: '720',
    });

    const resetForm = () => setForm({
        name: '', description: '',
        allowedPrincipalPatterns: '', maxPrincipals: '10',
        allowedExtensions: ['permit-pty', 'permit-port-forwarding', 'permit-agent-forwarding', 'permit-X11-forwarding', 'permit-user-rc'],
        requiredExtensions: [], maxValidityHours: '720',
    });

    const load = () => {
        setLoading(true);
        setError(null);
        apiGet<any>('/api/v1/admin/ssh/profiles/cert')
            .then((data) => setProfiles(Array.isArray(data) ? data : []))
            .catch((err) => setError(err.message))
            .finally(() => setLoading(false));
    };

    useEffect(() => { load(); }, []);

    const handleCreate = async () => {
        setCreating(true);
        try {
            const patterns = form.allowedPrincipalPatterns.trim()
                ? form.allowedPrincipalPatterns.split('\n').map(s => s.trim()).filter(Boolean)
                : [];
            await apiPostWithMfa('/api/v1/admin/ssh/profiles/cert', {
                name: form.name,
                description: form.description || undefined,
                allowedPrincipalPatterns: JSON.stringify(patterns),
                maxPrincipals: parseInt(form.maxPrincipals) || 10,
                allowedExtensions: JSON.stringify(form.allowedExtensions),
                requiredExtensions: JSON.stringify(form.requiredExtensions),
                maxValidityHours: parseInt(form.maxValidityHours) || 720,
            }, requireStepUp, StepUpOps.CreateSshProfile);
            setShowCreate(false);
            resetForm();
            load();
        } catch (err: any) {
            showToast('error', err.message || 'Failed to create SSH cert profile');
        } finally {
            setCreating(false);
        }
    };

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
        { key: 'name', header: 'Name', defaultWidth: 240, minWidth: 160, truncate: false, exportValue: (p) => p.name, render: (p) => <span className="text-gray-900 dark:text-white font-medium truncate">{p.name}</span> },
        { key: 'maxPrincipals', header: 'Max Principals', defaultWidth: 130, exportValue: (p) => (p.maxPrincipals ?? ''), render: (p) => <span className="text-xs text-gray-600 dark:text-gray-400">{p.maxPrincipals}</span> },
        { key: 'validity', header: 'Max Validity', defaultWidth: 120, exportValue: (p) => `${p.maxValidityHours}h`, render: (p) => <span className="text-xs text-gray-600 dark:text-gray-400">{p.maxValidityHours}h</span> },
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
            <div className="py-1"><span className="text-xs text-gray-600 dark:text-gray-400">Allowed Extensions</span><BadgeList items={p.allowedExtensions} /></div>
            <div className="py-1"><span className="text-xs text-gray-600 dark:text-gray-400">Required Extensions</span><BadgeList items={p.requiredExtensions} /></div>
            <p className="text-[11px] text-gray-500 pt-3">Open the full page to view principal patterns or edit.</p>
        </div>
    );

    return (
        <div className="space-y-4">
            <div className="flex items-center justify-between">
                <h3 className="text-sm font-semibold text-gray-900 dark:text-white">SSH Cert Profiles</h3>
                <button onClick={() => setShowCreate(!showCreate)}
                    className="px-4 py-2 text-sm bg-blue-600 text-gray-900 dark:text-white rounded hover:bg-blue-700 transition-colors">
                    {showCreate ? 'Cancel' : 'Create Profile'}
                </button>
            </div>

            {showCreate && (
                <div className="bg-gray-100 dark:bg-gray-800 border border-gray-300 dark:border-gray-700 rounded-lg p-4 space-y-3">
                    <h4 className="text-sm font-semibold text-gray-900 dark:text-white">New SSH Cert Profile</h4>
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                        <div>
                            <label className={labelClass}>Name</label>
                            <input type="text" value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} className={inputClass} placeholder="e.g. Standard User Cert" />
                        </div>
                        <div>
                            <label className={labelClass}>Description</label>
                            <input type="text" value={form.description} onChange={(e) => setForm({ ...form, description: e.target.value })} className={inputClass} placeholder="Optional" />
                        </div>
                        <div>
                            <label className={labelClass}>Max Principals</label>
                            <input type="text" inputMode="numeric" value={form.maxPrincipals} onChange={(e) => setForm({ ...form, maxPrincipals: e.target.value.replace(/\D/g, '') })} className={inputClass} />
                        </div>
                        <div>
                            <label className={labelClass}>Max Validity Hours</label>
                            <input type="text" inputMode="numeric" value={form.maxValidityHours} onChange={(e) => setForm({ ...form, maxValidityHours: e.target.value.replace(/\D/g, '') })} className={inputClass} />
                        </div>
                    </div>
                    <div>
                        <label className={labelClass}>Allowed Principal Patterns (one regex per line)</label>
                        <textarea rows={3} value={form.allowedPrincipalPatterns}
                            onChange={(e) => setForm({ ...form, allowedPrincipalPatterns: e.target.value })}
                            className={inputClass} placeholder={"^[a-z_][a-z0-9_-]*$\n^admin$"} />
                    </div>
                    <div>
                        <label className={labelClass}>Allowed Extensions</label>
                        <MultiToggle options={SSH_EXTENSION_OPTIONS} selected={form.allowedExtensions}
                            onChange={(next) => setForm({ ...form, allowedExtensions: next })} />
                    </div>
                    <div>
                        <label className={labelClass}>Required Extensions</label>
                        <MultiToggle options={SSH_EXTENSION_OPTIONS} selected={form.requiredExtensions}
                            onChange={(next) => setForm({ ...form, requiredExtensions: next })} />
                    </div>
                    <button onClick={handleCreate} disabled={creating || !form.name}
                        className="px-4 py-2 text-sm bg-blue-600 text-gray-900 dark:text-white rounded hover:bg-blue-700 disabled:opacity-50 transition-colors">
                        {creating ? 'Creating...' : 'Create'}
                    </button>
                </div>
            )}

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
                confirmClass="bg-red-600 hover:bg-red-700"
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
    const [error, setError] = useState<string | null>(null);
    const [showCreate, setShowCreate] = useState(false);
    const [creating, setCreating] = useState(false);
    const [signingProfiles, setSigningProfiles] = useState<any[]>([]);
    const [certProfiles, setCertProfiles] = useState<any[]>([]);
    const [authorities, setAuthorities] = useState<any[]>([]);
    const [confirmDelete, setConfirmDelete] = useState<any | null>(null);
    const [deleting, setDeleting] = useState(false);
    const [form, setForm] = useState({
        name: '', description: '',
        allowedSshSigningProfileIds: [] as string[],
        allowedSshCertProfileIds: [] as string[],
        requireApproval: false,
        maxValidityHours: '720',
        certificateAuthorityId: '',
    });

    const resetForm = () => setForm({
        name: '', description: '',
        allowedSshSigningProfileIds: [], allowedSshCertProfileIds: [],
        requireApproval: false, maxValidityHours: '720', certificateAuthorityId: '',
    });

    const load = () => {
        setLoading(true);
        setError(null);
        apiGet<any>('/api/v1/admin/ssh/profiles/request')
            .then((data) => setProfiles(Array.isArray(data) ? data : []))
            .catch((err) => setError(err.message))
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

    const handleCreate = async () => {
        setCreating(true);
        try {
            await apiPostWithMfa('/api/v1/admin/ssh/profiles/request', {
                name: form.name,
                description: form.description || undefined,
                allowedSshSigningProfileIds: JSON.stringify(form.allowedSshSigningProfileIds),
                allowedSshCertProfileIds: JSON.stringify(form.allowedSshCertProfileIds),
                requireApproval: form.requireApproval,
                maxValidityHours: parseInt(form.maxValidityHours) || 720,
                certificateAuthorityId: form.certificateAuthorityId || undefined,
            }, requireStepUp, StepUpOps.CreateSshProfile);
            setShowCreate(false);
            resetForm();
            load();
        } catch (err: any) {
            showToast('error', err.message || 'Failed to create SSH request profile');
        } finally {
            setCreating(false);
        }
    };

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
        { key: 'name', header: 'Name', defaultWidth: 220, minWidth: 150, truncate: false, exportValue: (p) => p.name, render: (p) => <span className="text-gray-900 dark:text-white font-medium truncate">{p.name}</span> },
        { key: 'approval', header: 'Approval', defaultWidth: 110, truncate: false, exportValue: (p) => (p.requireApproval ? 'Required' : 'Auto'), render: (p) => <StatusBadge status={p.requireApproval ? 'pending' : 'enabled'} label={p.requireApproval ? 'Required' : 'Auto'} /> },
        { key: 'caScope', header: 'CA Scope', defaultWidth: 170, exportValue: (p) => (p.certificateAuthorityId ? caName(p.certificateAuthorityId) : 'Any CA'), render: (p) => <span className="text-xs text-gray-600 dark:text-gray-400 truncate">{p.certificateAuthorityId ? caName(p.certificateAuthorityId) : 'Any CA'}</span> },
        { key: 'validity', header: 'Max Validity', defaultWidth: 120, exportValue: (p) => `${p.maxValidityHours}h`, render: (p) => <span className="text-xs text-gray-600 dark:text-gray-400">{p.maxValidityHours}h</span> },
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
                <p className="text-[11px] text-gray-500 pt-3">Open the full page to edit.</p>
            </div>
        );
    };

    return (
        <div className="space-y-4">
            <div className="flex items-center justify-between">
                <h3 className="text-sm font-semibold text-gray-900 dark:text-white">SSH Request Profiles</h3>
                <button onClick={() => setShowCreate(!showCreate)}
                    className="px-4 py-2 text-sm bg-blue-600 text-gray-900 dark:text-white rounded hover:bg-blue-700 transition-colors">
                    {showCreate ? 'Cancel' : 'Create Profile'}
                </button>
            </div>

            {showCreate && (
                <div className="bg-gray-100 dark:bg-gray-800 border border-gray-300 dark:border-gray-700 rounded-lg p-4 space-y-3">
                    <h4 className="text-sm font-semibold text-gray-900 dark:text-white">New SSH Request Profile</h4>
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                        <div>
                            <label className={labelClass}>Name</label>
                            <input type="text" value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} className={inputClass} placeholder="e.g. Developer Access" />
                        </div>
                        <div>
                            <label className={labelClass}>Description</label>
                            <input type="text" value={form.description} onChange={(e) => setForm({ ...form, description: e.target.value })} className={inputClass} placeholder="Optional" />
                        </div>
                        <div>
                            <label className={labelClass}>Max Validity Hours</label>
                            <input type="text" inputMode="numeric" value={form.maxValidityHours} onChange={(e) => setForm({ ...form, maxValidityHours: e.target.value.replace(/\D/g, '') })} className={inputClass} />
                        </div>
                        <div>
                            <label className={labelClass}>CA Scope</label>
                            <select value={form.certificateAuthorityId} onChange={(e) => setForm({ ...form, certificateAuthorityId: e.target.value })} className={inputClass}>
                                <option value="">-- Any CA --</option>
                                {authorities.map((a) => (
                                    <option key={caRowId(a)} value={caRowId(a)}>
                                        {caDisplayName(a)}
                                    </option>
                                ))}
                            </select>
                        </div>
                    </div>
                    <div className="flex flex-wrap gap-4">
                        <label className="flex items-center gap-2 text-xs text-gray-700 dark:text-gray-300">
                            <input type="checkbox" checked={form.requireApproval} onChange={(e) => setForm({ ...form, requireApproval: e.target.checked })} className="w-4 h-4 bg-gray-50 dark:bg-gray-900 border-gray-300 dark:border-gray-700 rounded" />
                            Require Approval
                        </label>
                    </div>
                    <div>
                        <label className={labelClass}>Allowed SSH Signing Profiles</label>
                        <div className="max-h-40 overflow-y-auto bg-gray-50 dark:bg-gray-900 border border-gray-300 dark:border-gray-700 rounded p-2 space-y-1">
                            {signingProfiles.length === 0 && <span className="text-xs text-gray-600">No signing profiles available</span>}
                            {signingProfiles.map(sp => (
                                <label key={sp.id} className="flex items-center gap-2 text-sm text-gray-900 dark:text-white cursor-pointer hover:bg-gray-100 dark:bg-gray-800 px-1 rounded">
                                    <input type="checkbox"
                                        checked={form.allowedSshSigningProfileIds.includes(sp.id)}
                                        onChange={(e) => setForm({
                                            ...form,
                                            allowedSshSigningProfileIds: e.target.checked
                                                ? [...form.allowedSshSigningProfileIds, sp.id]
                                                : form.allowedSshSigningProfileIds.filter(id => id !== sp.id)
                                        })}
                                        className="accent-blue-500" />
                                    <span>{sp.name}</span>
                                </label>
                            ))}
                        </div>
                    </div>
                    <div>
                        <label className={labelClass}>Allowed SSH Cert Profiles</label>
                        <div className="max-h-40 overflow-y-auto bg-gray-50 dark:bg-gray-900 border border-gray-300 dark:border-gray-700 rounded p-2 space-y-1">
                            {certProfiles.length === 0 && <span className="text-xs text-gray-600">No cert profiles available</span>}
                            {certProfiles.map(cp => (
                                <label key={cp.id} className="flex items-center gap-2 text-sm text-gray-900 dark:text-white cursor-pointer hover:bg-gray-100 dark:bg-gray-800 px-1 rounded">
                                    <input type="checkbox"
                                        checked={form.allowedSshCertProfileIds.includes(cp.id)}
                                        onChange={(e) => setForm({
                                            ...form,
                                            allowedSshCertProfileIds: e.target.checked
                                                ? [...form.allowedSshCertProfileIds, cp.id]
                                                : form.allowedSshCertProfileIds.filter(id => id !== cp.id)
                                        })}
                                        className="accent-blue-500" />
                                    <span>{cp.name}</span>
                                </label>
                            ))}
                        </div>
                    </div>
                    <button onClick={handleCreate} disabled={creating || !form.name}
                        className="px-4 py-2 text-sm bg-blue-600 text-gray-900 dark:text-white rounded hover:bg-blue-700 disabled:opacity-50 transition-colors">
                        {creating ? 'Creating...' : 'Create'}
                    </button>
                </div>
            )}

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
                confirmClass="bg-red-600 hover:bg-red-700"
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
            <h1 className="text-2xl font-bold text-gray-900 dark:text-white">Profile Management</h1>

            <div className="flex gap-1 border-b border-gray-300 dark:border-gray-700 overflow-x-auto">
                {TABS.map((tab) => (
                    <button key={tab} onClick={() => setActiveTab(tab)}
                        className={`px-4 py-2 text-sm font-medium transition-colors border-b-2 whitespace-nowrap ${activeTab === tab
                            ? 'text-blue-800 dark:text-blue-400 border-blue-400'
                            : 'text-gray-600 dark:text-gray-400 border-transparent hover:text-gray-700 dark:text-gray-300'}`}>
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
