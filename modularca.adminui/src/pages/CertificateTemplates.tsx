import React, { useState, useEffect } from 'react';
import { apiGet, apiPost, apiPostWithMfa, apiDelete, apiDeleteWithMfa } from '../api/client';
import { recordTableProps } from '../components/RecordDrawer';
import type { RecordDescriptor } from '@shared/records';
import { DataTable, type DataTableColumn } from '@shared/components/DataTable';
import { useScope } from '../context/ScopeContext';
import { useStepUp } from '../components/StepUpMfaContext';
import { useToast } from '@shared/context/ToastContext';
import { StatusBadge } from '@shared/components/cards/StatusBadge';
import { DetailField } from '@shared/components/cards/DetailField';
import ConfirmModal from '../components/ConfirmModal';
import { StepUpOps } from '@shared/generated';
import { inputClass, labelClass } from '@shared/components/forms';


const TEMPLATE_TABS = ['X.509 CA', 'SSH CA'] as const;
type TemplateTab = typeof TEMPLATE_TABS[number];

interface CertificateTemplate {
    id: string;
    name: string;
    description?: string;
    caId: string;
    caName?: string;
    requestProfileId?: string;
    requestProfileName?: string;
    certProfileId: string;
    certProfileName?: string;
    signingProfileId: string;
    signingProfileName?: string;
    isEnabled: boolean;
    createdAt: string;
    offeredToWindows?: boolean;
    msaeTemplateOid?: string | null;
    msaeMajorVersion?: number;
    msaeMinorVersion?: number;
    msaeMachineType?: boolean;
}

interface DropdownOption {
    id: string;
    name: string;
}

/* ─── X.509 CA Templates Tab ─── */
const X509TemplatesTab: React.FC = () => {
    const { showToast } = useToast();
    // These endpoints carry [RequireStepUp]; the plain helpers never attach X-MFA-Token.
    const { requireStepUp } = useStepUp();
    const [templates, setTemplates] = useState<CertificateTemplate[]>([]);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState<string | null>(null);
    const [showCreate, setShowCreate] = useState(false);
    const [creating, setCreating] = useState(false);

    const [authorities, setAuthorities] = useState<DropdownOption[]>([]);
    const [requestProfiles, setRequestProfiles] = useState<DropdownOption[]>([]);
    const [certProfiles, setCertProfiles] = useState<DropdownOption[]>([]);
    const [signingProfiles, setSigningProfiles] = useState<DropdownOption[]>([]);

    // Confirm modal state
    const [confirmAction, setConfirmAction] = useState<{ action: () => Promise<void>; title: string; message: string } | null>(null);
    const [confirmLoading, setConfirmLoading] = useState(false);

    const emptyForm = {
        name: '', description: '', caId: '', requestProfileId: '',
        certProfileId: '', signingProfileId: '', isEnabled: true,
        // Windows autoenrollment (MSAE): offer the template through the policy service.
        offerToWindows: false, msaeTemplateOid: '', msaeMachineType: true,
    };
    const [form, setForm] = useState(emptyForm);

    const resetForm = () => setForm(emptyForm);

    const extractList = (data: any): any[] =>
        Array.isArray(data) ? data : (data.items || data.templates || data.profiles || data.authorities || []);

    const { caId: scopeCaId } = useScope();

    const load = () => {
        setLoading(true);
        setError(null);
        apiGet<any>(`/api/v1/admin/templates${scopeCaId ? `?caId=${encodeURIComponent(scopeCaId)}` : ''}`)
            .then((data) => setTemplates(extractList(data)))
            .catch((err) => setError(err.message))
            .finally(() => setLoading(false));
    };

    // The scope narrows the list; a new template defaults to the scoped CA.
    useEffect(() => {
        load();
        if (scopeCaId) setForm((f) => ({ ...f, caId: f.caId || scopeCaId }));
    }, [scopeCaId]); // eslint-disable-line react-hooks/exhaustive-deps

    useEffect(() => {
        apiGet<any>('/api/v1/admin/authorities')
            .then((data) => {
                const list = extractList(data);
                setAuthorities(list.map((a: any) => ({ id: a.id || a.caId, name: a.name || a.commonName || a.id })));
            }).catch(() => {});
        apiGet<any>('/api/v1/admin/request-profiles')
            .then((data) => {
                const list = extractList(data);
                setRequestProfiles(list.map((p: any) => ({ id: p.id, name: p.name || p.id })));
            }).catch(() => {});
        apiGet<any>('/api/v1/admin/cert-profiles')
            .then((data) => {
                const list = extractList(data);
                setCertProfiles(list.map((p: any) => ({ id: p.id || p.certProfileId, name: p.name || p.id })));
            }).catch(() => {});
        apiGet<any>('/api/v1/admin/signing-profiles')
            .then((data) => {
                const list = extractList(data);
                setSigningProfiles(list.map((p: any) => ({ id: p.id || p.signingProfileId, name: p.name || p.id })));
            }).catch(() => {});
    }, []);

    const handleCreate = async () => {
        setCreating(true);
        try {
            const body: any = {
                name: form.name, description: form.description || undefined,
                caId: form.caId, certProfileId: form.certProfileId,
                signingProfileId: form.signingProfileId, isEnabled: form.isEnabled,
                offerToWindows: form.offerToWindows, msaeMachineType: form.msaeMachineType,
            };
            if (form.requestProfileId) body.requestProfileId = form.requestProfileId;
            if (form.offerToWindows && form.msaeTemplateOid.trim()) body.msaeTemplateOid = form.msaeTemplateOid.trim();
            await apiPostWithMfa('/api/v1/admin/templates', body, requireStepUp, StepUpOps.CreateCertificateTemplate);
            setShowCreate(false);
            resetForm();
            load();
        } catch (err: any) {
            showToast('error', err.message || 'Failed to create template');
        } finally {
            setCreating(false);
        }
    };

    /// <summary>
    /// Prompts for confirmation before deleting an X.509 template via the ConfirmModal.
    /// </summary>
    const handleDelete = (template: CertificateTemplate) => {
        setConfirmAction({
            title: 'Delete Template',
            message: `Are you sure you want to delete "${template.name}"? This action cannot be undone.`,
            action: async () => {
                await apiDeleteWithMfa(`/api/v1/admin/templates/${template.id}`, requireStepUp, StepUpOps.DeleteCertificateTemplate, template.id);
                load();
            },
        });
    };

    const record: RecordDescriptor<CertificateTemplate> = {
        kind: 'certificate-template',
        key: (t) => t.id,
        title: (t) => t.name,
        status: (t) => ({ label: t.isEnabled ? 'Enabled' : 'Disabled', tone: t.isEnabled ? 'ok' : 'neutral' }),
        columns: [
            { key: 'name', header: 'Name', defaultWidth: 240, sortable: true, exportValue: (t) => t.name, render: (t) => (
                <span className="min-w-0">
                    <span className="text-gray-900 dark:text-white font-medium truncate block">{t.name}</span>
                    {t.description && <span className="block text-xs text-gray-600 truncate">{t.description}</span>}
                </span>
            ) },
            { key: 'ca', header: 'CA Name', defaultWidth: 160, sortable: true, exportValue: (t) => t.caName || t.caId, render: (t) => <span className="text-gray-700 dark:text-gray-300 text-xs truncate">{t.caName || t.caId}</span> },
            { key: 'certProfile', header: 'Cert Profile', defaultWidth: 160, sortable: true, exportValue: (t) => t.certProfileName || t.certProfileId, render: (t) => <span className="text-gray-700 dark:text-gray-300 text-xs truncate">{t.certProfileName || t.certProfileId}</span> },
            { key: 'signingProfile', header: 'Signing Profile', defaultWidth: 160, sortable: true, exportValue: (t) => t.signingProfileName || t.signingProfileId, render: (t) => <span className="text-gray-700 dark:text-gray-300 text-xs truncate">{t.signingProfileName || t.signingProfileId}</span> },
            { key: 'windows', header: 'Windows', defaultWidth: 110, truncate: false, sortable: true, sortValue: (t) => !!t.offeredToWindows, exportValue: (t) => (t.offeredToWindows ? (t.msaeMachineType ? 'Computer' : 'User') : ''), render: (t) => t.offeredToWindows ? <StatusBadge status="active" label={t.msaeMachineType ? 'Computer' : 'User'} /> : <span className="text-gray-500">-</span> },
            { key: 'enabled', header: 'Enabled', defaultWidth: 110, truncate: false, sortable: true, sortValue: (t) => !!t.isEnabled, exportValue: (t) => (t.isEnabled ? 'Enabled' : 'Disabled'), render: (t) => <StatusBadge status={t.isEnabled ? 'enabled' : 'disabled'} label={t.isEnabled ? 'Enabled' : 'Disabled'} /> },
        ],
        sections: [
            { fields: [
                { label: 'ID', value: (t) => t.id, mono: true, copyable: true },
                { label: 'Description', value: (t) => t.description },
                { label: 'CA', value: (t) => t.caName || t.caId },
                { label: 'Created', value: (t) => (t.createdAt ? new Date(t.createdAt).toLocaleString() : null) },
            ] },
            { title: 'Profiles', fields: [
                { label: 'Request Profile', value: (t) => t.requestProfileName || t.requestProfileId || 'None' },
                { label: 'Cert Profile', value: (t) => t.certProfileName || t.certProfileId },
                { label: 'Signing Profile', value: (t) => t.signingProfileName || t.signingProfileId },
            ] },
            { title: 'Windows autoenrollment', fields: [
                { label: 'Offered', value: (t) => (t.offeredToWindows ? (t.msaeMachineType ? 'Yes, computer template' : 'Yes, user template') : 'No') },
                { label: 'Template OID', value: (t) => (t.offeredToWindows ? t.msaeTemplateOid : null), mono: true, copyable: true },
                { label: 'Template Version', value: (t) => (t.offeredToWindows ? `${t.msaeMajorVersion ?? 100}.${t.msaeMinorVersion ?? 0}` : null) },
            ] },
        ],
        audit: { tab: 'General', target: (t) => ({ type: 'CertificateTemplate', id: t.id }) },
        actions: [{ label: 'Delete', tone: 'danger', run: (t) => { handleDelete(t); } }],
    };

    return (
        <div className="space-y-4">
            <div className="flex items-center justify-between">
                <h3 className="text-sm font-semibold text-gray-900 dark:text-white">X.509 Templates</h3>
                <button onClick={() => setShowCreate(!showCreate)}
                    className="px-4 py-2 text-sm bg-blue-600 text-gray-900 dark:text-white rounded hover:bg-blue-700 transition-colors">
                    {showCreate ? 'Cancel' : 'Create Template'}
                </button>
            </div>

            {showCreate && (
                <div className="bg-gray-100 dark:bg-gray-800 border border-gray-300 dark:border-gray-700 rounded-lg p-4 space-y-4">
                    <h4 className="text-sm font-semibold text-gray-900 dark:text-white">New Certificate Template</h4>
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                        <div>
                            <label className={labelClass}>Name</label>
                            <input type="text" value={form.name}
                                onChange={(e) => setForm({ ...form, name: e.target.value })}
                                className={inputClass} placeholder="e.g. Standard TLS Template" />
                        </div>
                        <div>
                            <label className={labelClass}>Description</label>
                            <input type="text" value={form.description}
                                onChange={(e) => setForm({ ...form, description: e.target.value })}
                                className={inputClass} placeholder="Optional description" />
                        </div>
                        <div>
                            <label className={labelClass}>CA</label>
                            <select value={form.caId} onChange={(e) => setForm({ ...form, caId: e.target.value })} className={inputClass}>
                                <option value="">-- Select CA --</option>
                                {authorities.map((a) => <option key={a.id} value={a.id}>{a.name}</option>)}
                            </select>
                        </div>
                        <div>
                            <label className={labelClass}>Request Profile (optional)</label>
                            <select value={form.requestProfileId} onChange={(e) => setForm({ ...form, requestProfileId: e.target.value })} className={inputClass}>
                                <option value="">-- None --</option>
                                {requestProfiles.map((p) => <option key={p.id} value={p.id}>{p.name}</option>)}
                            </select>
                        </div>
                        <div>
                            <label className={labelClass}>Cert Profile</label>
                            <select value={form.certProfileId} onChange={(e) => setForm({ ...form, certProfileId: e.target.value })} className={inputClass}>
                                <option value="">-- Select Cert Profile --</option>
                                {certProfiles.map((p) => <option key={p.id} value={p.id}>{p.name}</option>)}
                            </select>
                        </div>
                        <div>
                            <label className={labelClass}>Signing Profile</label>
                            <select value={form.signingProfileId} onChange={(e) => setForm({ ...form, signingProfileId: e.target.value })} className={inputClass}>
                                <option value="">-- Select Signing Profile --</option>
                                {signingProfiles.map((p) => <option key={p.id} value={p.id}>{p.name}</option>)}
                            </select>
                        </div>
                    </div>
                    <div className="flex flex-wrap gap-4">
                        <label className="flex items-center gap-2 text-xs text-gray-700 dark:text-gray-300">
                            <input type="checkbox" checked={form.isEnabled}
                                onChange={(e) => setForm({ ...form, isEnabled: e.target.checked })}
                                className="w-4 h-4 bg-gray-50 dark:bg-gray-900 border-gray-300 dark:border-gray-700 rounded" />
                            Enabled
                        </label>
                        <label className="flex items-center gap-2 text-xs text-gray-700 dark:text-gray-300">
                            <input type="checkbox" checked={form.offerToWindows}
                                onChange={(e) => setForm({ ...form, offerToWindows: e.target.checked })}
                                className="w-4 h-4 bg-gray-50 dark:bg-gray-900 border-gray-300 dark:border-gray-700 rounded" />
                            Offer to Windows clients (MSAE)
                        </label>
                        {form.offerToWindows && (
                            <label className="flex items-center gap-2 text-xs text-gray-700 dark:text-gray-300">
                                <input type="checkbox" checked={form.msaeMachineType}
                                    onChange={(e) => setForm({ ...form, msaeMachineType: e.target.checked })}
                                    className="w-4 h-4 bg-gray-50 dark:bg-gray-900 border-gray-300 dark:border-gray-700 rounded" />
                                Computer template (uncheck for a user template)
                            </label>
                        )}
                    </div>
                    {form.offerToWindows && (
                        <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                            <div>
                                <label className={labelClass}>Template OID (optional)</label>
                                <input type="text" value={form.msaeTemplateOid}
                                    onChange={(e) => setForm({ ...form, msaeTemplateOid: e.target.value })}
                                    className={inputClass} placeholder="Generated if blank; set to keep an AD CS template's OID" />
                            </div>
                        </div>
                    )}
                    <button onClick={handleCreate}
                        disabled={creating || !form.name || !form.caId || !form.certProfileId || !form.signingProfileId}
                        className="px-4 py-2 text-sm bg-blue-600 text-gray-900 dark:text-white rounded hover:bg-blue-700 disabled:opacity-50 transition-colors">
                        {creating ? 'Creating...' : 'Create Template'}
                    </button>
                </div>
            )}

            <div className="bg-gray-100 dark:bg-gray-800 border border-gray-300 dark:border-gray-700 rounded-lg overflow-x-auto">
                {loading && <div className="p-4 text-sm text-gray-600 dark:text-gray-400 text-center">Loading...</div>}
                {error && <div className="p-4 text-sm text-red-800 dark:text-red-400 text-center">{error}</div>}
                {!loading && !error && templates.length === 0 && (
                    <div className="p-4 text-sm text-gray-600 text-center">No certificate templates found</div>
                )}
                {!loading && !error && templates.length > 0 && (
                    <DataTable<CertificateTemplate>
                        tableId="templates-x509"
                        title="Templates"
                        rows={templates}
                        empty="No templates"
                        sort={{ key: 'name', dir: 'asc' }}
                        {...recordTableProps(record)}
                    />
                )}
            </div>


            <ConfirmModal
                isOpen={!!confirmAction}
                title={confirmAction?.title || ''}
                message={confirmAction?.message || ''}
                confirmLabel="Delete"
                loading={confirmLoading}
                onConfirm={async () => {
                    if (!confirmAction) return;
                    setConfirmLoading(true);
                    try {
                        await confirmAction.action();
                    } catch (err: any) {
                        showToast('error', err.message || 'Operation failed');
                    } finally {
                        setConfirmLoading(false);
                        setConfirmAction(null);
                    }
                }}
                onCancel={() => setConfirmAction(null)}
            />
        </div>
    );
};

/* ─── SSH CA Templates Tab ─── */
const SshTemplatesTab: React.FC = () => {
    const { showToast } = useToast();
    const [templates, setTemplates] = useState<any[]>([]);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState<string | null>(null);
    const [showCreate, setShowCreate] = useState(false);
    const [creating, setCreating] = useState(false);

    const [caKeys, setCaKeys] = useState<DropdownOption[]>([]);
    const [signingProfiles, setSigningProfiles] = useState<DropdownOption[]>([]);
    const [certProfiles, setCertProfiles] = useState<DropdownOption[]>([]);
    const [requestProfiles, setRequestProfiles] = useState<DropdownOption[]>([]);

    // Confirm modal state
    const [confirmAction, setConfirmAction] = useState<{ action: () => Promise<void>; title: string; message: string } | null>(null);
    const [confirmLoading, setConfirmLoading] = useState(false);

    const [form, setForm] = useState({
        name: '', description: '', sshCaKeyId: '',
        sshSigningProfileId: '', sshCertProfileId: '',
        sshRequestProfileId: '', isEnabled: true,
    });

    const resetForm = () => setForm({
        name: '', description: '', sshCaKeyId: '',
        sshSigningProfileId: '', sshCertProfileId: '',
        sshRequestProfileId: '', isEnabled: true,
    });

    const load = () => {
        setLoading(true);
        setError(null);
        apiGet<any>('/api/v1/admin/ssh/templates')
            .then((data) => setTemplates(Array.isArray(data) ? data : []))
            .catch((err) => setError(err.message))
            .finally(() => setLoading(false));
    };

    useEffect(() => {
        load();
        apiGet<any>('/api/v1/admin/ssh/ca-keys')
            .then((data) => {
                const list = Array.isArray(data) ? data : [];
                setCaKeys(list.map((k: any) => ({ id: k.id, name: k.name || k.id })));
            }).catch(() => {});
        apiGet<any>('/api/v1/admin/ssh/profiles/signing')
            .then((data) => {
                const list = Array.isArray(data) ? data : [];
                setSigningProfiles(list.map((p: any) => ({ id: p.id, name: p.name || p.id })));
            }).catch(() => {});
        apiGet<any>('/api/v1/admin/ssh/profiles/cert')
            .then((data) => {
                const list = Array.isArray(data) ? data : [];
                setCertProfiles(list.map((p: any) => ({ id: p.id, name: p.name || p.id })));
            }).catch(() => {});
        apiGet<any>('/api/v1/admin/ssh/profiles/request')
            .then((data) => {
                const list = Array.isArray(data) ? data : [];
                setRequestProfiles(list.map((p: any) => ({ id: p.id, name: p.name || p.id })));
            }).catch(() => {});
    }, []);

    const handleCreate = async () => {
        setCreating(true);
        try {
            const body: any = {
                name: form.name, description: form.description || undefined,
                sshCaKeyId: form.sshCaKeyId, sshSigningProfileId: form.sshSigningProfileId,
                sshCertProfileId: form.sshCertProfileId, isEnabled: form.isEnabled,
            };
            if (form.sshRequestProfileId) body.sshRequestProfileId = form.sshRequestProfileId;
            await apiPost('/api/v1/admin/ssh/templates', body);
            setShowCreate(false);
            resetForm();
            load();
        } catch (err: any) {
            showToast('error', err.message || 'Failed to create SSH template');
        } finally {
            setCreating(false);
        }
    };

    /// <summary>
    /// Prompts for confirmation before deleting an SSH template via the ConfirmModal.
    /// </summary>
    const handleDelete = (template: any) => {
        setConfirmAction({
            title: 'Delete SSH Template',
            message: `Are you sure you want to delete "${template.name}"? This action cannot be undone.`,
            action: async () => {
                await apiDelete(`/api/v1/admin/ssh/templates/${template.id}`);
                load();
            },
        });
    };

    const record: RecordDescriptor<any> = {
        kind: 'ssh-template',
        key: (t) => t.id,
        title: (t) => t.name,
        status: (t) => ({ label: t.isEnabled ? 'Enabled' : 'Disabled', tone: t.isEnabled ? 'ok' : 'neutral' }),
        columns: [
            { key: 'name', header: 'Name', defaultWidth: 240, sortable: true, exportValue: (t: any) => t.name, render: (t: any) => (
                <span className="min-w-0">
                    <span className="text-gray-900 dark:text-white font-medium truncate block">{t.name}</span>
                    {t.description && <span className="block text-xs text-gray-600 truncate">{t.description}</span>}
                </span>
            ) },
            { key: 'caKey', header: 'CA Key', defaultWidth: 160, sortable: true, exportValue: (t: any) => t.sshCaKeyName || t.sshCaKeyId, render: (t: any) => <span className="text-gray-700 dark:text-gray-300 text-xs truncate">{t.sshCaKeyName || t.sshCaKeyId}</span> },
            { key: 'signingProfile', header: 'Signing Profile', defaultWidth: 160, sortable: true, exportValue: (t: any) => t.sshSigningProfileName || t.sshSigningProfileId, render: (t: any) => <span className="text-gray-700 dark:text-gray-300 text-xs truncate">{t.sshSigningProfileName || t.sshSigningProfileId}</span> },
            { key: 'certProfile', header: 'Cert Profile', defaultWidth: 160, sortable: true, exportValue: (t: any) => t.sshCertProfileName || t.sshCertProfileId, render: (t: any) => <span className="text-gray-700 dark:text-gray-300 text-xs truncate">{t.sshCertProfileName || t.sshCertProfileId}</span> },
            { key: 'enabled', header: 'Enabled', defaultWidth: 110, truncate: false, sortable: true, sortValue: (t: any) => !!t.isEnabled, exportValue: (t: any) => (t.isEnabled ? 'Enabled' : 'Disabled'), render: (t: any) => <StatusBadge status={t.isEnabled ? 'enabled' : 'disabled'} label={t.isEnabled ? 'Enabled' : 'Disabled'} /> },
        ],
        sections: [
            { fields: [
                { label: 'ID', value: (t) => t.id, mono: true, copyable: true },
                { label: 'Description', value: (t) => t.description },
                { label: 'SSH CA Key', value: (t) => t.sshCaKeyName || t.sshCaKeyId },
                { label: 'Created', value: (t) => (t.createdAt ? new Date(t.createdAt).toLocaleString() : null) },
            ] },
            { title: 'Profiles', fields: [
                { label: 'Signing Profile', value: (t) => t.sshSigningProfileName || t.sshSigningProfileId },
                { label: 'Cert Profile', value: (t) => t.sshCertProfileName || t.sshCertProfileId },
                { label: 'Request Profile', value: (t) => t.sshRequestProfileName || t.sshRequestProfileId || 'None' },
            ] },
        ],
        audit: { tab: 'General', target: (t) => ({ type: 'SshTemplate', id: t.id }) },
        actions: [{ label: 'Delete', tone: 'danger', run: (t) => { handleDelete(t); } }],
    };

    return (
        <div className="space-y-4">
            <div className="flex items-center justify-between">
                <h3 className="text-sm font-semibold text-gray-900 dark:text-white">SSH Templates</h3>
                <button onClick={() => setShowCreate(!showCreate)}
                    className="px-4 py-2 text-sm bg-blue-600 text-gray-900 dark:text-white rounded hover:bg-blue-700 transition-colors">
                    {showCreate ? 'Cancel' : 'Create Template'}
                </button>
            </div>

            {showCreate && (
                <div className="bg-gray-100 dark:bg-gray-800 border border-gray-300 dark:border-gray-700 rounded-lg p-4 space-y-4">
                    <h4 className="text-sm font-semibold text-gray-900 dark:text-white">New SSH Certificate Template</h4>
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                        <div>
                            <label className={labelClass}>Name</label>
                            <input type="text" value={form.name}
                                onChange={(e) => setForm({ ...form, name: e.target.value })}
                                className={inputClass} placeholder="e.g. Standard User SSH" />
                        </div>
                        <div>
                            <label className={labelClass}>Description</label>
                            <input type="text" value={form.description}
                                onChange={(e) => setForm({ ...form, description: e.target.value })}
                                className={inputClass} placeholder="Optional description" />
                        </div>
                        <div>
                            <label className={labelClass}>SSH CA Key</label>
                            <select value={form.sshCaKeyId} onChange={(e) => setForm({ ...form, sshCaKeyId: e.target.value })} className={inputClass}>
                                <option value="">-- Select CA Key --</option>
                                {caKeys.map((k) => <option key={k.id} value={k.id}>{k.name}</option>)}
                            </select>
                        </div>
                        <div>
                            <label className={labelClass}>Signing Profile</label>
                            <select value={form.sshSigningProfileId} onChange={(e) => setForm({ ...form, sshSigningProfileId: e.target.value })} className={inputClass}>
                                <option value="">-- Select Signing Profile --</option>
                                {signingProfiles.map((p) => <option key={p.id} value={p.id}>{p.name}</option>)}
                            </select>
                        </div>
                        <div>
                            <label className={labelClass}>Cert Profile</label>
                            <select value={form.sshCertProfileId} onChange={(e) => setForm({ ...form, sshCertProfileId: e.target.value })} className={inputClass}>
                                <option value="">-- Select Cert Profile --</option>
                                {certProfiles.map((p) => <option key={p.id} value={p.id}>{p.name}</option>)}
                            </select>
                        </div>
                        <div>
                            <label className={labelClass}>Request Profile (optional)</label>
                            <select value={form.sshRequestProfileId} onChange={(e) => setForm({ ...form, sshRequestProfileId: e.target.value })} className={inputClass}>
                                <option value="">-- None --</option>
                                {requestProfiles.map((p) => <option key={p.id} value={p.id}>{p.name}</option>)}
                            </select>
                        </div>
                    </div>
                    <div className="flex flex-wrap gap-4">
                        <label className="flex items-center gap-2 text-xs text-gray-700 dark:text-gray-300">
                            <input type="checkbox" checked={form.isEnabled}
                                onChange={(e) => setForm({ ...form, isEnabled: e.target.checked })}
                                className="w-4 h-4 bg-gray-50 dark:bg-gray-900 border-gray-300 dark:border-gray-700 rounded" />
                            Enabled
                        </label>
                    </div>
                    <button onClick={handleCreate}
                        disabled={creating || !form.name || !form.sshCaKeyId || !form.sshSigningProfileId || !form.sshCertProfileId}
                        className="px-4 py-2 text-sm bg-blue-600 text-gray-900 dark:text-white rounded hover:bg-blue-700 disabled:opacity-50 transition-colors">
                        {creating ? 'Creating...' : 'Create Template'}
                    </button>
                </div>
            )}

            <div className="bg-gray-100 dark:bg-gray-800 border border-gray-300 dark:border-gray-700 rounded-lg overflow-x-auto">
                {loading && <div className="p-4 text-sm text-gray-600 dark:text-gray-400 text-center">Loading...</div>}
                {error && <div className="p-4 text-sm text-red-800 dark:text-red-400 text-center">{error}</div>}
                {!loading && !error && templates.length === 0 && (
                    <div className="p-4 text-sm text-gray-600 text-center">No SSH certificate templates found</div>
                )}
                {!loading && !error && templates.length > 0 && (
                    <DataTable<any>
                        tableId="templates-ssh"
                        title="SSH Templates"
                        rows={templates}
                        empty="No SSH templates"
                        sort={{ key: 'name', dir: 'asc' }}
                        {...recordTableProps(record)}
                    />
                )}
            </div>


            <ConfirmModal
                isOpen={!!confirmAction}
                title={confirmAction?.title || ''}
                message={confirmAction?.message || ''}
                confirmLabel="Delete"
                loading={confirmLoading}
                onConfirm={async () => {
                    if (!confirmAction) return;
                    setConfirmLoading(true);
                    try {
                        await confirmAction.action();
                    } catch (err: any) {
                        showToast('error', err.message || 'Operation failed');
                    } finally {
                        setConfirmLoading(false);
                        setConfirmAction(null);
                    }
                }}
                onCancel={() => setConfirmAction(null)}
            />
        </div>
    );
};

/* ─── Certificate Templates Page ─── */
//
// Templates are consumed by Windows autoenrollment (MSAE): a template offered to Windows is
// advertised by the policy service (/msae/{ca}/cep) and issued from when a client's CSR names
// it. ACME, EST, SCEP and CMP still issue from their per-CA protocol configuration, not from a
// template; the note below says so, so nobody expects a template to govern those.
//
const CertificateTemplates: React.FC = () => {
    const [activeTab, setActiveTab] = useState<TemplateTab>('X.509 CA');

    return (
        <div className="p-3 sm:p-6 space-y-4 sm:space-y-6">
            <h1 className="text-2xl font-bold text-gray-900 dark:text-white">Certificate Templates</h1>
            <p className="text-sm text-gray-600 dark:text-gray-400">
                Manage certificate templates that combine a CA, profiles, and settings into a reusable configuration.
            </p>

            <div className="bg-blue-50 dark:bg-blue-900/20 border border-blue-300 dark:border-blue-700/60 rounded-lg p-4 text-sm text-blue-800 dark:text-blue-300">
                <span className="font-semibold">Used by Windows autoenrollment.</span> A template offered to
                Windows clients is advertised by the MSAE policy service and issued from when a client names it in
                its request. ACME, EST, SCEP and CMP issue from each CA&apos;s protocol configuration and do not read
                templates.
            </div>

            <div className="flex gap-1 border-b border-gray-300 dark:border-gray-700">
                {TEMPLATE_TABS.map((tab) => (
                    <button key={tab} onClick={() => setActiveTab(tab)}
                        className={`px-4 py-2 text-sm font-medium transition-colors border-b-2 ${activeTab === tab
                            ? 'text-blue-800 dark:text-blue-400 border-blue-400'
                            : 'text-gray-600 dark:text-gray-400 border-transparent hover:text-gray-700 dark:text-gray-300'}`}>
                        {tab}
                    </button>
                ))}
            </div>

            {activeTab === 'X.509 CA' && <X509TemplatesTab />}
            {activeTab === 'SSH CA' && <SshTemplatesTab />}
        </div>
    );
};

export default CertificateTemplates;
