import React, { useState, useEffect } from 'react';
import { apiGet, apiPost, apiPostWithMfa, apiDelete, apiDeleteWithMfa } from '../api/client';
import { useStepUp } from '../components/StepUpMfaContext';
import { useToast } from '../context/ToastContext';
import StatusBadge from '../components/cards/StatusBadge';
import DetailField from '../components/cards/DetailField';
import ConfirmModal from '../components/ConfirmModal';
import { StepUpOps } from '@shared/generated';

const inputClass = 'w-full px-3 py-2 bg-gray-50 dark:bg-gray-900 border border-gray-300 dark:border-gray-700 rounded text-sm text-gray-900 dark:text-white focus:outline-none focus:border-blue-500';
const labelClass = 'block text-xs text-gray-600 dark:text-gray-400 mb-1';

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
    const [selectedTemplate, setSelectedTemplate] = useState<CertificateTemplate | null>(null);
    const [showCreate, setShowCreate] = useState(false);
    const [creating, setCreating] = useState(false);

    const [authorities, setAuthorities] = useState<DropdownOption[]>([]);
    const [requestProfiles, setRequestProfiles] = useState<DropdownOption[]>([]);
    const [certProfiles, setCertProfiles] = useState<DropdownOption[]>([]);
    const [signingProfiles, setSigningProfiles] = useState<DropdownOption[]>([]);

    // Confirm modal state
    const [confirmAction, setConfirmAction] = useState<{ action: () => Promise<void>; title: string; message: string } | null>(null);
    const [confirmLoading, setConfirmLoading] = useState(false);

    const [form, setForm] = useState({
        name: '', description: '', caId: '', requestProfileId: '',
        certProfileId: '', signingProfileId: '', isEnabled: true,
    });

    const resetForm = () => setForm({
        name: '', description: '', caId: '', requestProfileId: '',
        certProfileId: '', signingProfileId: '', isEnabled: true,
    });

    const extractList = (data: any): any[] =>
        Array.isArray(data) ? data : (data.items || data.templates || data.profiles || data.authorities || []);

    const load = () => {
        setLoading(true);
        setError(null);
        apiGet<any>('/api/v1/admin/templates')
            .then((data) => setTemplates(extractList(data)))
            .catch((err) => setError(err.message))
            .finally(() => setLoading(false));
    };

    useEffect(() => {
        load();
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
            };
            if (form.requestProfileId) body.requestProfileId = form.requestProfileId;
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
                if (selectedTemplate?.id === template.id) setSelectedTemplate(null);
                load();
            },
        });
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
                    </div>
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
                    <table className="w-full min-w-[600px] text-sm">
                        <thead>
                            <tr className="border-b border-gray-300 dark:border-gray-700 text-gray-600 dark:text-gray-400 text-xs">
                                <th className="px-4 py-3 text-left">Name</th>
                                <th className="px-4 py-3 text-left">CA Name</th>
                                <th className="px-4 py-3 text-left">Cert Profile</th>
                                <th className="px-4 py-3 text-left">Signing Profile</th>
                                <th className="px-4 py-3 text-left">Enabled</th>
                                <th className="px-4 py-3 text-right">Actions</th>
                            </tr>
                        </thead>
                        <tbody>
                            {templates.map((t) => (
                                <tr key={t.id} className="border-b border-gray-300 dark:border-gray-700 last:border-b-0 hover:bg-gray-200/30 dark:bg-gray-700/30 transition-colors">
                                    <td className="px-4 py-3">
                                        <button onClick={() => setSelectedTemplate(t)}
                                            className="text-blue-800 dark:text-blue-400 hover:text-blue-300 font-medium text-left">
                                            {t.name}
                                        </button>
                                        {t.description && <div className="text-xs text-gray-600 mt-0.5">{t.description}</div>}
                                    </td>
                                    <td className="px-4 py-3 text-gray-700 dark:text-gray-300 text-xs">{t.caName || t.caId}</td>
                                    <td className="px-4 py-3 text-gray-700 dark:text-gray-300 text-xs">{t.certProfileName || t.certProfileId}</td>
                                    <td className="px-4 py-3 text-gray-700 dark:text-gray-300 text-xs">{t.signingProfileName || t.signingProfileId}</td>
                                    <td className="px-4 py-3">
                                        <StatusBadge status={t.isEnabled ? 'enabled' : 'disabled'} label={t.isEnabled ? 'Enabled' : 'Disabled'} />
                                    </td>
                                    <td className="px-4 py-3 text-right">
                                        <button onClick={() => handleDelete(t)}
                                            className="px-3 py-1 text-xs bg-red-50 dark:bg-red-900/50 text-red-800 dark:text-red-300 border border-red-300 dark:border-red-700 rounded hover:bg-red-900 transition-colors">
                                            Delete
                                        </button>
                                    </td>
                                </tr>
                            ))}
                        </tbody>
                    </table>
                )}
            </div>

            {selectedTemplate && (
                <div className="fixed inset-0 bg-black/25 dark:bg-black/60 flex items-center justify-center z-50 p-4"
                    onClick={() => setSelectedTemplate(null)}>
                    <div className="bg-gray-100 dark:bg-gray-800 border border-gray-300 dark:border-gray-700 rounded-lg w-full max-w-2xl mx-4 max-h-[85vh] overflow-y-auto"
                        onClick={(e) => e.stopPropagation()}>
                        <div className="flex items-center justify-between p-4 border-b border-gray-300 dark:border-gray-700">
                            <h3 className="text-lg font-semibold text-gray-900 dark:text-white">{selectedTemplate.name}</h3>
                            <button onClick={() => setSelectedTemplate(null)}
                                className="text-gray-600 dark:text-gray-400 hover:text-gray-900 dark:hover:text-white dark:text-white text-xl px-2">X</button>
                        </div>
                        <div className="p-4 space-y-3">
                            <DetailField label="ID" value={selectedTemplate.id} />
                            <DetailField label="Template Name" value={selectedTemplate.name} />
                            <DetailField label="Description" value={selectedTemplate.description || 'None'} />
                            <DetailField label="CA" value={selectedTemplate.caName || selectedTemplate.caId} />
                            <DetailField label="Request Profile" value={selectedTemplate.requestProfileName || selectedTemplate.requestProfileId || 'None'} />
                            <DetailField label="Cert Profile" value={selectedTemplate.certProfileName || selectedTemplate.certProfileId} />
                            <DetailField label="Signing Profile" value={selectedTemplate.signingProfileName || selectedTemplate.signingProfileId} />
                            <div className="py-1">
                                <span className="text-xs text-gray-600 dark:text-gray-400">Enabled</span>
                                <div className="mt-1">
                                    <StatusBadge status={selectedTemplate.isEnabled ? 'enabled' : 'disabled'} label={selectedTemplate.isEnabled ? 'Enabled' : 'Disabled'} />
                                </div>
                            </div>
                            <DetailField label="Created At" value={selectedTemplate.createdAt ? new Date(selectedTemplate.createdAt).toLocaleString() : undefined} />
                        </div>
                        <div className="p-4 border-t border-gray-300 dark:border-gray-700 flex justify-end">
                            <button onClick={() => handleDelete(selectedTemplate)}
                                className="px-4 py-2 text-sm bg-red-50 dark:bg-red-900/50 text-red-800 dark:text-red-300 border border-red-300 dark:border-red-700 rounded hover:bg-red-900 transition-colors">
                                Delete
                            </button>
                        </div>
                    </div>
                </div>
            )}

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
    const [selectedTemplate, setSelectedTemplate] = useState<any | null>(null);
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
                if (selectedTemplate?.id === template.id) setSelectedTemplate(null);
                load();
            },
        });
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
                    <table className="w-full min-w-[600px] text-sm">
                        <thead>
                            <tr className="border-b border-gray-300 dark:border-gray-700 text-gray-600 dark:text-gray-400 text-xs">
                                <th className="px-4 py-3 text-left">Name</th>
                                <th className="px-4 py-3 text-left">CA Key</th>
                                <th className="px-4 py-3 text-left">Signing Profile</th>
                                <th className="px-4 py-3 text-left">Cert Profile</th>
                                <th className="px-4 py-3 text-left">Enabled</th>
                                <th className="px-4 py-3 text-right">Actions</th>
                            </tr>
                        </thead>
                        <tbody>
                            {templates.map((t: any) => (
                                <tr key={t.id} className="border-b border-gray-300 dark:border-gray-700 last:border-b-0 hover:bg-gray-200/30 dark:bg-gray-700/30 transition-colors">
                                    <td className="px-4 py-3">
                                        <button onClick={() => setSelectedTemplate(t)}
                                            className="text-blue-800 dark:text-blue-400 hover:text-blue-300 font-medium text-left">
                                            {t.name}
                                        </button>
                                        {t.description && <div className="text-xs text-gray-600 mt-0.5">{t.description}</div>}
                                    </td>
                                    <td className="px-4 py-3 text-gray-700 dark:text-gray-300 text-xs">{t.sshCaKeyName || t.sshCaKeyId}</td>
                                    <td className="px-4 py-3 text-gray-700 dark:text-gray-300 text-xs">{t.sshSigningProfileName || t.sshSigningProfileId}</td>
                                    <td className="px-4 py-3 text-gray-700 dark:text-gray-300 text-xs">{t.sshCertProfileName || t.sshCertProfileId}</td>
                                    <td className="px-4 py-3">
                                        <StatusBadge status={t.isEnabled ? 'enabled' : 'disabled'} label={t.isEnabled ? 'Enabled' : 'Disabled'} />
                                    </td>
                                    <td className="px-4 py-3 text-right">
                                        <button onClick={() => handleDelete(t)}
                                            className="px-3 py-1 text-xs bg-red-50 dark:bg-red-900/50 text-red-800 dark:text-red-300 border border-red-300 dark:border-red-700 rounded hover:bg-red-900 transition-colors">
                                            Delete
                                        </button>
                                    </td>
                                </tr>
                            ))}
                        </tbody>
                    </table>
                )}
            </div>

            {selectedTemplate && (
                <div className="fixed inset-0 bg-black/25 dark:bg-black/60 flex items-center justify-center z-50 p-4"
                    onClick={() => setSelectedTemplate(null)}>
                    <div className="bg-gray-100 dark:bg-gray-800 border border-gray-300 dark:border-gray-700 rounded-lg w-full max-w-2xl mx-4 max-h-[85vh] overflow-y-auto"
                        onClick={(e) => e.stopPropagation()}>
                        <div className="flex items-center justify-between p-4 border-b border-gray-300 dark:border-gray-700">
                            <h3 className="text-lg font-semibold text-gray-900 dark:text-white">{selectedTemplate.name}</h3>
                            <button onClick={() => setSelectedTemplate(null)}
                                className="text-gray-600 dark:text-gray-400 hover:text-gray-900 dark:hover:text-white dark:text-white text-xl px-2">X</button>
                        </div>
                        <div className="p-4 space-y-3">
                            <DetailField label="ID" value={selectedTemplate.id} />
                            <DetailField label="Template Name" value={selectedTemplate.name} />
                            <DetailField label="Description" value={selectedTemplate.description || 'None'} />
                            <DetailField label="SSH CA Key" value={selectedTemplate.sshCaKeyName || selectedTemplate.sshCaKeyId} />
                            <DetailField label="Signing Profile" value={selectedTemplate.sshSigningProfileName || selectedTemplate.sshSigningProfileId} />
                            <DetailField label="Cert Profile" value={selectedTemplate.sshCertProfileName || selectedTemplate.sshCertProfileId} />
                            <DetailField label="Request Profile" value={selectedTemplate.sshRequestProfileName || selectedTemplate.sshRequestProfileId || 'None'} />
                            <div className="py-1">
                                <span className="text-xs text-gray-600 dark:text-gray-400">Enabled</span>
                                <div className="mt-1">
                                    <StatusBadge status={selectedTemplate.isEnabled ? 'enabled' : 'disabled'} label={selectedTemplate.isEnabled ? 'Enabled' : 'Disabled'} />
                                </div>
                            </div>
                            <DetailField label="Created At" value={selectedTemplate.createdAt ? new Date(selectedTemplate.createdAt).toLocaleString() : undefined} />
                        </div>
                        <div className="p-4 border-t border-gray-300 dark:border-gray-700 flex justify-end">
                            <button onClick={() => handleDelete(selectedTemplate)}
                                className="px-4 py-2 text-sm bg-red-50 dark:bg-red-900/50 text-red-800 dark:text-red-300 border border-red-300 dark:border-red-700 rounded hover:bg-red-900 transition-colors">
                                Delete
                            </button>
                        </div>
                    </div>
                </div>
            )}

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
// INTERNAL NOTE — NOT WIRED INTO ISSUANCE (hidden from navigation as of 2026-06).
// Templates are CRUD-only: no enrollment/ACME/SCEP/EST/CMP/SSH issuance path reads a template.
// The backend resolver CaResolverService.ResolveByTemplateAsync(templateName) exists but has no
// caller, and no issuance request accepts a templateId. This page is intentionally kept (reachable
// by direct URL at /templates) but removed from the sidebar so operators aren't misled into
// thinking a template governs issuance.
//
// RE-IMPLEMENT plan: add an optional templateId to the enrollment/issuance request paths (or have
// CaProtocolConfig reference a template), call ResolveByTemplateAsync to expand it into the
// CA + cert/signing/request profiles, then restore the nav entry in Layout.tsx. Until then the
// banner below tells anyone who lands here that changes have no effect.
//
const CertificateTemplates: React.FC = () => {
    const [activeTab, setActiveTab] = useState<TemplateTab>('X.509 CA');

    return (
        <div className="p-3 sm:p-6 space-y-4 sm:space-y-6">
            <h1 className="text-2xl font-bold text-gray-900 dark:text-white">Certificate Templates</h1>
            <p className="text-sm text-gray-600 dark:text-gray-400">
                Manage certificate templates that combine a CA, profiles, and settings into a reusable configuration.
            </p>

            {/* Hidden-from-nav notice: templates are not yet consumed by any issuance path. */}
            <div className="bg-amber-50 dark:bg-amber-900/20 border border-amber-300 dark:border-amber-700/60 rounded-lg p-4 text-sm text-amber-800 dark:text-amber-300">
                <span className="font-semibold">Not yet active.</span> Certificate templates are not currently
                consumed by any issuance or enrollment flow — creating or editing one has no effect on how
                certificates are issued. This page is hidden from the navigation pending re-implementation that
                wires templates into the issuance pipeline.
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
