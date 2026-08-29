import React, { useEffect, useState } from 'react';
import { useParams, useNavigate, useSearchParams } from 'react-router-dom';
import { apiGet, apiPost, apiPutWithMfa, apiDeleteWithMfa } from '../api/client';
import { useToast } from '@shared/context/ToastContext';
import { useStepUp } from '../components/StepUpMfaContext';
import { StatusBadge } from '@shared/components/cards/StatusBadge';
import { DetailField } from '@shared/components/cards/DetailField';
import ConfirmModal from '../components/ConfirmModal';
import { DetailPage, DetailSection } from '../components/DetailPage';
import { StepUpOps } from '@shared/generated';

function formatDate(d: string | null) {
    if (!d) return '-';
    return new Date(d).toLocaleDateString('en-US', { year: 'numeric', month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' });
}

function publishFlags(p: any): string {
    const flags: string[] = [];
    if (p.publishCACert) flags.push('CA Cert');
    if (p.publishCRL) flags.push('CRL');
    if (p.publishDelta) flags.push('Delta');
    if (p.publishUserCerts) flags.push('User Certs');
    return flags.length > 0 ? flags.join(', ') : 'None';
}

const emptyForm = {
    name: '', host: '', port: '389', useSsl: false, username: '', password: '',
    baseDn: '', userDnTemplate: '', updateInterval: '', enabled: true,
    publishCACert: true, publishCRL: true, publishDelta: false, publishUserCerts: false,
};

const inputCls = 'w-full px-3 py-2 bg-gray-50 dark:bg-gray-900 border border-gray-300 dark:border-gray-700 rounded text-sm text-gray-900 dark:text-white placeholder-gray-400 dark:placeholder-gray-500 focus:outline-none focus:border-blue-500';
const labelCls = 'block text-xs font-semibold text-gray-600 dark:text-gray-400 mb-1';

const ToggleField: React.FC<{ label: string; checked: boolean; onChange: (v: boolean) => void }> = ({ label, checked, onChange }) => (
    <label className="flex items-center gap-2 cursor-pointer text-sm">
        <div onClick={() => onChange(!checked)} className={`relative w-8 h-4 rounded-full transition-colors cursor-pointer ${checked ? 'bg-blue-600' : 'bg-gray-400 dark:bg-gray-600'}`}>
            <div className={`absolute top-0.5 left-0.5 w-3 h-3 rounded-full bg-white transition-transform ${checked ? 'translate-x-4' : ''}`} />
        </div>
        <span className="text-gray-700 dark:text-gray-300">{label}</span>
    </label>
);

/// <summary>
/// Editable detail page for a single LDAP publisher. Publishers are CA-scoped, so the owning CA id
/// rides in the <c>caId</c> query param for a robust deep-link/refresh. Edit covers the full publisher
/// config; Test Connection and Delete live in the action bar.
/// </summary>
const LdapPublisherDetail: React.FC = () => {
    const { id } = useParams<{ id: string }>();
    const navigate = useNavigate();
    const { showToast } = useToast();
    const { requireStepUp } = useStepUp();
    const [searchParams] = useSearchParams();
    const caId = searchParams.get('caId') || '';
    const basePath = `/api/v1/admin/authorities/${caId}/ldap-publishers`;

    const [pub, setPub] = useState<any | null>(null);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState<string | null>(null);
    const [refresh, setRefresh] = useState(0);

    const [form, setForm] = useState({ ...emptyForm });
    const [initialForm, setInitialForm] = useState({ ...emptyForm });
    const [saving, setSaving] = useState(false);
    const [testing, setTesting] = useState(false);
    const [confirmDelete, setConfirmDelete] = useState(false);
    const [deleting, setDeleting] = useState(false);

    useEffect(() => {
        if (!caId) { setError('Missing CA reference — open this publisher from the Distribution page.'); setLoading(false); return; }
        let cancelled = false;
        setLoading(true);
        setError(null);
        apiGet<any>(basePath)
            .then((data) => {
                if (cancelled) return;
                const list = Array.isArray(data) ? data : (data.items || data.publishers || []);
                const p = list.find((x: any) => x.id === id) || null;
                setPub(p);
                if (p) {
                    const loaded = {
                        name: p.name || '', host: p.host || '', port: String(p.port || 389), useSsl: p.useSsl ?? false,
                        username: p.username || '', password: '', baseDn: p.baseDn || '', userDnTemplate: p.userDnTemplate || '',
                        updateInterval: p.updateInterval || '', enabled: p.enabled ?? true,
                        publishCACert: p.publishCACert ?? true, publishCRL: p.publishCRL ?? true,
                        publishDelta: p.publishDelta ?? false, publishUserCerts: p.publishUserCerts ?? false,
                    };
                    setForm(loaded);
                    setInitialForm(loaded);
                }
                setLoading(false);
            })
            .catch((err) => { if (!cancelled) { setError(err.message || 'Failed to load publisher'); setLoading(false); } });
        return () => { cancelled = true; };
    }, [id, caId, refresh]);

    const dirty = JSON.stringify(form) !== JSON.stringify(initialForm);

    const handleSave = async () => {
        setSaving(true);
        try {
            await apiPutWithMfa(`${basePath}/${id}`, {
                name: form.name, host: form.host, port: parseInt(form.port, 10) || 389, useSsl: form.useSsl,
                username: form.username || undefined, password: form.password || undefined, baseDn: form.baseDn,
                userDnTemplate: form.userDnTemplate || undefined, updateInterval: form.updateInterval || undefined,
                enabled: form.enabled, publishCACert: form.publishCACert, publishCRL: form.publishCRL,
                publishDelta: form.publishDelta, publishUserCerts: form.publishUserCerts,
            }, requireStepUp, StepUpOps.UpdateLdapPublisher, id);
            showToast('success', 'LDAP publisher updated');
            setRefresh((r) => r + 1);
        } catch (err: any) {
            if (err.message !== 'Step-up MFA cancelled') showToast('error', err.message || 'Failed to update publisher');
            throw err;
        } finally {
            setSaving(false);
        }
    };

    const handleCancel = () => {
        setForm(initialForm);
    };

    const test = async () => {
        setTesting(true);
        try {
            const result: any = await apiPost(`${basePath}/${id}/test`, {});
            if (result?.success) showToast('success', result.message || 'Connection successful');
            else showToast('error', result?.message || 'Connection test failed');
        } catch (err: any) {
            showToast('error', err.message || 'Connection test failed');
        } finally {
            setTesting(false);
        }
    };

    const doDelete = async () => {
        setDeleting(true);
        try {
            await apiDeleteWithMfa(`${basePath}/${id}`, requireStepUp, StepUpOps.DeleteLdapPublisher, id);
            showToast('success', 'LDAP publisher deleted');
            navigate(`/distribution?tab=ldap${caId ? `&caId=${caId}` : ''}`);
        } catch (err: any) {
            if (err.message !== 'Step-up MFA cancelled') showToast('error', err.message || 'Failed to delete publisher');
        } finally {
            setDeleting(false);
            setConfirmDelete(false);
        }
    };

    if (loading) return <div className="p-6 text-sm text-gray-600 dark:text-gray-400">Loading…</div>;
    if (error) return (
        <div className="p-6 space-y-3">
            <p className="text-sm text-red-800 dark:text-red-400">{error}</p>
            <button onClick={() => navigate('/distribution?tab=ldap')} className="px-3 py-1.5 text-sm bg-gray-200 dark:bg-gray-700 rounded">Back to Distribution</button>
        </div>
    );
    if (!pub) return (
        <div className="p-6 space-y-3">
            <p className="text-sm text-gray-600 dark:text-gray-400">LDAP publisher not found.</p>
            <button onClick={() => navigate('/distribution?tab=ldap')} className="px-3 py-1.5 text-sm bg-gray-200 dark:bg-gray-700 rounded">Back to Distribution</button>
        </div>
    );

    const backTo = `/distribution?tab=ldap${caId ? `&caId=${caId}` : ''}`;

    return (
        <DetailPage
            breadcrumbs={[{ label: 'Distribution', to: backTo }, { label: 'LDAP Publishers' }, { label: pub.name }]}
            title={pub.name}
            status={<StatusBadge status={pub.enabled ? 'enabled' : 'disabled'} />}
            subtitle={<span className="font-mono">{pub.host}:{pub.port}</span>}
            backTo={backTo}
            editable
            onSave={handleSave}
            onCancel={handleCancel}
            saveDisabled={!dirty || !form.name.trim() || !form.host.trim() || !form.baseDn.trim()}
            actions={
                <div className="flex items-center gap-2 flex-wrap">
                    <button onClick={test} disabled={testing} className="px-3 py-1.5 text-xs bg-indigo-50 dark:bg-indigo-900/50 text-indigo-800 dark:text-indigo-300 border border-indigo-300 dark:border-indigo-700 rounded hover:bg-indigo-900 disabled:opacity-50 transition-colors">{testing ? 'Testing…' : 'Test Connection'}</button>
                    <button onClick={() => setConfirmDelete(true)} disabled={deleting} className="px-3 py-1.5 text-xs bg-red-50 dark:bg-red-900/50 text-red-800 dark:text-red-300 border border-red-300 dark:border-red-700 rounded hover:bg-red-900 disabled:opacity-50 transition-colors">Delete</button>
                </div>
            }
        >
            {(mode) => (<>
                {mode === 'view' ? (
                    <DetailSection title="LDAP Publisher">
                        <div className="grid grid-cols-1 md:grid-cols-2 gap-x-8">
                            <DetailField label="Name" value={pub.name} />
                            <DetailField label="Host" value={`${pub.host}:${pub.port}`} mono />
                            <DetailField label="Status" value={pub.enabled ? 'Enabled' : 'Disabled'} />
                            <DetailField label="Use SSL" value={pub.useSsl ? 'Yes' : 'No'} />
                            <DetailField label="Username" value={pub.username || '-'} />
                            <DetailField label="Base DN" value={pub.baseDn} mono />
                            <DetailField label="User DN Template" value={pub.userDnTemplate || '-'} mono />
                            <DetailField label="Update Interval" value={pub.updateInterval || '-'} mono />
                            <DetailField label="Publish" value={publishFlags(pub)} />
                            <DetailField label="Last Updated" value={formatDate(pub.lastUpdated)} />
                            <DetailField label="Next Update" value={formatDate(pub.nextUpdate)} />
                        </div>
                    </DetailSection>
                ) : (
                    <DetailSection title="Edit LDAP Publisher">
                        <div className="space-y-3 max-w-3xl">
                            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
                                <div><label className={labelCls}>Name *</label><input type="text" value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} className={inputCls} /></div>
                                <div><label className={labelCls}>Host *</label><input type="text" value={form.host} onChange={(e) => setForm({ ...form, host: e.target.value })} className={inputCls} /></div>
                                <div><label className={labelCls}>Port</label><input type="text" inputMode="numeric" value={form.port} onChange={(e) => setForm({ ...form, port: e.target.value.replace(/\D/g, '') })} placeholder="636 for LDAPS, 389 plain" className={inputCls} /></div>
                                <div><label className={labelCls}>Username</label><input type="text" value={form.username} onChange={(e) => setForm({ ...form, username: e.target.value })} className={inputCls} /></div>
                                <div><label className={labelCls}>Password</label><input type="password" value={form.password} onChange={(e) => setForm({ ...form, password: e.target.value })} placeholder="(unchanged)" className={inputCls} /></div>
                                <div><label className={labelCls}>Base DN *</label><input type="text" value={form.baseDn} onChange={(e) => setForm({ ...form, baseDn: e.target.value })} className={inputCls} /></div>
                                <div className="md:col-span-2"><label className={labelCls}>User DN Template</label><input type="text" value={form.userDnTemplate} onChange={(e) => setForm({ ...form, userDnTemplate: e.target.value })} placeholder="uid={email},ou=People,{baseDn}" className={inputCls} /></div>
                                <div><label className={labelCls}>Update Interval (cron)</label><input type="text" value={form.updateInterval} onChange={(e) => setForm({ ...form, updateInterval: e.target.value })} placeholder="0 */6 * * *" className={`${inputCls} font-mono`} /></div>
                            </div>
                            <div className="flex flex-wrap gap-4 pt-1">
                                <ToggleField label="Use SSL" checked={form.useSsl} onChange={(v) => setForm({ ...form, useSsl: v })} />
                                <ToggleField label="Enabled" checked={form.enabled} onChange={(v) => setForm({ ...form, enabled: v })} />
                            </div>
                            {!form.useSsl && (
                                <div className="rounded border border-amber-300 dark:border-amber-800 bg-amber-50 dark:bg-amber-900/30 p-3 max-w-3xl">
                                    <p className="text-xs text-amber-900 dark:text-amber-300">
                                        Without SSL the bind password is sent to {form.host || 'the directory'} in cleartext.
                                        Enable it and use the LDAPS port (usually 636). Many directories, Active Directory
                                        included, reject unencrypted simple binds outright.
                                    </p>
                                </div>
                            )}
                            <div>
                                <span className={`${labelCls} mb-2`}>Publish Options</span>
                                <div className="flex flex-wrap gap-4">
                                    <label className="flex items-center gap-1.5 text-sm text-gray-700 dark:text-gray-300 cursor-pointer"><input type="checkbox" checked={form.publishCACert} onChange={(e) => setForm({ ...form, publishCACert: e.target.checked })} className="rounded border-gray-400 dark:border-gray-600 text-blue-600 focus:ring-blue-500" />CA Certificate</label>
                                    <label className="flex items-center gap-1.5 text-sm text-gray-700 dark:text-gray-300 cursor-pointer"><input type="checkbox" checked={form.publishCRL} onChange={(e) => setForm({ ...form, publishCRL: e.target.checked })} className="rounded border-gray-400 dark:border-gray-600 text-blue-600 focus:ring-blue-500" />CRL</label>
                                    <label className="flex items-center gap-1.5 text-sm text-gray-700 dark:text-gray-300 cursor-pointer"><input type="checkbox" checked={form.publishDelta} onChange={(e) => setForm({ ...form, publishDelta: e.target.checked })} className="rounded border-gray-400 dark:border-gray-600 text-blue-600 focus:ring-blue-500" />Delta CRL</label>
                                    <label className="flex items-center gap-1.5 text-sm text-gray-700 dark:text-gray-300 cursor-pointer"><input type="checkbox" checked={form.publishUserCerts} onChange={(e) => setForm({ ...form, publishUserCerts: e.target.checked })} className="rounded border-gray-400 dark:border-gray-600 text-blue-600 focus:ring-blue-500" />User Certificates</label>
                                </div>
                            </div>
                        </div>
                    </DetailSection>
                )}

                <ConfirmModal
                    isOpen={confirmDelete}
                    title="Delete LDAP Publisher"
                    message={`Delete "${pub.name}"? This cannot be undone.`}
                    confirmLabel="Delete"
                    confirmClass="bg-red-600 hover:bg-red-700"
                    loading={deleting}
                    onConfirm={doDelete}
                    onCancel={() => setConfirmDelete(false)}
                />
            </>)}
        </DetailPage>
    );
};

export default LdapPublisherDetail;
