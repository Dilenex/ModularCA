import React, { useEffect, useState } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { apiGet, apiPutWithMfa, apiDeleteWithMfa } from '../api/client';
import { useStepUp } from '../components/StepUpMfaContext';
import { useToast } from '@shared/context/ToastContext';
import { DetailField } from '@shared/components/cards/DetailField';
import ConfirmModal from '../components/ConfirmModal';
import { DetailPage, DetailSection } from '../components/DetailPage';
import { StepUpOps } from '@shared/generated';
import { inputClass as inputCls, labelClass as labelCls } from '@shared/components/forms';

interface Whitelist {
    id: string;
    name: string;
    description: string | null;
    scope: string;
    certificateAuthorityId: string | null;
    protocol: string | null;
    cidrs: string[];
    isEnabled: boolean;
    isSystemDefault: boolean;
    createdAt: string;
    updatedAt: string;
}

const CIDR_REGEX = /^(\d{1,3}\.){3}\d{1,3}(\/\d{1,2})?$|^[0-9a-fA-F:]+(\/\d{1,3})?$/;

function formatDate(d: string | null) {
    if (!d) return '-';
    return new Date(d).toLocaleDateString('en-US', { year: 'numeric', month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' });
}


const WhitelistDetail: React.FC = () => {
    const { id } = useParams<{ id: string }>();
    const navigate = useNavigate();
    const { requireStepUp } = useStepUp();
    const { showToast } = useToast();

    const [wl, setWl] = useState<Whitelist | null>(null);
    const [caName, setCaName] = useState<string>('-');
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState<string | null>(null);
    const [refresh, setRefresh] = useState(0);

    // edit form
    const [form, setForm] = useState({ name: '', description: '', cidrsText: '', isEnabled: true });
    const [initialForm, setInitialForm] = useState({ name: '', description: '', cidrsText: '', isEnabled: true });
    const [formError, setFormError] = useState<string | null>(null);
    const [confirmDelete, setConfirmDelete] = useState(false);
    const [deleting, setDeleting] = useState(false);

    // The list endpoint returns everything; find the one entry (robust on refresh/deep-link).
    useEffect(() => {
        let cancelled = false;
        setLoading(true);
        setError(null);
        Promise.all([
            apiGet<any>('/api/v1/admin/whitelists'),
            apiGet<any>('/api/v1/admin/authorities').catch(() => []),
        ]).then(([wlData, authData]) => {
            if (cancelled) return;
            const items: Whitelist[] = Array.isArray(wlData) ? wlData : (wlData.items || wlData.whitelists || []);
            const found = items.find((w) => w.id === id) || null;
            setWl(found);
            if (found) {
                const seeded = { name: found.name, description: found.description || '', cidrsText: (found.cidrs || []).join('\n'), isEnabled: found.isEnabled };
                setForm(seeded);
                setInitialForm(seeded);
                if (found.certificateAuthorityId) {
                    const cas = Array.isArray(authData) ? authData : (authData.items || authData.authorities || []);
                    const flat: any[] = [];
                    const flatten = (l: any[]) => { for (const c of l) { flat.push(c); if (c.children) flatten(c.children); } };
                    flatten(cas);
                    const ca = flat.find((a) => a.id === found.certificateAuthorityId || a.certificateId === found.certificateAuthorityId);
                    setCaName(ca ? (ca.label || ca.name || ca.commonName || found.certificateAuthorityId) : found.certificateAuthorityId);
                } else setCaName('-');
            }
            setLoading(false);
        }).catch((err) => { if (!cancelled) { setError(err.message || 'Failed to load'); setLoading(false); } });
        return () => { cancelled = true; };
    }, [id, refresh]);

    const parseCidrs = (text: string) => text.split('\n').map((l) => l.trim()).filter(Boolean);

    const dirty = JSON.stringify(form) !== JSON.stringify(initialForm);

    const handleSave = async () => {
        const cidrs = parseCidrs(form.cidrsText);
        if (!form.name.trim()) { setFormError('Name is required.'); throw new Error('Name is required.'); }
        for (const c of cidrs) if (!CIDR_REGEX.test(c)) { const msg = `Invalid CIDR: "${c}"`; setFormError(msg); throw new Error(msg); }
        setFormError(null);
        try {
            await apiPutWithMfa(`/api/v1/admin/whitelists/${id}`,
                { name: form.name.trim(), description: form.description.trim() || null, cidrs, isEnabled: form.isEnabled },
                requireStepUp, StepUpOps.UpdateWhitelist, id!);
            showToast('success', 'Whitelist updated');
            setRefresh((r) => r + 1);
        } catch (err: any) {
            if (err.message !== 'Step-up MFA cancelled') showToast('error', err.message || 'Failed to save');
            throw err;
        }
    };

    const handleCancel = () => { setForm(initialForm); setFormError(null); };

    const doDelete = async () => {
        setDeleting(true);
        try {
            await apiDeleteWithMfa(`/api/v1/admin/whitelists/${id}`, requireStepUp, StepUpOps.DeleteWhitelist, id!);
            showToast('success', 'Whitelist deleted');
            navigate('/whitelists');
        } catch (err: any) {
            if (err?.message !== 'Step-up MFA cancelled') showToast('error', err.message || 'Failed to delete');
        } finally {
            setDeleting(false);
            setConfirmDelete(false);
        }
    };

    if (loading) return <div className="p-6 text-sm text-gray-600 dark:text-gray-400">Loading…</div>;
    if (error) return <div className="p-6 text-sm text-red-800 dark:text-red-400">{error}</div>;
    if (!wl) return (
        <div className="p-6 space-y-3">
            <p className="text-sm text-gray-600 dark:text-gray-400">Whitelist not found.</p>
            <button onClick={() => navigate('/whitelists')} className="px-3 py-1.5 text-sm bg-gray-200 dark:bg-gray-700 rounded">Back to Whitelists</button>
        </div>
    );

    const statusBadge = (
        <span className={`px-2 py-0.5 text-[11px] rounded border ${wl.isEnabled
            ? 'bg-green-50 dark:bg-green-900/40 text-green-800 dark:text-green-300 border-green-300 dark:border-green-700'
            : 'bg-gray-200 dark:bg-gray-700 text-gray-600 dark:text-gray-400 border-gray-300 dark:border-gray-600'}`}>{wl.isEnabled ? 'Enabled' : 'Disabled'}</span>
    );

    return (
        <DetailPage
            breadcrumbs={[{ label: 'Whitelists', to: '/whitelists' }, { label: wl.name }]}
            title={wl.name}
            status={statusBadge}
            subtitle={<span>{wl.scope}{wl.protocol ? ` · ${wl.protocol}` : ''}{wl.isSystemDefault ? ' · System Default' : ''}</span>}
            editable
            onSave={handleSave}
            onCancel={handleCancel}
            saveDisabled={!dirty || !form.name.trim()}
            actions={!wl.isSystemDefault ? (
                <button onClick={() => setConfirmDelete(true)} className="px-3 py-1.5 text-xs bg-red-50 dark:bg-red-900/50 text-red-800 dark:text-red-300 border border-red-300 dark:border-red-700 rounded hover:bg-red-900 transition-colors">Delete</button>
            ) : undefined}
        >
            {(mode) => (<>{mode === 'view' ? (
                <DetailSection title="Details">
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-x-8">
                        <DetailField label="Name" value={wl.name} />
                        <DetailField label="Status" value={wl.isEnabled ? 'Enabled' : 'Disabled'} />
                        <DetailField label="Scope" value={wl.scope} />
                        <DetailField label="Protocol" value={wl.protocol || '-'} />
                        <DetailField label="Certificate Authority" value={caName} />
                        <DetailField label="System Default" value={wl.isSystemDefault ? 'Yes' : 'No'} />
                        <DetailField label="Description" value={wl.description || '-'} />
                        <DetailField label="Created" value={formatDate(wl.createdAt)} />
                        <DetailField label="Updated" value={formatDate(wl.updatedAt)} />
                    </div>
                    <div className="mt-3">
                        <span className="text-xs text-gray-500">CIDRs ({(wl.cidrs || []).length})</span>
                        <div className="mt-1 max-h-72 overflow-y-auto rounded border border-gray-300 dark:border-gray-700 bg-gray-50 dark:bg-gray-900 p-2 font-mono text-xs space-y-0.5">
                            {(wl.cidrs || []).length === 0
                                ? <span className="text-gray-500">No CIDRs — blocks all for a matched rule.</span>
                                : (wl.cidrs || []).map((c, i) => <div key={i} className="text-gray-800 dark:text-gray-200">{c}</div>)}
                        </div>
                    </div>
                </DetailSection>
            ) : (
                <DetailSection title="Edit Whitelist">
                    <div className="space-y-4 max-w-2xl">
                        <div className="bg-blue-50 dark:bg-blue-900/20 border border-blue-300 dark:border-blue-800 rounded p-2 text-xs text-blue-800 dark:text-blue-300">
                            Scope, CA, and protocol are set at creation and can't be changed here — recreate the rule to change them.
                        </div>
                        <div>
                            <label className={labelCls}>Name *</label>
                            <input type="text" value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })}
                                autoComplete="off" data-1p-ignore data-lpignore="true" data-bwignore data-form-type="other" className={inputCls} />
                        </div>
                        <div>
                            <label className={labelCls}>Description</label>
                            <input type="text" value={form.description} onChange={(e) => setForm({ ...form, description: e.target.value })}
                                autoComplete="off" data-1p-ignore data-lpignore="true" data-bwignore data-form-type="other" className={inputCls} />
                        </div>
                        <div>
                            <label className={labelCls}>CIDRs (one per line)</label>
                            <textarea value={form.cidrsText} onChange={(e) => setForm({ ...form, cidrsText: e.target.value })} rows={8}
                                autoComplete="off" data-1p-ignore data-lpignore="true" data-bwignore data-form-type="other" spellCheck={false}
                                placeholder={'10.0.0.0/8\n::1/128'} className={`${inputCls} font-mono`} />
                        </div>
                        <label className="flex items-center gap-2 text-sm text-gray-700 dark:text-gray-300">
                            <input type="checkbox" checked={form.isEnabled} onChange={(e) => setForm({ ...form, isEnabled: e.target.checked })} className="h-4 w-4 rounded border-gray-300 dark:border-gray-700 text-blue-600 focus:ring-blue-500" />
                            Enabled
                        </label>
                        {formError && <p className="text-sm text-red-800 dark:text-red-400">{formError}</p>}
                    </div>
                </DetailSection>
            )}
            <ConfirmModal
                isOpen={confirmDelete}
                title="Delete Whitelist"
                message={`Delete whitelist "${wl.name}"? This cannot be undone.`}
                confirmLabel="Delete"
                loading={deleting}
                onConfirm={doDelete}
                onCancel={() => setConfirmDelete(false)}
            />
            </>)}
        </DetailPage>
    );
};

export default WhitelistDetail;
