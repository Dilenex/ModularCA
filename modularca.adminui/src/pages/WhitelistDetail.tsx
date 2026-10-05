import React, { useEffect, useState } from 'react';
import type { NoticeInput } from '@shared/notifications/notice';
import { InlineNotice } from '@shared/components/InlineNotice';
import { errorNotice } from '@shared-auth/api/notices';
import { useParams, useNavigate } from 'react-router-dom';
import { apiGet, apiPutWithMfa, apiDeleteWithMfa } from '../api/client';
import { useStepUp } from '../components/StepUpMfaContext';
import { useToast } from '@shared/context/ToastContext';
import { DetailField } from '@shared/components/cards/DetailField';
import ConfirmModal from '../components/ConfirmModal';
import { DetailPage, DetailSection } from '../components/DetailPage';
import { StepUpOps } from '@shared/generated';
import { FieldHint, inputClass as inputCls, labelClass as labelCls } from '@shared/components/forms';
import { ChipListInput } from '@shared/components/ChipListInput';
import { invalidItems } from '@shared/components/chipList';
import { validateIpOrCidr } from '@shared/validators';

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

/** One whitelist entry: an address or a CIDR range. The whitelist matcher tolerates host bits (10.0.0.1/8). */
const validateCidr = (value: string) => validateIpOrCidr(value);

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
    const [error, setError] = useState<NoticeInput | null>(null);
    const [refresh, setRefresh] = useState(0);

    // edit form
    const [form, setForm] = useState({ name: '', description: '', cidrs: [] as string[], isEnabled: true });
    const [initialForm, setInitialForm] = useState({ name: '', description: '', cidrs: [] as string[], isEnabled: true });
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
                const seeded = { name: found.name, description: found.description || '', cidrs: found.cidrs || [], isEnabled: found.isEnabled };
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
        }).catch((err) => { if (!cancelled) { setError(errorNotice(err, 'Failed to load')); setLoading(false); } });
        return () => { cancelled = true; };
    }, [id, refresh]);

    const dirty = JSON.stringify(form) !== JSON.stringify(initialForm);
    const invalidCidrs = invalidItems(form.cidrs, validateCidr);

    const handleSave = async () => {
        const cidrs = form.cidrs;
        if (!form.name.trim()) { setFormError('Name is required.'); throw new Error('Name is required.'); }
        if (invalidCidrs.length > 0) { const msg = `Fix the CIDRs marked invalid: ${invalidCidrs.join(', ')}`; setFormError(msg); throw new Error(msg); }
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

    if (loading) return <div className="p-6 text-sm text-ink-muted">Loading…</div>;
    if (error) return <InlineNotice notice={error} />;
    if (!wl) return (
        <div className="p-6 space-y-3">
            <p className="text-sm text-ink-muted">Whitelist not found.</p>
            <button onClick={() => navigate('/whitelists')} className="px-3 py-1.5 text-sm bg-sunken rounded">Back to Whitelists</button>
        </div>
    );

    const statusBadge = (
        <span className={`px-2 py-0.5 text-[11px] rounded border ${wl.isEnabled
            ? 'bg-ok-soft text-ok border-ok/40'
            : 'bg-sunken text-ink-muted border-line-strong'}`}>{wl.isEnabled ? 'Enabled' : 'Disabled'}</span>
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
            saveDisabled={!dirty || !form.name.trim() || invalidCidrs.length > 0}
            actions={!wl.isSystemDefault ? (
                <button onClick={() => setConfirmDelete(true)} className="px-3 py-1.5 text-xs bg-crit-soft text-crit border border-crit/40 rounded hover:bg-crit/15 transition-colors">Delete</button>
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
                        <span className="text-xs text-ink-muted">CIDRs ({(wl.cidrs || []).length})</span>
                        <div className="mt-1 max-h-72 overflow-y-auto rounded border border-line bg-sunken p-2 data-mono space-y-0.5">
                            {(wl.cidrs || []).length === 0
                                ? <span className="text-ink-muted">No CIDRs — blocks all for a matched rule.</span>
                                : (wl.cidrs || []).map((c, i) => <div key={i} className="text-ink">{c}</div>)}
                        </div>
                    </div>
                </DetailSection>
            ) : (
                <DetailSection title="Edit Whitelist">
                    <div className="space-y-4 max-w-2xl">
                        <div className="bg-info-soft border border-info/40 rounded p-2 text-xs text-info">
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
                            <label htmlFor="whitelist-cidrs" className={labelCls}>CIDRs</label>
                            <ChipListInput id="whitelist-cidrs" value={form.cidrs} onChange={(next) => setForm({ ...form, cidrs: next })}
                                validate={validateCidr} caseInsensitive mono aria-describedby="whitelist-cidrs-hint"
                                placeholder="e.g. 10.0.0.0/8, then Enter" />
                            <FieldHint id="whitelist-cidrs-hint" tone="warn">
                                An empty list means block all for a matched rule; it is not 'no restriction'. Use 0.0.0.0/0 and ::/0 to allow any address. Make sure your own address is still covered before saving.
                            </FieldHint>
                        </div>
                        <label className="flex items-center gap-2 text-sm text-ink">
                            <input type="checkbox" checked={form.isEnabled} onChange={(e) => setForm({ ...form, isEnabled: e.target.checked })} className="h-4 w-4 rounded border-line-strong text-accent-ink focus:ring-accent" />
                            Enabled
                        </label>
                        {invalidCidrs.length > 0 && <FieldHint tone="warn">Save is disabled until the CIDRs marked invalid are fixed or removed.</FieldHint>}
                        {formError && <p className="text-sm text-crit">{formError}</p>}
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
