import React, { useCallback, useEffect, useRef, useState } from 'react';
import { useLocation } from 'react-router-dom';
import type { NoticeInput } from '@shared/notifications/notice';
import { errorNotice } from '@shared-auth/api/notices';
import { InlineNotice } from '@shared/components/InlineNotice';
import { apiGet, apiPostWithMfa, apiDeleteWithMfa } from '../api/client';
import { useStepUp } from './StepUpMfaContext';
import { useToast } from '@shared/context/ToastContext';
import { DataTable, DataTableColumn } from '@shared/components/DataTable';
import { StatusBadge } from '@shared/components/cards/StatusBadge';
import { FieldHint, inputClass, labelClass } from '@shared/components/forms';
import ConfirmModal from './ConfirmModal';
import { StepUpOps } from '@shared/generated';

/**
 * The names a tenant's enrollment and revocation endpoints are reached by. Each name gets its own
 * TLS certificate from one of the tenant's CAs, picked by SNI on the same listener as the console;
 * the console and sign-in stay on the public domain, since security keys are bound to that name.
 */
type CertState = 'active' | 'expiring' | 'expired' | 'revoked' | 'missing';
interface Hostname {
    id: string; tenantId: string; hostname: string; issuingCaId: string; issuingCaLabel?: string | null; issuingCaName?: string | null;
    certificateId?: string | null; certificateSerial?: string | null; notBefore?: string | null; notAfter?: string | null;
    certificateState: CertState; createdAt: string; notes?: string | null;
}
interface HostnameList { publicDomain: string; hostnames: Hostname[] }
export interface HostnameCaOption { id: string; name: string; label?: string; isEnabled?: boolean; isSshCa?: boolean }

const fmt = (iso?: string | null) => (iso ? new Date(iso).toLocaleString() : '-');
const badge = (s: CertState): { status: 'active' | 'pending' | 'expired' | 'revoked' | 'disabled'; label: string } => {
    switch (s) {
        case 'active': return { status: 'active', label: 'Valid' };
        case 'expiring': return { status: 'pending', label: 'Renewing soon' };
        case 'expired': return { status: 'expired', label: 'Expired' };
        case 'revoked': return { status: 'revoked', label: 'Revoked' };
        default: return { status: 'disabled', label: 'No certificate' };
    }
};

const TenantHostnamesPanel: React.FC<{ tenantId: string; cas: HostnameCaOption[] }> = ({ tenantId, cas }) => {
    const { requireStepUp } = useStepUp();
    const { showToast } = useToast();
    const location = useLocation();
    const anchor = useRef<HTMLDivElement>(null);
    const base = `/api/v1/admin/tenants/${tenantId}/hostnames`;
    const issuers = cas.filter((c) => c.isEnabled !== false && !c.isSshCa);

    const [rows, setRows] = useState<Hostname[]>([]);
    const [publicDomain, setPublicDomain] = useState('');
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState<NoticeInput | null>(null);
    const [formError, setFormError] = useState<NoticeInput | null>(null);
    const [adding, setAdding] = useState(false);
    const [form, setForm] = useState({ hostname: '', issuingCaId: '', notes: '' });
    const [busy, setBusy] = useState(false);
    const [confirm, setConfirm] = useState<{ title: string; message: string; label: string; action: () => Promise<void> } | null>(null);

    const load = useCallback(() => {
        setLoading(true);
        apiGet<HostnameList>(base)
            .then((r) => { setRows(Array.isArray(r?.hostnames) ? r.hostnames : []); setPublicDomain(r?.publicDomain || ''); setError(null); })
            .catch((e) => setError(errorNotice(e, 'Failed to load hostnames')))
            .finally(() => setLoading(false));
    }, [base]);

    useEffect(() => { load(); }, [load]);

    // The readiness checklist links here as ?tab=hostnames; bring the section into view.
    useEffect(() => {
        if (new URLSearchParams(location.search).get('tab') === 'hostnames') anchor.current?.scrollIntoView({ block: 'start' });
    }, [location.search]);

    useEffect(() => {
        if (!form.issuingCaId && issuers.length > 0) setForm((f) => ({ ...f, issuingCaId: issuers[0].id }));
    }, [issuers, form.issuingCaId]);

    const run = async (label: string, fn: () => Promise<void>) => {
        setBusy(true);
        try { await fn(); load(); }
        catch (e: any) { if (e?.message !== 'Step-up MFA cancelled') showToast('error', e?.message || `${label} failed`); }
        finally { setBusy(false); }
    };

    const create = async () => {
        setBusy(true);
        setFormError(null);
        try {
            await apiPostWithMfa(base, { hostname: form.hostname.trim(), issuingCaId: form.issuingCaId, notes: form.notes || null }, requireStepUp, StepUpOps.ManageTenantHostname);
            showToast('success', `${form.hostname.trim().toLowerCase()} added; its certificate is live.`);
            setForm({ hostname: '', issuingCaId: form.issuingCaId, notes: '' });
            setAdding(false);
            load();
        } catch (e: any) {
            if (e?.message !== 'Step-up MFA cancelled') setFormError(errorNotice(e, 'The hostname was not added'));
        } finally {
            setBusy(false);
        }
    };

    const reissue = (h: Hostname) => run('Reissue', async () => {
        await apiPostWithMfa(`${base}/${h.id}/reissue`, {}, requireStepUp, StepUpOps.ManageTenantHostname, h.id);
        showToast('success', `New certificate issued for ${h.hostname}.`);
    });

    const remove = (h: Hostname) => setConfirm({
        title: `Remove ${h.hostname}?`,
        message: 'Its certificate is revoked and the name stops being served at once. Clients that reach this tenant by this name, including any forest whose service principal names it, will fail until they are pointed elsewhere.',
        label: 'Remove hostname',
        action: () => run('Remove', async () => {
            await apiDeleteWithMfa(`${base}/${h.id}`, requireStepUp, StepUpOps.ManageTenantHostname, h.id);
            showToast('success', `${h.hostname} removed.`);
        }),
    });

    const columns: DataTableColumn<Hostname>[] = [
        { key: 'hostname', header: 'Hostname', defaultWidth: 240, minWidth: 160, exportValue: (h) => h.hostname, render: (h) => <span className="font-mono text-xs text-gray-900 dark:text-white">{h.hostname}</span> },
        { key: 'ca', header: 'Issuing CA', defaultWidth: 180, exportValue: (h) => h.issuingCaLabel || h.issuingCaName || '', render: (h) => <span className="text-xs text-gray-600 dark:text-gray-400">{h.issuingCaName || h.issuingCaLabel || '-'}{h.issuingCaLabel && h.issuingCaName ? <span className="font-mono text-gray-500"> ({h.issuingCaLabel})</span> : null}</span> },
        { key: 'expiry', header: 'Certificate expires', defaultWidth: 180, exportValue: (h) => h.notAfter || '', render: (h) => <span className="text-xs text-gray-600 dark:text-gray-400">{fmt(h.notAfter)}</span> },
        { key: 'state', header: 'Certificate', defaultWidth: 130, truncate: false, exportValue: (h) => badge(h.certificateState).label, render: (h) => { const b = badge(h.certificateState); return <StatusBadge status={b.status} label={b.label} />; } },
        { key: 'actions', header: '', defaultWidth: 170, truncate: false, exportValue: () => '', render: (h) => (
            <span className="flex items-center gap-1.5">
                <button disabled={busy} onClick={() => reissue(h)} className="px-2 py-0.5 text-[11px] rounded border bg-gray-100 dark:bg-gray-700 text-gray-700 dark:text-gray-300 border-gray-300 dark:border-gray-600 hover:bg-gray-200 dark:hover:bg-gray-600 disabled:opacity-40">Reissue</button>
                <button disabled={busy} onClick={() => remove(h)} className="px-2 py-0.5 text-[11px] rounded border bg-red-50 dark:bg-red-900/50 text-red-800 dark:text-red-300 border-red-300 dark:border-red-700 hover:bg-red-100 dark:hover:bg-red-900 disabled:opacity-40">Delete</button>
            </span>
        ) },
    ];

    return (
        <div ref={anchor} id="hostnames" className="space-y-3 scroll-mt-4">
            <ConfirmModal isOpen={!!confirm} title={confirm?.title ?? ''} message={confirm?.message ?? ''} confirmLabel={confirm?.label} loading={busy}
                onConfirm={() => { const a = confirm?.action; setConfirm(null); a?.(); }} onCancel={() => setConfirm(null)} />
            <div className="flex items-start justify-between gap-3 flex-wrap">
                <div>
                    <h3 className="text-sm font-semibold text-gray-900 dark:text-white">Hostnames <span className="text-gray-500 font-normal">({rows.length})</span></h3>
                    <p className="text-xs text-gray-600 dark:text-gray-400 mt-1">
                        Names this tenant's enrollment and revocation endpoints answer to, each under a TLS certificate from one of the tenant's own CAs. Certificates renew on the web TLS schedule.
                    </p>
                </div>
                <button onClick={() => { setAdding((v) => !v); setFormError(null); }} className="px-3 py-1.5 text-xs font-semibold rounded bg-blue-600 text-white hover:bg-blue-700 transition-colors">
                    {adding ? 'Cancel' : 'Add a hostname'}
                </button>
            </div>

            {adding && (
                <div className="bg-gray-100 dark:bg-gray-800 border border-gray-300 dark:border-gray-700 rounded-lg p-4 space-y-3">
                    {formError && <InlineNotice notice={formError} />}
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                        <div>
                            <label className={labelClass}>Hostname *</label>
                            <input className={`${inputClass} font-mono`} value={form.hostname} onChange={(e) => setForm({ ...form, hostname: e.target.value })} aria-describedby="tenant-hostname-hint" placeholder="ca.customer.example" autoCapitalize="none" spellCheck={false} />
                            <FieldHint id="tenant-hostname-hint">
                                Clients reach this tenant's enrollment and revocation endpoints by this name; the console and sign-in stay on {publicDomain || 'the public domain'}, since security keys are bound to that name.
                            </FieldHint>
                        </div>
                        <div>
                            <label className={labelClass}>Issuing CA *</label>
                            <select className={inputClass} value={form.issuingCaId} onChange={(e) => setForm({ ...form, issuingCaId: e.target.value })}>
                                {issuers.length === 0 && <option value="">-- this tenant has no CA that can issue --</option>}
                                {issuers.map((c) => <option key={c.id} value={c.id}>{c.name}{c.label ? ` (${c.label})` : ''}</option>)}
                            </select>
                            <FieldHint id="tenant-hostname-ca-hint">Issues and renews the endpoint certificate. Clients must trust this CA, as they already do to enroll from it.</FieldHint>
                        </div>
                        <div className="md:col-span-2">
                            <label className={labelClass}>Notes</label>
                            <input className={inputClass} value={form.notes} onChange={(e) => setForm({ ...form, notes: e.target.value })} placeholder="optional" />
                        </div>
                    </div>
                    <div className="flex justify-end">
                        <button disabled={busy || !form.hostname.trim() || !form.issuingCaId} onClick={create} className="px-3 py-1.5 text-xs font-semibold rounded bg-blue-600 text-white hover:bg-blue-700 disabled:opacity-50">Add and issue certificate</button>
                    </div>
                </div>
            )}

            <DataTable<Hostname>
                tableId={`tenant-hostnames-${tenantId}`}
                rows={rows}
                rowKey={(h) => h.id}
                loading={loading}
                error={error}
                empty={`No hostnames. Clients reach this tenant's CAs as ${publicDomain || 'the public domain'} until one is added.`}
                columns={columns}
                disableExport
            />
        </div>
    );
};

export default TenantHostnamesPanel;
