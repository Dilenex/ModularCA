import React, { useState, useEffect, useMemo } from 'react';
import { apiGet, apiPostWithMfa, apiPutWithMfa } from '../api/client';
import { recordTableProps } from '../components/RecordDrawer';
import type { RecordDescriptor } from '@shared/records';
import { useStepUp } from '../components/StepUpMfaContext';
import { useToast } from '@shared/context/ToastContext';
import ConfirmModal from '../components/ConfirmModal';
import { DataTable, DataTableColumn, DataTableBulkAction } from '@shared/components/DataTable';
import { StepUpOps } from '@shared/generated';
import { inputClass, labelClass } from '@shared/components/forms';

/// <summary>
/// Represents a single whitelist rule returned by the admin whitelist API.
/// Matches the backend WhitelistEntity schema.
/// </summary>
interface Whitelist {
    id: string;
    name: string;
    description: string | null;
    scope: 'System' | 'Setup' | 'Auth' | 'Api' | 'ShortUrl' | 'Ca' | 'Protocol' | 'Admin';
    certificateAuthorityId: string | null;
    protocol: string | null;
    cidrs: string[];
    isEnabled: boolean;
    isSystemDefault: boolean;
    createdAt: string;
    updatedAt: string;
}

type WhitelistScope = Whitelist['scope'];

const SCOPES: WhitelistScope[] = ['System', 'Setup', 'Admin', 'Auth', 'Api', 'ShortUrl', 'Ca', 'Protocol'];
const PROTOCOLS = ['ACME', 'EST', 'SCEP', 'CMP', 'MSAE', 'OCSP', 'TSA', 'CRL', 'CA'];

/// <summary>
/// Validates a single CIDR string. Accepts IPv4 (optionally with /prefix)
/// and IPv6 (optionally with /prefix). Deliberately loose — the backend
/// does the canonical parse.
/// </summary>
const CIDR_REGEX = /^(\d{1,3}\.){3}\d{1,3}(\/\d{1,2})?$|^[0-9a-fA-F:]+(\/\d{1,3})?$/;

function formatDate(d: string | null): string {
    if (!d) return '-';
    return new Date(d).toLocaleDateString('en-US', {
        year: 'numeric', month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit',
    });
}

interface FormState {
    name: string;
    description: string;
    scope: WhitelistScope;
    certificateAuthorityId: string;
    protocol: string;
    cidrsText: string;
    isEnabled: boolean;
}

const emptyForm: FormState = {
    name: '', description: '', scope: 'System', certificateAuthorityId: '', protocol: '', cidrsText: '', isEnabled: true,
};

/// <summary>
/// Admin CRUD page for IP whitelist rules. Lists rules from /api/v1/admin/whitelists in a
/// resizable DataTable with row selection; create/edit/enable/disable/delete run from the bulk
/// toolbar with step-up MFA. CIDR entries are validated client-side before submission.
/// </summary>
const Whitelists: React.FC = () => {
    const { requireStepUp } = useStepUp();
    const { showToast } = useToast();

    const [whitelists, setWhitelists] = useState<Whitelist[]>([]);
    const [authorities, setAuthorities] = useState<any[]>([]);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState<string | null>(null);
    const [refreshTrigger, setRefreshTrigger] = useState(0);

    // Modal / form state
    const [showModal, setShowModal] = useState(false);
    const [editingId, setEditingId] = useState<string | null>(null);
    const [form, setForm] = useState<FormState>(emptyForm);
    const [formError, setFormError] = useState<string | null>(null);
    const [saving, setSaving] = useState(false);

    // Bulk-delete confirm modal state
    const [confirmBulk, setConfirmBulk] = useState<Whitelist[] | null>(null);
    const [confirmLoading, setConfirmLoading] = useState(false);

    useEffect(() => {
        let cancelled = false;
        setLoading(true);
        setError(null);

        Promise.all([
            apiGet<any>('/api/v1/admin/whitelists'),
            apiGet<any>('/api/v1/admin/authorities').catch(() => []),
        ])
            .then(([wlData, authData]) => {
                if (cancelled) return;
                const items = Array.isArray(wlData) ? wlData : wlData.items || wlData.whitelists || [];
                setWhitelists(items);

                const cas = Array.isArray(authData) ? authData : authData.items || authData.authorities || [];
                const flat: any[] = [];
                const flatten = (list: any[]) => { for (const ca of list) { flat.push(ca); if (ca.children && Array.isArray(ca.children)) flatten(ca.children); } };
                flatten(cas);
                setAuthorities(flat);
                setLoading(false);
            })
            .catch((err) => {
                if (!cancelled) { setError(err.message || 'Failed to load whitelists'); setLoading(false); }
            });

        return () => { cancelled = true; };
    }, [refreshTrigger]);

    const caNameById = (caId: string | null): string => {
        if (!caId) return '-';
        const ca = authorities.find((a) => a.id === caId || a.certificateId === caId);
        if (!ca) return caId.substring(0, 8);
        return ca.label || ca.name || ca.commonName || caId.substring(0, 8);
    };

    const openCreate = () => { setEditingId(null); setForm(emptyForm); setFormError(null); setShowModal(true); };

    const closeModal = () => { setShowModal(false); setEditingId(null); setForm(emptyForm); setFormError(null); };

    const parseCidrs = (text: string): string[] => text.split('\n').map((l) => l.trim()).filter((l) => l.length > 0);

    const validateForm = (): { ok: boolean; cidrs: string[] } => {
        if (!form.name.trim()) { setFormError('Name is required.'); return { ok: false, cidrs: [] }; }
        if (form.scope === 'Ca' && !form.certificateAuthorityId) { setFormError('Certificate Authority is required for Ca scope.'); return { ok: false, cidrs: [] }; }
        if (form.scope === 'Protocol' && !form.protocol) { setFormError('Protocol is required for Protocol scope.'); return { ok: false, cidrs: [] }; }
        const cidrs = parseCidrs(form.cidrsText);
        for (const cidr of cidrs) {
            if (!CIDR_REGEX.test(cidr)) { setFormError(`Invalid CIDR: "${cidr}"`); return { ok: false, cidrs: [] }; }
        }
        setFormError(null);
        return { ok: true, cidrs };
    };

    const handleSave = async () => {
        const { ok, cidrs } = validateForm();
        if (!ok) return;
        setSaving(true);
        try {
            if (editingId) {
                // scope/CA/protocol are create-only (unique composite index); only mutable fields on PUT.
                await apiPutWithMfa(`/api/v1/admin/whitelists/${editingId}`,
                    { name: form.name.trim(), description: form.description.trim() || null, cidrs, isEnabled: form.isEnabled },
                    requireStepUp, StepUpOps.UpdateWhitelist, editingId);
                showToast('success', 'Whitelist updated');
            } else {
                await apiPostWithMfa('/api/v1/admin/whitelists', {
                    name: form.name.trim(),
                    description: form.description.trim() || null,
                    scope: form.scope,
                    certificateAuthorityId: form.scope === 'Ca' ? form.certificateAuthorityId
                        : form.scope === 'Protocol' && form.certificateAuthorityId ? form.certificateAuthorityId : null,
                    protocol: form.scope === 'Protocol' ? form.protocol : null,
                    cidrs, isEnabled: form.isEnabled,
                }, requireStepUp, StepUpOps.CreateWhitelist);
                showToast('success', 'Whitelist created');
            }
            closeModal();
            setRefreshTrigger((t) => t + 1);
        } catch (err: any) {
            setFormError(err.message || 'Failed to save whitelist');
        } finally {
            setSaving(false);
        }
    };

    /// <summary>
    /// Bulk enable/disable selected rules. Skips rows already in the target state, runs sequentially,
    /// and aborts the batch if the operator cancels a step-up prompt.
    /// </summary>
    const bulkSetEnabled = async (rows: Whitelist[], enabled: boolean) => {
        const targets = rows.filter((wl) => wl.isEnabled !== enabled);
        if (targets.length === 0) { showToast('info', `All selected are already ${enabled ? 'enabled' : 'disabled'}.`); return; }
        try {
            // Single step-up authorization covers the whole batch (one MFA prompt).
            const ids = targets.map((wl) => wl.id);
            const res = await apiPostWithMfa<any>('/api/v1/admin/whitelists/bulk-set-enabled', { ids, enabled }, requireStepUp, StepUpOps.UpdateWhitelist);
            const updated = res?.updated ?? ids.length;
            showToast('success', `${enabled ? 'Enabled' : 'Disabled'} ${updated} rule${updated !== 1 ? 's' : ''}.`);
        } catch (err: any) {
            if (err?.message !== 'Step-up MFA cancelled') showToast('error', err.message || 'Failed to update');
        }
        setRefreshTrigger((t) => t + 1);
    };

    const performBulkDelete = async () => {
        if (!confirmBulk) return;
        setConfirmLoading(true);
        try {
            // Single step-up authorization covers the whole batch (one MFA prompt) via the
            // bulk-delete endpoint. System-default rules are filtered here and skipped server-side.
            const ids = confirmBulk.filter((w) => !w.isSystemDefault).map((w) => w.id);
            if (ids.length === 0) { showToast('info', 'Only system-default rules selected — nothing to delete.'); return; }
            const res = await apiPostWithMfa<any>('/api/v1/admin/whitelists/bulk-delete', { ids }, requireStepUp, StepUpOps.DeleteWhitelist);
            const deleted = res?.deleted ?? ids.length;
            showToast('success', `Deleted ${deleted} whitelist${deleted !== 1 ? 's' : ''}.`);
            setRefreshTrigger((t) => t + 1);
        } catch (err: any) {
            if (err?.message !== 'Step-up MFA cancelled') showToast('error', err.message || 'Failed to delete');
        } finally {
            setConfirmLoading(false);
            setConfirmBulk(null);
        }
    };

    const sorted = useMemo(() => {
        const order: Record<WhitelistScope, number> = { System: 0, Setup: 1, Admin: 2, Auth: 3, Api: 4, ShortUrl: 5, Ca: 6, Protocol: 7 };
        return [...whitelists].sort((a, b) => {
            const ds = order[a.scope] - order[b.scope];
            return ds !== 0 ? ds : a.name.localeCompare(b.name);
        });
    }, [whitelists]);

    const record: RecordDescriptor<Whitelist> = useMemo(() => ({
        kind: 'whitelist',
        key: (wl) => wl.id,
        title: (wl) => wl.name,
        status: (wl) => ({ label: wl.isEnabled ? 'Enabled' : 'Disabled', tone: wl.isEnabled ? 'ok' : 'neutral' }),
        columns: [
            {
                key: 'name', header: 'Name', defaultWidth: 240, minWidth: 160, truncate: false, sortable: true,
                exportValue: (wl) => wl.name,
                render: (wl) => (
                    <div className="min-w-0">
                        <div className="flex items-center gap-2">
                            <span className="text-gray-900 dark:text-white font-medium truncate">{wl.name}</span>
                            {wl.isSystemDefault && (
                                <span className="px-1.5 py-0.5 text-[10px] bg-blue-50 dark:bg-blue-900/40 text-blue-800 dark:text-blue-300 border border-blue-300 dark:border-blue-700 rounded shrink-0">System Default</span>
                            )}
                        </div>
                        {wl.description && <div className="text-xs text-gray-600 truncate">{wl.description}</div>}
                    </div>
                ),
            },
            { key: 'scope', header: 'Scope', defaultWidth: 100, sortable: true, exportValue: (wl) => wl.scope, truncate: false,
                render: (wl) => <span className="px-2 py-0.5 text-xs bg-gray-200 dark:bg-gray-700 text-gray-700 dark:text-gray-300 rounded">{wl.scope}</span> },
            { key: 'protocol', header: 'Protocol', defaultWidth: 90, sortable: true, exportValue: (wl) => wl.protocol || '', render: (wl) => wl.protocol || '-' },
            { key: 'ca', header: 'CA', defaultWidth: 150, sortable: true, exportValue: (wl) => caNameById(wl.certificateAuthorityId), render: (wl) => caNameById(wl.certificateAuthorityId) },
            { key: 'cidrs', header: 'CIDRs', defaultWidth: 80, align: 'right', sortable: true, sortValue: (wl) => (wl.cidrs || []).length, exportValue: (wl) => (wl.cidrs || []).join(' '), render: (wl) => (wl.cidrs || []).length },
            { key: 'enabled', header: 'Status', defaultWidth: 90, truncate: false, sortable: true, sortValue: (wl) => wl.isEnabled, exportValue: (wl) => (wl.isEnabled ? 'Enabled' : 'Disabled'),
                render: (wl) => (
                    <span className={`px-2 py-0.5 text-[11px] rounded border ${wl.isEnabled
                        ? 'bg-green-50 dark:bg-green-900/40 text-green-800 dark:text-green-300 border-green-300 dark:border-green-700'
                        : 'bg-gray-200 dark:bg-gray-700 text-gray-600 dark:text-gray-400 border-gray-300 dark:border-gray-600'}`}>{wl.isEnabled ? 'Enabled' : 'Disabled'}</span>
                ) },
            { key: 'updated', header: 'Updated', defaultWidth: 150, sortable: true, sortValue: (wl) => wl.updatedAt ? new Date(wl.updatedAt) : null, exportValue: (wl) => wl.updatedAt, render: (wl) => formatDate(wl.updatedAt) },
        ],
        sections: [
            { fields: [
                { label: 'Scope', value: (wl) => wl.scope },
                { label: 'System Default', value: (wl) => (wl.isSystemDefault ? 'Yes' : null) },
                { label: 'Description', value: (wl) => wl.description },
                { label: 'Protocol', value: (wl) => wl.protocol },
                { label: 'CA', value: (wl) => caNameById(wl.certificateAuthorityId) },
                { label: 'Created', value: (wl) => formatDate(wl.createdAt) },
                { label: 'Updated', value: (wl) => formatDate(wl.updatedAt) },
            ] },
            { title: 'CIDRs', fields: [
                { label: 'Rules', value: (wl) => (
                    <div className="max-h-60 overflow-y-auto rounded border border-gray-300 dark:border-gray-700 bg-gray-50 dark:bg-gray-900 p-2 font-mono text-xs space-y-0.5">
                        {(wl.cidrs || []).length === 0
                            ? <span className="text-gray-500">No CIDRs — blocks all for a matched rule.</span>
                            : (wl.cidrs || []).map((c, i) => <div key={i} className="text-gray-800 dark:text-gray-200">{c}</div>)}
                    </div>
                ) },
            ] },
        ],
        audit: { tab: 'General', target: (wl) => ({ type: 'Whitelist', id: wl.id }) },
        page: { path: (wl) => `/whitelists/${wl.id}` },
        // eslint-disable-next-line react-hooks/exhaustive-deps
    }), [authorities]);

    // Edit moved to the per-entry detail page (open via the drawer's "Open full page", then the
    // View/Edit toggle). The modal below is now create-only.
    const bulkActions: DataTableBulkAction<Whitelist>[] = [
        { label: 'Enable', onClick: (rows) => bulkSetEnabled(rows, true) },
        { label: 'Disable', onClick: (rows) => bulkSetEnabled(rows, false) },
        { label: 'Delete', variant: 'danger', enabledFor: (wl) => !wl.isSystemDefault, onClick: (rows) => setConfirmBulk(rows) },
    ];


    return (
        <div className="p-3 sm:p-6 space-y-4 sm:space-y-6">
            <div className="flex items-center justify-between">
                <div>
                    <h1 className="text-2xl font-bold text-gray-900 dark:text-white">Whitelists</h1>
                    <p className="text-xs text-gray-600 mt-1">
                        IP allow-list rules for setup, auth, protocol, and CA-scoped endpoints. System defaults are
                        seeded on first bootstrap and can be edited but not deleted. Select rows to edit, enable/disable, or delete.
                    </p>
                </div>
                <button onClick={openCreate} className="px-4 py-2 text-sm font-semibold bg-blue-600 text-white rounded hover:bg-blue-700 transition-colors">
                    New Whitelist
                </button>
            </div>

            <DataTable<Whitelist>
                tableId="whitelists"
                title="Rules"
                rows={sorted}
                loading={loading}
                error={error}
                empty="No whitelist rules found. They are normally seeded on first bootstrap — reload after running setup."
                selectable
                bulkActions={bulkActions}
                exportFileName="whitelists"
                {...recordTableProps(record)}
            />

            {/* Create/Edit Modal */}
            {showModal && (
                <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 p-4">
                    <div className="bg-white dark:bg-gray-900 border border-gray-300 dark:border-gray-700 rounded-xl shadow-2xl w-full max-w-2xl mx-4 max-h-[90vh] overflow-y-auto">
                        <div className="px-6 py-4 border-b border-gray-300 dark:border-gray-700 flex items-center justify-between">
                            <h3 className="text-lg font-bold text-gray-900 dark:text-white">{editingId ? 'Edit Whitelist' : 'New Whitelist'}</h3>
                            <button onClick={closeModal} className="text-gray-600 hover:text-gray-900 dark:hover:text-white transition-colors" title="Close">
                                <svg className="h-5 w-5" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
                                </svg>
                            </button>
                        </div>

                        <div className="p-6 space-y-4">
                            <div>
                                <label className={labelClass}>Name *</label>
                                <input type="text" value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} placeholder="e.g., corporate-network"
                                    autoComplete="off" data-1p-ignore data-lpignore="true" data-bwignore data-form-type="other" className={inputClass} />
                            </div>
                            <div>
                                <label className={labelClass}>Description</label>
                                <input type="text" value={form.description} onChange={(e) => setForm({ ...form, description: e.target.value })} placeholder="Optional description"
                                    autoComplete="off" data-1p-ignore data-lpignore="true" data-bwignore data-form-type="other" className={inputClass} />
                            </div>
                            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                                <div>
                                    <label className={labelClass}>Scope *</label>
                                    <select value={form.scope} onChange={(e) => {
                                        const scope = e.target.value as WhitelistScope;
                                        setForm({ ...form, scope, certificateAuthorityId: scope === 'Ca' || scope === 'Protocol' ? form.certificateAuthorityId : '', protocol: scope === 'Protocol' ? form.protocol : '' });
                                    }} className={inputClass} disabled={!!editingId}>
                                        {SCOPES.map((s) => <option key={s} value={s}>{s}</option>)}
                                    </select>
                                </div>
                                {(form.scope === 'Ca' || form.scope === 'Protocol') && (
                                    <div>
                                        <label className={labelClass}>Certificate Authority *</label>
                                        <select value={form.certificateAuthorityId} onChange={(e) => setForm({ ...form, certificateAuthorityId: e.target.value })} className={inputClass} disabled={!!editingId}>
                                            <option value="">-- Select CA --</option>
                                            {authorities.map((ca) => <option key={ca.id} value={ca.id}>{ca.label || ca.name || ca.commonName || ca.id}</option>)}
                                        </select>
                                    </div>
                                )}
                                {form.scope === 'Protocol' && (
                                    <div>
                                        <label className={labelClass}>Protocol *</label>
                                        <select value={form.protocol} onChange={(e) => setForm({ ...form, protocol: e.target.value })} className={inputClass} disabled={!!editingId}>
                                            <option value="">-- Select Protocol --</option>
                                            {PROTOCOLS.map((p) => <option key={p} value={p}>{p}</option>)}
                                        </select>
                                    </div>
                                )}
                            </div>
                            <div>
                                <label className={labelClass}>CIDRs (one per line)</label>
                                <textarea value={form.cidrsText} onChange={(e) => setForm({ ...form, cidrsText: e.target.value })} placeholder={'10.0.0.0/8\n192.168.0.0/16\n::1/128'} rows={6}
                                    autoComplete="off" data-1p-ignore data-lpignore="true" data-bwignore data-form-type="other" spellCheck={false} className={`${inputClass} font-mono`} />
                                <p className="text-[11px] text-gray-600 mt-1">An empty list means "block all" for a matched rule. Use <code>0.0.0.0/0</code> and <code>::/0</code> to allow any IP.</p>
                            </div>
                            <div className="flex items-center gap-2">
                                <input id="wl-enabled" type="checkbox" checked={form.isEnabled} onChange={(e) => setForm({ ...form, isEnabled: e.target.checked })} className="h-4 w-4 rounded border-gray-300 dark:border-gray-700 text-blue-600 focus:ring-blue-500" />
                                <label htmlFor="wl-enabled" className="text-sm text-gray-700 dark:text-gray-300">Enabled</label>
                            </div>
                            {formError && (
                                <div className="bg-red-50 dark:bg-red-900/30 border border-red-300 dark:border-red-700 rounded p-3">
                                    <p className="text-sm text-red-800 dark:text-red-300">{formError}</p>
                                </div>
                            )}
                        </div>

                        <div className="px-6 py-4 border-t border-gray-300 dark:border-gray-700 flex justify-end gap-3">
                            <button onClick={closeModal} disabled={saving} className="px-4 py-2 text-sm bg-gray-200 dark:bg-gray-700 text-gray-700 dark:text-gray-300 rounded hover:bg-gray-300 dark:hover:bg-gray-600 transition-colors">Cancel</button>
                            <button onClick={handleSave} disabled={saving} className="px-4 py-2 text-sm font-semibold bg-blue-600 text-white rounded hover:bg-blue-700 disabled:opacity-50 transition-colors">
                                {saving ? 'Saving...' : editingId ? 'Save Changes' : 'Create'}
                            </button>
                        </div>
                    </div>
                </div>
            )}

            <ConfirmModal
                isOpen={!!confirmBulk}
                title="Delete Whitelists"
                message={confirmBulk
                    ? (() => {
                        const deletable = confirmBulk.filter((w) => !w.isSystemDefault).length;
                        const skipped = confirmBulk.length - deletable;
                        return `Delete ${deletable} whitelist${deletable !== 1 ? 's' : ''}?${skipped ? ` ${skipped} system-default rule${skipped !== 1 ? 's' : ''} will be skipped.` : ''} This cannot be undone.`;
                    })()
                    : ''}
                confirmLabel="Delete"
                loading={confirmLoading}
                onConfirm={performBulkDelete}
                onCancel={() => setConfirmBulk(null)}
            />
        </div>
    );
};

export default Whitelists;
