import React, { useCallback, useEffect, useState } from 'react';
import { apiGet, apiPostWithMfa, apiPutWithMfa, apiDeleteWithMfa } from '../api/client';
import { useStepUp } from './StepUpMfaContext';
import { useToast } from '@shared/context/ToastContext';
import { DataTable, DataTableColumn } from '@shared/components/DataTable';
import { DetailField } from '@shared/components/cards/DetailField';
import { StatusBadge } from '@shared/components/cards/StatusBadge';
import { ToggleField, inputClass, labelClass } from '@shared/components/forms';
import { StepUpOps } from '@shared/generated';
import AuditTable from './AuditTable';

/**
 * A tenant's Kerberos realm bindings for Windows autoenrollment: which Active Directory forests
 * may present tickets, whose capabilities their principals act with, and the service keys that
 * seal the tickets. Keys go in three ways and never come back out; the only export is the setup
 * script for the forest.
 */
interface RealmKey { kvno: number; encryptionType: string; source: string; createdAt: string; retireAfter?: string | null }
interface Realm {
    id: string; tenantId: string; realm: string; dnsDomain: string; servicePrincipal: string;
    enrollmentUserId: string; enrollmentUsername?: string | null; allowMachines: boolean; allowUsers: boolean;
    isEnabled: boolean; notes?: string | null; createdAt: string; lastUsedAt?: string | null; keys: RealmKey[];
}
interface UserOption { id: string; username: string; isActive?: boolean; service?: boolean; scope?: string }

const blankRealm = { realm: '', dnsDomain: '', servicePrincipal: `HTTP/${window.location.hostname}`, enrollmentUserId: '', allowMachines: true, allowUsers: true, notes: '' };
const blankKey = { source: 'Password', accountName: 'svc-modularca-enroll', accountKind: 'User', password: '', kvno: '1', keytab: '' };

const fmt = (iso?: string | null) => (iso ? new Date(iso).toLocaleString() : '-');
const isLive = (k: RealmKey) => !k.retireAfter || new Date(k.retireAfter) > new Date();

const KerberosRealmsPanel: React.FC<{ tenantId: string; tenantName: string; caLabels: string[] }> = ({ tenantId, tenantName, caLabels }) => {
    const { requireStepUp } = useStepUp();
    const { showToast } = useToast();
    const base = `/api/v1/admin/tenants/${tenantId}/kerberos-realms`;

    const [realms, setRealms] = useState<Realm[]>([]);
    const [users, setUsers] = useState<UserOption[]>([]);
    const [tenantCaLabels, setTenantCaLabels] = useState<string[]>(caLabels);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState<string | null>(null);
    const [adding, setAdding] = useState(false);
    const [form, setForm] = useState(blankRealm);
    const [busy, setBusy] = useState(false);

    const load = useCallback(() => {
        setLoading(true);
        apiGet<Realm[]>(base)
            .then((r) => { setRealms(Array.isArray(r) ? r : []); setError(null); })
            .catch((e) => setError(e.message || 'Failed to load realms'))
            .finally(() => setLoading(false));
    }, [base]);

    useEffect(() => {
        load();
        // The tenant's own CAs, for the policy URL in the setup script.
        apiGet<any>('/api/v1/admin/authorities/hierarchy').then((data) => {
            const all = Array.isArray(data) ? data : (data.items || data.authorities || []);
            const labels: string[] = [];
            const walk = (list: any[]) => { for (const ca of list) { if (ca.tenantId === tenantId && ca.label) labels.push(ca.label); if (ca.children?.length) walk(ca.children); } };
            walk(all);
            if (labels.length > 0) setTenantCaLabels(labels);
        }).catch(() => {});
        // Service identities first: the natural choice for a forest to act as. People after.
        Promise.all([
            apiGet<any>('/api/v1/admin/service-identities').catch(() => []),
            apiGet<any>('/api/v1/admin/users').catch(() => []),
        ]).then(([svc, people]) => {
            const s = (Array.isArray(svc) ? svc : svc.items || []).filter((u: any) => u.isActive !== false)
                .map((u: any) => ({ id: u.id, username: u.username, service: true, scope: u.scope === 'ca' ? `CA ${u.caLabel}` : u.scope === 'tenant' ? `tenant ${u.tenantName}` : 'system' }));
            const p = (Array.isArray(people) ? people : people.items || []).filter((u: UserOption) => u.isActive !== false)
                .map((u: any) => ({ id: u.id, username: u.username, service: false }));
            setUsers([...s, ...p]);
        });
    }, [load]);

    const run = async (label: string, fn: () => Promise<void>) => {
        setBusy(true);
        try { await fn(); await new Promise<void>((r) => { load(); r(); }); }
        catch (e: any) { if (e?.message !== 'Step-up MFA cancelled') showToast('error', e?.message || `${label} failed`); }
        finally { setBusy(false); }
    };

    const create = () => run('Create', async () => {
        await apiPostWithMfa(base, {
            realm: form.realm, dnsDomain: form.dnsDomain || null, servicePrincipal: form.servicePrincipal,
            enrollmentUserId: form.enrollmentUserId, allowMachines: form.allowMachines, allowUsers: form.allowUsers, notes: form.notes || null,
        }, requireStepUp, StepUpOps.ManageKerberosRealm);
        showToast('success', `Realm ${form.realm.toUpperCase()} bound. Add a key next.`);
        setForm(blankRealm);
        setAdding(false);
    });

    const columns: DataTableColumn<Realm>[] = [
        { key: 'realm', header: 'Realm', defaultWidth: 220, minWidth: 160, exportValue: (r) => r.realm, render: (r) => <span className="font-mono text-xs text-gray-900 dark:text-white">{r.realm}</span> },
        { key: 'dns', header: 'DNS domain', defaultWidth: 180, exportValue: (r) => r.dnsDomain, render: (r) => <span className="text-xs text-gray-600 dark:text-gray-400">{r.dnsDomain}</span> },
        { key: 'spn', header: 'Service principal', defaultWidth: 200, exportValue: (r) => r.servicePrincipal, render: (r) => <span className="font-mono text-xs text-gray-600 dark:text-gray-400">{r.servicePrincipal}</span> },
        { key: 'user', header: 'Acts as', defaultWidth: 140, exportValue: (r) => r.enrollmentUsername || '', render: (r) => <span className="text-xs text-gray-600 dark:text-gray-400">{r.enrollmentUsername || '-'}</span> },
        { key: 'keys', header: 'Keys', defaultWidth: 200, truncate: false, exportValue: (r) => r.keys.map((k) => `${k.kvno}:${k.encryptionType}`).join(' '), render: (r) => (
            <span className="flex flex-wrap gap-1">
                {r.keys.length === 0 && <span className="text-xs text-amber-700 dark:text-amber-400">no key yet</span>}
                {r.keys.map((k) => (
                    <span key={`${k.kvno}-${k.encryptionType}`} className={`px-1.5 py-0.5 text-[10px] rounded border font-mono ${isLive(k) ? 'border-gray-300 dark:border-gray-600 text-gray-700 dark:text-gray-300' : 'border-gray-200 dark:border-gray-700 text-gray-400 line-through'}`}>
                        {k.kvno} · {k.encryptionType.replace('_CTS_HMAC_SHA1_96', '')}
                    </span>
                ))}
            </span>
        ) },
        { key: 'lastUsed', header: 'Last used', defaultWidth: 160, exportValue: (r) => r.lastUsedAt || '', render: (r) => <span className="text-xs text-gray-600 dark:text-gray-400">{fmt(r.lastUsedAt)}</span> },
        { key: 'status', header: 'Status', defaultWidth: 100, truncate: false, exportValue: (r) => (r.isEnabled ? 'Enabled' : 'Disabled'), render: (r) => <StatusBadge status={r.isEnabled ? 'enabled' : 'disabled'} label={r.isEnabled ? 'Enabled' : 'Disabled'} /> },
    ];

    return (
        <div className="space-y-3">
            <div className="flex items-start justify-between gap-3 flex-wrap">
                <div>
                    <h3 className="text-sm font-semibold text-gray-900 dark:text-white">Kerberos realms <span className="text-gray-500 font-normal">({realms.length})</span></h3>
                    <p className="text-xs text-gray-600 dark:text-gray-400 mt-1">
                        Active Directory forests whose machines and users may enroll from this tenant's CAs by Windows integrated authentication. Each forest holds a service account with the enrollment SPN; its key is imported here and never shown again.
                    </p>
                </div>
                <button onClick={() => setAdding((v) => !v)} className="px-3 py-1.5 text-xs font-semibold rounded bg-blue-600 text-white hover:bg-blue-700 transition-colors">
                    {adding ? 'Cancel' : 'Bind a forest'}
                </button>
            </div>

            {adding && (
                <div className="bg-gray-100 dark:bg-gray-800 border border-gray-300 dark:border-gray-700 rounded-lg p-4 space-y-3">
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                        <div>
                            <label className={labelClass}>Realm *</label>
                            <input className={inputClass} value={form.realm} onChange={(e) => setForm({ ...form, realm: e.target.value.toUpperCase() })} placeholder="CORP.CUSTOMER.LOCAL" />
                        </div>
                        <div>
                            <label className={labelClass}>DNS domain (defaults to the realm, lower-case)</label>
                            <input className={inputClass} value={form.dnsDomain} onChange={(e) => setForm({ ...form, dnsDomain: e.target.value })} placeholder="corp.customer.local" />
                        </div>
                        <div>
                            <label className={labelClass}>Service principal *</label>
                            <input className={`${inputClass} font-mono`} value={form.servicePrincipal} onChange={(e) => setForm({ ...form, servicePrincipal: e.target.value })} />
                        </div>
                        <div>
                            <label className={labelClass}>Enrollment identity * <span className="font-normal text-gray-500">(create one under Users, Service identities)</span></label>
                            <select className={inputClass} value={form.enrollmentUserId} onChange={(e) => setForm({ ...form, enrollmentUserId: e.target.value })}>
                                <option value="">-- identity the forest's principals act as --</option>
                                {users.some((u) => u.service) && (
                                    <optgroup label="Service identities (no sign-in)">
                                        {users.filter((u) => u.service).map((u) => <option key={u.id} value={u.id}>{u.username} · {u.scope}</option>)}
                                    </optgroup>
                                )}
                                <optgroup label="People">
                                    {users.filter((u) => !u.service).map((u) => <option key={u.id} value={u.id}>{u.username}</option>)}
                                </optgroup>
                            </select>
                        </div>
                        <ToggleField size="md" labelSide="left" label="Machines may enroll" description="Computer accounts (name$)" checked={form.allowMachines} onChange={(v) => setForm({ ...form, allowMachines: v })} />
                        <ToggleField size="md" labelSide="left" label="Users may enroll" description="User accounts" checked={form.allowUsers} onChange={(v) => setForm({ ...form, allowUsers: v })} />
                    </div>
                    <div className="flex justify-end">
                        <button disabled={busy || !form.realm || !form.servicePrincipal || !form.enrollmentUserId} onClick={create} className="px-3 py-1.5 text-xs font-semibold rounded bg-blue-600 text-white hover:bg-blue-700 disabled:opacity-50">Bind</button>
                    </div>
                </div>
            )}

            <DataTable<Realm>
                tableId={`kerberos-realms-${tenantId}`}
                rows={realms}
                rowKey={(r) => r.id}
                loading={loading}
                error={error}
                empty="No forests bound. Bind one to enable Windows integrated authentication for this tenant's CAs."
                columns={columns}
                disableExport
                renderDrawer={(r) => <RealmDrawer realm={r} base={base} tenantName={tenantName} caLabels={tenantCaLabels} users={users} onChanged={load} />}
                drawerTitle={(r) => r.realm}
            />
        </div>
    );
};

const RealmDrawer: React.FC<{ realm: Realm; base: string; tenantName: string; caLabels: string[]; users: UserOption[]; onChanged: () => void }> = ({ realm, base, tenantName, caLabels, users, onChanged }) => {
    const { requireStepUp } = useStepUp();
    const { showToast } = useToast();
    const [tab, setTab] = useState<'overview' | 'keys' | 'setup' | 'audit'>('overview');
    const [key, setKey] = useState(blankKey);
    const [generated, setGenerated] = useState<string | null>(null);
    const [script, setScript] = useState<string | null>(null);
    const [scriptCa, setScriptCa] = useState(caLabels[0] || '');
    const [busy, setBusy] = useState(false);
    const path = `${base}/${realm.id}`;

    useEffect(() => { setTab('overview'); setGenerated(null); setScript(null); }, [realm.id]);

    const run = async (label: string, fn: () => Promise<void>) => {
        setBusy(true);
        try { await fn(); onChanged(); }
        catch (e: any) { if (e?.message !== 'Step-up MFA cancelled') showToast('error', e?.message || `${label} failed`); }
        finally { setBusy(false); }
    };

    const save = (patch: Partial<Realm>) => run('Update', async () => {
        const next = { ...realm, ...patch };
        await apiPutWithMfa(path, {
            realm: next.realm, dnsDomain: next.dnsDomain, servicePrincipal: next.servicePrincipal, enrollmentUserId: next.enrollmentUserId,
            allowMachines: next.allowMachines, allowUsers: next.allowUsers, isEnabled: next.isEnabled, notes: next.notes || null,
        }, requireStepUp, StepUpOps.ManageKerberosRealm, realm.id);
    });

    const addKey = () => run('Add key', async () => {
        const body: any = { source: key.source, accountName: key.accountName, accountKind: key.accountKind, kvno: parseInt(key.kvno, 10) || 1 };
        if (key.source === 'Password') body.password = key.password;
        if (key.source === 'Keytab') body.keytab = key.keytab;
        const result = await apiPostWithMfa<any>(`${path}/keys`, body, requireStepUp, StepUpOps.ManageKerberosRealm, realm.id);
        setKey({ ...blankKey, accountName: key.accountName, accountKind: key.accountKind, kvno: String((parseInt(key.kvno, 10) || 1) + 1) });
        if (result?.password) setGenerated(result.password);
        showToast('success', `Key version ${result.kvno} stored (${(result.encryptionTypes || []).length} types${result.retired ? `, ${result.retired} older retired` : ''}).`);
    });

    const retire = (kvno: number) => run('Retire', async () => {
        await apiPostWithMfa(`${path}/keys/${kvno}/retire`, {}, requireStepUp, StepUpOps.ManageKerberosRealm, realm.id);
    });

    const remove = () => run('Delete', async () => {
        await apiDeleteWithMfa(path, requireStepUp, StepUpOps.ManageKerberosRealm, realm.id);
        showToast('success', `Realm ${realm.realm} deleted.`);
    });

    const fetchScript = () => {
        const q = new URLSearchParams();
        if (scriptCa) q.set('caLabel', scriptCa);
        if (key.accountName) q.set('accountName', key.accountName);
        apiGet<{ script: string }>(`${path}/setup-script?${q}`).then((r) => setScript(r.script)).catch((e) => showToast('error', e.message));
    };

    const onKeytabFile = (file: File | null) => {
        if (!file) return;
        const reader = new FileReader();
        reader.onload = () => {
            const bytes = new Uint8Array(reader.result as ArrayBuffer);
            let bin = '';
            bytes.forEach((b) => { bin += String.fromCharCode(b); });
            setKey((k) => ({ ...k, keytab: btoa(bin) }));
        };
        reader.readAsArrayBuffer(file);
    };

    const tabBtn = (k: typeof tab, label: string) => (
        <button key={k} onClick={() => setTab(k)} className={`px-3 py-1.5 text-xs font-medium border-b-2 -mb-px transition-colors ${tab === k ? 'border-blue-600 text-blue-700 dark:text-blue-400' : 'border-transparent text-gray-600 dark:text-gray-400 hover:text-gray-900 dark:hover:text-white'}`}>{label}</button>
    );

    return (
        <div className="space-y-3">
            <div className="flex items-center justify-between gap-2 flex-wrap">
                <StatusBadge status={realm.isEnabled ? 'enabled' : 'disabled'} label={realm.isEnabled ? 'Enabled' : 'Disabled'} />
                <span className="flex items-center gap-1.5 flex-wrap">
                    <button disabled={busy} onClick={() => save({ isEnabled: !realm.isEnabled })} className="px-2.5 py-1 text-xs rounded border bg-gray-100 dark:bg-gray-700 text-gray-700 dark:text-gray-300 border-gray-300 dark:border-gray-600 hover:bg-gray-200 dark:hover:bg-gray-600 disabled:opacity-40">{realm.isEnabled ? 'Disable' : 'Enable'}</button>
                    <button disabled={busy} onClick={remove} className="px-2.5 py-1 text-xs rounded border bg-red-50 dark:bg-red-900/50 text-red-800 dark:text-red-300 border-red-300 dark:border-red-700 hover:bg-red-100 dark:hover:bg-red-900 disabled:opacity-40">Delete</button>
                </span>
            </div>

            <div className="flex gap-1 border-b border-gray-200 dark:border-gray-800">
                {tabBtn('overview', 'Overview')}{tabBtn('keys', 'Keys')}{tabBtn('setup', 'Setup script')}{tabBtn('audit', 'Audit')}
            </div>

            {tab === 'overview' && (
                <div className="space-y-3">
                    <div className="grid grid-cols-1 sm:grid-cols-2 gap-x-4">
                        <DetailField label="Realm" value={realm.realm} mono />
                        <DetailField label="DNS domain" value={realm.dnsDomain} mono />
                        <DetailField label="Service principal" value={realm.servicePrincipal} mono />
                        <DetailField label="Acts as" value={realm.enrollmentUsername || realm.enrollmentUserId} />
                        <DetailField label="Machines" value={realm.allowMachines ? 'May enroll' : 'Refused'} />
                        <DetailField label="Users" value={realm.allowUsers ? 'May enroll' : 'Refused'} />
                        <DetailField label="Last ticket accepted" value={fmt(realm.lastUsedAt)} />
                        <DetailField label="Bound" value={fmt(realm.createdAt)} />
                    </div>
                    <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                        <div>
                            <label className={labelClass}>Enrollment identity</label>
                            <select className={inputClass} value={realm.enrollmentUserId} disabled={busy} onChange={(e) => save({ enrollmentUserId: e.target.value })}>
                                {users.filter((u) => u.service).map((u) => <option key={u.id} value={u.id}>{u.username} · {u.scope}</option>)}
                                {users.filter((u) => !u.service).map((u) => <option key={u.id} value={u.id}>{u.username}</option>)}
                                {!users.some((u) => u.id === realm.enrollmentUserId) && <option value={realm.enrollmentUserId}>{realm.enrollmentUsername || realm.enrollmentUserId}</option>}
                            </select>
                        </div>
                        <div className="space-y-1">
                            <ToggleField size="md" labelSide="left" label="Machines may enroll" checked={realm.allowMachines} onChange={(v) => save({ allowMachines: v })} />
                            <ToggleField size="md" labelSide="left" label="Users may enroll" checked={realm.allowUsers} onChange={(v) => save({ allowUsers: v })} />
                        </div>
                    </div>
                </div>
            )}

            {tab === 'keys' && (
                <div className="space-y-3">
                    {generated && (
                        <div className="rounded border border-amber-300 dark:border-amber-700 bg-amber-50 dark:bg-amber-900/30 p-3 text-xs text-amber-900 dark:text-amber-200 space-y-1">
                            <div className="font-semibold">Set this password on the service account now. It will not be shown again.</div>
                            <div className="flex items-center gap-2">
                                <code className="font-mono text-sm break-all">{generated}</code>
                                <button onClick={() => navigator.clipboard.writeText(generated).then(() => showToast('success', 'Password copied'))} className="px-2 py-0.5 rounded border border-amber-400 text-[11px] hover:bg-amber-100 dark:hover:bg-amber-900">Copy</button>
                                <button onClick={() => setGenerated(null)} className="px-2 py-0.5 rounded border border-amber-400 text-[11px] hover:bg-amber-100 dark:hover:bg-amber-900">Dismiss</button>
                            </div>
                        </div>
                    )}

                    <table className="w-full text-xs">
                        <thead><tr className="text-left text-gray-500 dark:text-gray-400"><th className="py-1 pr-2">Version</th><th className="py-1 pr-2">Type</th><th className="py-1 pr-2">Source</th><th className="py-1 pr-2">Added</th><th className="py-1 pr-2">Retires</th><th /></tr></thead>
                        <tbody>
                            {realm.keys.length === 0 && <tr><td colSpan={6} className="py-2 text-amber-700 dark:text-amber-400">No key yet. Tickets from this realm are refused until one is added.</td></tr>}
                            {realm.keys.map((k) => (
                                <tr key={`${k.kvno}-${k.encryptionType}`} className={`border-t border-gray-200 dark:border-gray-800 ${isLive(k) ? '' : 'text-gray-400'}`}>
                                    <td className="py-1 pr-2 font-mono">{k.kvno}</td>
                                    <td className="py-1 pr-2 font-mono">{k.encryptionType}</td>
                                    <td className="py-1 pr-2">{k.source}</td>
                                    <td className="py-1 pr-2">{fmt(k.createdAt)}</td>
                                    <td className="py-1 pr-2">{k.retireAfter ? fmt(k.retireAfter) : 'live'}</td>
                                    <td className="py-1 text-right">{isLive(k) && <button disabled={busy} onClick={() => retire(k.kvno)} className="text-[11px] text-red-700 dark:text-red-400 hover:underline">Retire</button>}</td>
                                </tr>
                            ))}
                        </tbody>
                    </table>

                    <div className="bg-gray-100 dark:bg-gray-800 border border-gray-300 dark:border-gray-700 rounded-lg p-3 space-y-2">
                        <div className="text-xs font-semibold text-gray-900 dark:text-white">Add a key version</div>
                        <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
                            <div>
                                <label className={labelClass}>How</label>
                                <select className={inputClass} value={key.source} onChange={(e) => setKey({ ...key, source: e.target.value })}>
                                    <option value="Password">Derive from the account password</option>
                                    <option value="Generated">Generate a password for me</option>
                                    <option value="Keytab">Upload a keytab file</option>
                                </select>
                            </div>
                            <div>
                                <label className={labelClass}>Key version (kvno)</label>
                                <input className={inputClass} type="number" min={1} value={key.kvno} onChange={(e) => setKey({ ...key, kvno: e.target.value })} />
                            </div>
                            {key.source !== 'Keytab' && (
                                <>
                                    <div>
                                        <label className={labelClass}>Account name</label>
                                        <input className={`${inputClass} font-mono`} value={key.accountName} onChange={(e) => setKey({ ...key, accountName: e.target.value })} />
                                    </div>
                                    <div>
                                        <label className={labelClass}>Account kind (decides the salt)</label>
                                        <select className={inputClass} value={key.accountKind} onChange={(e) => setKey({ ...key, accountKind: e.target.value })}>
                                            <option value="User">User (service) account</option>
                                            <option value="Computer">Computer account</option>
                                        </select>
                                    </div>
                                </>
                            )}
                            {key.source === 'Password' && (
                                <div className="sm:col-span-2">
                                    <label className={labelClass}>Password (used once, not stored)</label>
                                    {/* A text field masked by CSS, not a password field: the browser must not offer to save a
                                        credential that ModularCA itself never stores. */}
                                    <input className={inputClass} type="text" autoComplete="off" autoCorrect="off" spellCheck={false} data-lpignore="true" data-1p-ignore="true"
                                        style={{ WebkitTextSecurity: 'disc' } as React.CSSProperties}
                                        value={key.password} onChange={(e) => setKey({ ...key, password: e.target.value })} />
                                </div>
                            )}
                            {key.source === 'Keytab' && (
                                <div className="sm:col-span-2">
                                    <label className={labelClass}>Keytab (AES entries for {realm.servicePrincipal}@{realm.realm}; the file is not kept)</label>
                                    <input className={inputClass} type="file" onChange={(e) => onKeytabFile(e.target.files?.[0] || null)} />
                                </div>
                            )}
                        </div>
                        <div className="flex justify-end">
                            <button disabled={busy || (key.source === 'Password' && !key.password) || (key.source === 'Keytab' && !key.keytab) || (key.source !== 'Keytab' && !key.accountName)} onClick={addKey} className="px-3 py-1.5 text-xs font-semibold rounded bg-blue-600 text-white hover:bg-blue-700 disabled:opacity-50">Add key</button>
                        </div>
                    </div>
                </div>
            )}

            {tab === 'setup' && (
                <div className="space-y-2">
                    <p className="text-xs text-gray-600 dark:text-gray-400">PowerShell for a domain administrator of {realm.realm}, plus the Group Policy values. It contains no secret.</p>
                    <div className="flex items-end gap-2 flex-wrap">
                        <div>
                            <label className={labelClass}>Policy URL for CA</label>
                            <select className={inputClass} value={scriptCa} onChange={(e) => setScriptCa(e.target.value)}>
                                <option value="">(none)</option>
                                {caLabels.map((l) => <option key={l} value={l}>{l}</option>)}
                            </select>
                        </div>
                        <button onClick={fetchScript} className="px-3 py-1.5 text-xs font-semibold rounded bg-gray-200 dark:bg-gray-700 text-gray-800 dark:text-gray-200 hover:bg-gray-300 dark:hover:bg-gray-600">Generate</button>
                        {script && <button onClick={() => navigator.clipboard.writeText(script).then(() => showToast('success', 'Script copied'))} className="px-3 py-1.5 text-xs font-semibold rounded bg-blue-600 text-white hover:bg-blue-700">Copy</button>}
                    </div>
                    {script && <pre className="text-[11px] font-mono whitespace-pre-wrap bg-gray-100 dark:bg-gray-900 border border-gray-300 dark:border-gray-700 rounded p-3 overflow-x-auto">{script}</pre>}
                </div>
            )}

            {tab === 'audit' && <AuditTable tab="General" target={{ type: 'KerberosRealm', id: realm.id }} pageSize={10} />}
        </div>
    );
};

export default KerberosRealmsPanel;
