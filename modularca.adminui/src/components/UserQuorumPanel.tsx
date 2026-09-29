import React, { useEffect, useState, useCallback } from 'react';
import type { NoticeInput } from '@shared/notifications/notice';
import { InlineNotice } from '@shared/components/InlineNotice';
import { errorNotice } from '@shared-auth/api/notices';
import { apiGet, apiPutWithMfa } from '../api/client';
import { useStepUp } from './StepUpMfaContext';
import { useToast } from '@shared/context/ToastContext';
import { useAuth } from '../context/AuthContext';
import { StepUpOps } from '@shared/generated';
import { FieldHint } from '@shared/components/forms';

/** Same sentence as on Settings → Security Policy; the number is "other people", never "people". */
const INITIATOR_EXCLUDED = 'The initiator is always excluded, so the effective minimum is 1 other approver.';

export interface CaQ { id: string; name: string; label?: string; override: number | null; effective: number; }
export interface TenantQ { id: string; name: string; override: number | null; effective: number; cas: CaQ[]; }
/** The instance's CA-level quorum (the ceiling for instance CAs, which have no tenant) and those CAs. */
export interface InstanceQ { id: null; name: string; override: number | null; effective: number; cas: CaQ[]; }
export interface QuorumData { system: { quorum: number }; instance?: InstanceQ; tenants: TenantQ[]; }

/* one quorum row (system / tenant / CA). Controlled: the parent owns the value. Read-only renders the
   value as text; `trailing` adds an inline control (e.g. a per-row Save where editing is row-local). */
export const QuorumRow: React.FC<{
    label: React.ReactNode;
    sublabel?: React.ReactNode;
    value: string;               // current input value ('' = inherit)
    onChange: (next: string) => void;
    override: number | null;     // source override (null = inheriting); for System it's the value
    effective: number;
    allowInherit: boolean;       // false for System (must always have a value)
    max?: number;                // ceiling (tenant effective, for CAs) — drives the invalid-border hint
    readOnly?: boolean;          // render values without inputs (View mode)
    trailing?: React.ReactNode;  // inline control at the end of the row (editable rows only)
    className?: string;
}> = ({ label, sublabel, value, onChange, override, effective, allowInherit, max, readOnly, trailing, className }) => {
    const parsed = value.trim() === '' ? null : parseInt(value, 10);
    const tooHigh = max != null && parsed != null && parsed > max;

    return (
        <div className={`flex items-center gap-3 px-3 py-2 ${className || ''}`}>
            <div className="min-w-0 flex-1">
                <div className="text-sm text-gray-900 dark:text-white truncate">{label}</div>
                {sublabel && <div className="text-[10px] text-gray-500 truncate">{sublabel}</div>}
            </div>
            {readOnly ? (
                <span className="w-24 text-xs text-right text-gray-700 dark:text-gray-300 shrink-0">
                    {override != null ? override : (allowInherit ? 'inherit' : effective)}
                </span>
            ) : (
                <input inputMode="numeric" value={value}
                    placeholder={allowInherit ? `inherit (${effective})` : ''}
                    title={tooHigh ? `Can't exceed the tenant's quorum (${max})` : allowInherit ? 'Blank = inherit the parent value' : undefined}
                    onChange={(e) => onChange(e.target.value.replace(/\D/g, ''))}
                    className={`w-24 px-2 py-1 text-xs bg-gray-50 dark:bg-gray-900 border rounded text-gray-900 dark:text-white focus:outline-none ${tooHigh ? 'border-red-500' : 'border-gray-300 dark:border-gray-700 focus:border-blue-500'}`} />
            )}
            <span className="text-[11px] text-gray-500 w-28 shrink-0">
                effective {effective}{allowInherit && override == null ? ' · inherited' : ''}
            </span>
            {!readOnly && trailing}
        </div>
    );
};

/**
 * System-scope controlled-user approval quorum (standalone), and the instance's CA-level quorum
 * with its CAs (the system signing CA, SSH CAs: no tenant). Tenant- and CA-scope quorums are
 * edited on each tenant's detail page (/tenants/:id). Drop this card on the Tenants & Quotas list
 * page. Self-saving (step-up MFA) since it isn't part of any page-level edit batch; a non-super
 * change to the instance or an instance CA opens a policy-change ceremony (202).
 */
export const SystemQuorumCard: React.FC = () => {
    const { showToast } = useToast();
    const { requireStepUp } = useStepUp();
    const { user } = useAuth();
    const isSuper = !!(user as any)?.isSuper;
    const [system, setSystem] = useState<{ quorum: number } | null>(null);
    const [instance, setInstance] = useState<InstanceQ | null>(null);
    const [val, setVal] = useState('');
    const [instanceVal, setInstanceVal] = useState('');
    const [caVals, setCaVals] = useState<Record<string, string>>({});
    const [saving, setSaving] = useState(false);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState<NoticeInput | null>(null);

    const load = useCallback(() => {
        setLoading(true);
        apiGet<QuorumData>('/api/v1/admin/user-quorum')
            .then((d) => {
                setSystem(d.system); setVal(String(d.system.quorum));
                setInstance(d.instance ?? null);
                setInstanceVal(d.instance?.override != null ? String(d.instance.override) : '');
                setCaVals(Object.fromEntries((d.instance?.cas ?? []).map((ca) => [ca.id, ca.override != null ? String(ca.override) : ''])));
                setError(null);
            })
            .catch((e) => setError(errorNotice(e, 'Failed to load')))
            .finally(() => setLoading(false));
    }, []);
    useEffect(() => { load(); }, [load]);

    const parsed = val.trim() === '' ? null : parseInt(val, 10);
    const changed = !!system && parsed != null && parsed !== system.quorum;

    const save = async () => {
        if (!changed || parsed == null) return;
        setSaving(true);
        try {
            await apiPutWithMfa('/api/v1/admin/security-policy', { userQuorum: parsed }, requireStepUp, StepUpOps.UpdateConfig);
            showToast('success', 'System quorum updated'); load();
        } catch (err: any) { if (err?.message !== 'Step-up MFA cancelled') showToast('error', err.message || 'Failed'); }
        finally { setSaving(false); }
    };

    const num = (s: string) => (s.trim() === '' ? null : parseInt(s, 10));
    const saveScoped = async (url: string, quorum: number | null, target?: string) => {
        setSaving(true);
        try {
            const result = await apiPutWithMfa<any>(url, { quorum }, requireStepUp, StepUpOps.UpdateTenantSettings, target);
            if (result?.ceremonyId) showToast('info', 'Quorum change ceremony started. Approve at /admin/ceremonies/' + result.ceremonyId);
            else showToast('success', 'Quorum updated');
            load();
        } catch (err: any) { if (err?.message !== 'Step-up MFA cancelled') showToast('error', err.message || 'Failed'); }
        finally { setSaving(false); }
    };
    const saveButton = (disabled: boolean, onClick: () => void) => (
        <button onClick={onClick} disabled={disabled || saving}
            className="px-2.5 py-1 text-[11px] bg-blue-600 text-white rounded hover:bg-blue-700 disabled:opacity-40 disabled:cursor-not-allowed shrink-0">
            {saving ? '…' : 'Save'}
        </button>
    );

    return (
        <div className="bg-gray-100 dark:bg-gray-800 border border-gray-300 dark:border-gray-700 rounded-lg overflow-hidden">
            <div className="px-4 py-3 border-b border-gray-300 dark:border-gray-700">
                <h3 className="text-sm font-semibold text-gray-900 dark:text-white">Controlled-User Approval Quorum</h3>
                <p className="text-xs text-gray-600 dark:text-gray-400 mt-1">
                    Approvals required to promote/demote/delete a privileged user. The <strong>System</strong> quorum and the <strong>Instance</strong> quorum (for the instance's own CAs, which belong to no tenant) are set here; <strong>tenant</strong> and per-<strong>CA</strong> quorums (which inherit from System and may require fewer, never more) are set on each tenant's page. Separate from the tenant <em>key</em>-ceremony quorum.
                </p>
            </div>

            {loading && <div className="p-4 text-sm text-gray-600 dark:text-gray-400 text-center">Loading…</div>}
            {error && <InlineNotice notice={error} />}
            {!loading && !error && system && (<>
                <QuorumRow
                    label="System" sublabel="System administrators · standalone"
                    value={val} onChange={setVal}
                    override={system.quorum} effective={system.quorum} allowInherit={false}
                    readOnly={!isSuper}
                    trailing={
                        <button onClick={save} disabled={!changed || saving}
                            className="px-2.5 py-1 text-[11px] bg-blue-600 text-white rounded hover:bg-blue-700 disabled:opacity-40 disabled:cursor-not-allowed shrink-0">
                            {saving ? '…' : 'Save'}
                        </button>
                    } />
                <FieldHint className="px-3 pb-3">{INITIATOR_EXCLUDED}</FieldHint>
                {!isSuper && (
                    <p className="px-3 pb-3 -mt-1 text-[11px] text-gray-500">
                        Only a system super-administrator can change the System quorum. Tenant and per-CA quorums are set on each tenant's page (and start a ceremony for non-super admins).
                    </p>
                )}
                {instance && (
                    <div className="border-t border-gray-300 dark:border-gray-700">
                        <QuorumRow
                            label="Instance" sublabel="Instance CA administrators / operators · ceiling for instance CAs"
                            value={instanceVal} onChange={setInstanceVal}
                            override={instance.override} effective={instance.effective} allowInherit
                            className="border-b border-gray-200 dark:border-gray-700/60 bg-gray-50/60 dark:bg-gray-900/30"
                            trailing={saveButton(num(instanceVal) === instance.override || (num(instanceVal) ?? 1) < 1,
                                () => saveScoped('/api/v1/admin/user-quorum/instance', num(instanceVal)))} />
                        {instance.cas.map((ca) => (
                            <QuorumRow key={ca.id}
                                label={ca.label || ca.name} sublabel="Instance CA administrators / operators"
                                value={caVals[ca.id] ?? ''} onChange={(v) => setCaVals((m) => ({ ...m, [ca.id]: v }))}
                                override={ca.override} effective={ca.effective} allowInherit max={instance.effective}
                                className="border-b border-gray-200 dark:border-gray-700/60 last:border-b-0 bg-gray-50/40 dark:bg-gray-900/20 pl-8"
                                trailing={saveButton(num(caVals[ca.id] ?? '') === ca.override,
                                    () => saveScoped(`/api/v1/admin/user-quorum/ca/${ca.id}`, num(caVals[ca.id] ?? ''), ca.id))} />
                        ))}
                    </div>
                )}
            </>)}
        </div>
    );
};

/**
 * Tenant- and CA-scope controlled-user approval quorums for one tenant, as a section inside
 * TenantDetail. Fully controlled — the parent owns the values and the (page-level) save, so this just
 * renders the rows. Read-only in View mode; editable in Edit mode.
 */
export const TenantUserQuorumSection: React.FC<{
    quorum: TenantQ | null;
    readOnly: boolean;
    tenantValue: string;
    onTenantChange: (next: string) => void;
    caValues: Record<string, string>;
    onCaChange: (caId: string, next: string) => void;
}> = ({ quorum, readOnly, tenantValue, onTenantChange, caValues, onCaChange }) => {
    if (!quorum) return <div className="py-3 text-xs text-gray-500 text-center border border-gray-300 dark:border-gray-700 rounded-lg">No quorum data for this tenant.</div>;

    return (
        <div className="border border-gray-300 dark:border-gray-700 rounded-lg overflow-hidden">
            <div className="flex items-center gap-3 px-3 py-2 border-b border-gray-300 dark:border-gray-700 bg-gray-50/60 dark:bg-gray-900/40 text-[10px] text-gray-500 font-semibold uppercase tracking-wide">
                <span className="flex-1">Scope</span>
                <span className="w-24 text-right shrink-0">Required</span>
                <span className="w-28 shrink-0">Effective</span>
            </div>
            <QuorumRow
                label={quorum.name} sublabel="Org administrators / operators"
                value={tenantValue} onChange={onTenantChange}
                override={quorum.override} effective={quorum.effective} allowInherit readOnly={readOnly}
                className="border-b border-gray-200 dark:border-gray-700/60 bg-gray-50/60 dark:bg-gray-900/30" />
            {quorum.cas.length === 0 ? (
                <div className="pl-8 pr-3 py-2 text-[11px] text-gray-500">No CAs in this tenant.</div>
            ) : quorum.cas.map((ca) => (
                <QuorumRow key={ca.id}
                    label={ca.label || ca.name} sublabel="CA administrators / operators"
                    value={caValues[ca.id] ?? ''} onChange={(s) => onCaChange(ca.id, s)}
                    override={ca.override} effective={ca.effective} allowInherit max={quorum.effective} readOnly={readOnly}
                    className="border-b border-gray-200 dark:border-gray-700/60 last:border-b-0 bg-gray-50/40 dark:bg-gray-900/20 pl-8" />
            ))}
            <div className="px-3 py-2 text-[11px] text-gray-500 border-t border-gray-200 dark:border-gray-700/60">
                {!readOnly && <>Blank = inherit the parent value. A CA can require fewer approvals than its tenant, never more. </>}
                {INITIATOR_EXCLUDED}
            </div>
        </div>
    );
};

export default SystemQuorumCard;
