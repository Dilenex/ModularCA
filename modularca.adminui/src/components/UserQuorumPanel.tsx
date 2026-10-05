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
import { ceremonyLink } from '../pages/ceremonyLinks';
import { quorumProblem } from './userQuorum';

/** Same sentence as on Settings → Security Policy; the number is "other people", never "people". */
const INITIATOR_EXCLUDED = 'The initiator is always excluded, so the effective minimum is 1 other approver.';

export interface CaQ { id: string; name: string; label?: string; override: number | null; effective: number; }
export interface SpaceQ { id: string; name: string; override: number | null; effective: number; cas: CaQ[]; }
/** The instance's CA-level quorum (the ceiling for instance CAs, which have no space) and those CAs. */
export interface InstanceQ { id: null; name: string; override: number | null; effective: number; cas: CaQ[]; }
export interface QuorumData { system: { quorum: number }; instance?: InstanceQ; spaces: SpaceQ[]; }

/* one quorum row (system / space / CA). Controlled: the parent owns the value. Read-only renders the
   value as text; `trailing` adds an inline control (e.g. a per-row Save where editing is row-local). */
export const QuorumRow: React.FC<{
    label: React.ReactNode;
    sublabel?: React.ReactNode;
    value: string;               // current input value ('' = inherit)
    onChange: (next: string) => void;
    override: number | null;     // source override (null = inheriting); for System it's the value
    effective: number;
    allowInherit: boolean;       // false for System (must always have a value)
    max?: number;                // ceiling (space effective, for CAs) — drives the invalid-border hint
    maxLabel?: string;           // names the ceiling in the hint
    invalid?: boolean;           // the parent found the value unsaveable; red border
    readOnly?: boolean;          // render values without inputs (View mode)
    trailing?: React.ReactNode;  // inline control at the end of the row (editable rows only)
    className?: string;
}> = ({ label, sublabel, value, onChange, override, effective, allowInherit, max, maxLabel = "the space's quorum", invalid, readOnly, trailing, className }) => {
    const parsed = value.trim() === '' ? null : parseInt(value, 10);
    const tooHigh = max != null && parsed != null && parsed > max;
    const flagged = tooHigh || !!invalid;

    return (
        <div className={`flex items-center gap-3 px-3 py-2 ${className || ''}`}>
            <div className="min-w-0 flex-1">
                <div className="text-sm text-ink truncate">{label}</div>
                {sublabel && <div className="text-[10px] text-ink-muted truncate">{sublabel}</div>}
            </div>
            {readOnly ? (
                <span className="w-24 text-xs text-right text-ink shrink-0">
                    {override != null ? override : (allowInherit ? 'inherit' : effective)}
                </span>
            ) : (
                <input inputMode="numeric" value={value}
                    placeholder={allowInherit ? `inherit (${effective})` : ''}
                    title={tooHigh ? `Can't exceed ${maxLabel} (${max})` : allowInherit ? 'Blank = inherit the parent value' : undefined}
                    onChange={(e) => onChange(e.target.value.replace(/\D/g, ''))}
                    className={`w-24 px-2 py-1 text-xs bg-raised border rounded text-ink focus:outline-none ${flagged ? 'border-crit' : 'border-line-strong focus:border-accent'}`} />
            )}
            <span className="text-[11px] text-ink-muted w-28 shrink-0">
                effective {effective}{allowInherit && override == null ? ' · inherited' : ''}
            </span>
            {!readOnly && trailing}
        </div>
    );
};

/**
 * System-scope controlled-user approval quorum (standalone), and the instance's CA-level quorum
 * with its CAs (the system signing CA, SSH CAs: no space). Space- and CA-scope quorums are
 * edited on each space's detail page (/spaces/:id). Drop this card on the Spaces & Quotas list
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
    const systemProblem = changed ? quorumProblem(val, { allowInherit: false }) : null;

    const save = async () => {
        if (!changed || parsed == null || systemProblem) return;
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
            const result = await apiPutWithMfa<any>(url, { quorum }, requireStepUp, StepUpOps.UpdateSpaceSettings, target);
            if (result?.ceremonyId) showToast('info', `Quorum change ceremony started. Approve it at ${ceremonyLink(result.ceremonyId)}`);
            else showToast('success', 'Quorum updated');
            load();
        } catch (err: any) { if (err?.message !== 'Step-up MFA cancelled') showToast('error', err.message || 'Failed'); }
        finally { setSaving(false); }
    };
    const saveButton = (disabled: boolean, onClick: () => void) => (
        <button onClick={onClick} disabled={disabled || saving}
            className="px-2.5 py-1 text-[11px] bg-accent text-on-accent rounded hover:bg-accent-hover disabled:opacity-40 disabled:cursor-not-allowed shrink-0">
            {saving ? '…' : 'Save'}
        </button>
    );

    return (
        <div className="bg-raised border border-line rounded-lg overflow-hidden">
            <div className="px-4 py-3 border-b border-line">
                <h3 className="text-sm font-semibold text-ink">Controlled-User Approval Quorum</h3>
                <p className="text-xs text-ink-muted mt-1">
                    Approvals required to promote/demote/delete a privileged user. The <strong>System</strong> quorum and the <strong>Instance</strong> quorum (for the instance's own CAs, which belong to no space) are set here; <strong>space</strong> and per-<strong>CA</strong> quorums (which inherit from System and may require fewer, never more) are set on each space's page. Separate from the space <em>key</em>-ceremony quorum.
                </p>
            </div>

            {loading && <div className="p-4 text-sm text-ink-muted text-center">Loading…</div>}
            {error && <InlineNotice notice={error} />}
            {!loading && !error && system && (<>
                <QuorumRow
                    label="System" sublabel="System administrators · standalone"
                    value={val} onChange={setVal}
                    override={system.quorum} effective={system.quorum} allowInherit={false}
                    readOnly={!isSuper} invalid={!!systemProblem}
                    trailing={
                        <button onClick={save} disabled={!changed || !!systemProblem || saving}
                            className="px-2.5 py-1 text-[11px] bg-accent text-on-accent rounded hover:bg-accent-hover disabled:opacity-40 disabled:cursor-not-allowed shrink-0">
                            {saving ? '…' : 'Save'}
                        </button>
                    } />
                {isSuper && systemProblem && <FieldHint tone="warn" className="px-3">{systemProblem}</FieldHint>}
                <FieldHint className="px-3 pb-3">{INITIATOR_EXCLUDED}</FieldHint>
                {!isSuper && (
                    <p className="px-3 pb-3 -mt-1 text-[11px] text-ink-muted">
                        Only a system super-administrator can change the System quorum. Space and per-CA quorums are set on each space's page (and start a ceremony for non-super admins).
                    </p>
                )}
                {instance && (() => {
                    const instanceProblem = quorumProblem(instanceVal, { allowInherit: true });
                    return (
                        <div className="border-t border-line">
                            <QuorumRow
                                label="Instance" sublabel="Instance CA administrators / operators · ceiling for instance CAs"
                                value={instanceVal} onChange={setInstanceVal}
                                override={instance.override} effective={instance.effective} allowInherit invalid={!!instanceProblem}
                                className="border-b border-line bg-sunken"
                                trailing={saveButton(num(instanceVal) === instance.override || !!instanceProblem,
                                    () => saveScoped('/api/v1/admin/user-quorum/instance', num(instanceVal)))} />
                            {instanceProblem && <FieldHint tone="warn" className="px-3 pb-2">{instanceProblem}</FieldHint>}
                            {instance.cas.map((ca) => {
                                const caProblem = quorumProblem(caVals[ca.id] ?? '', { allowInherit: true, max: instance.effective, maxLabel: "the instance's quorum" });
                                return (
                                    <React.Fragment key={ca.id}>
                                        <QuorumRow
                                            label={ca.label || ca.name} sublabel="Instance CA administrators / operators"
                                            value={caVals[ca.id] ?? ''} onChange={(v) => setCaVals((m) => ({ ...m, [ca.id]: v }))}
                                            override={ca.override} effective={ca.effective} allowInherit max={instance.effective}
                                            maxLabel="the instance's quorum" invalid={!!caProblem}
                                            className="border-b border-line last:border-b-0 bg-sunken pl-8"
                                            trailing={saveButton(num(caVals[ca.id] ?? '') === ca.override || !!caProblem,
                                                () => saveScoped(`/api/v1/admin/user-quorum/ca/${ca.id}`, num(caVals[ca.id] ?? ''), ca.id))} />
                                        {caProblem && <FieldHint tone="warn" className="pl-8 pr-3 pb-2">{caProblem}</FieldHint>}
                                    </React.Fragment>
                                );
                            })}
                        </div>
                    );
                })()}
            </>)}
        </div>
    );
};

/**
 * Space- and CA-scope controlled-user approval quorums for one space, as a section inside
 * SpaceDetail. Fully controlled — the parent owns the values and the (page-level) save, so this just
 * renders the rows. Read-only in View mode; editable in Edit mode.
 */
export const SpaceUserQuorumSection: React.FC<{
    quorum: SpaceQ | null;
    readOnly: boolean;
    spaceValue: string;
    onSpaceChange: (next: string) => void;
    caValues: Record<string, string>;
    onCaChange: (caId: string, next: string) => void;
}> = ({ quorum, readOnly, spaceValue, onSpaceChange, caValues, onCaChange }) => {
    if (!quorum) return <div className="py-3 text-xs text-ink-muted text-center border border-line rounded-lg">No quorum data for this space.</div>;

    return (
        <div className="border border-line rounded-lg overflow-hidden">
            <div className="flex items-center gap-3 px-3 py-2 border-b border-line bg-sunken text-[10px] text-ink-muted font-semibold uppercase tracking-wide">
                <span className="flex-1">Scope</span>
                <span className="w-24 text-right shrink-0">Required</span>
                <span className="w-28 shrink-0">Effective</span>
            </div>
            <QuorumRow
                label={quorum.name} sublabel="Space administrators / operators"
                value={spaceValue} onChange={onSpaceChange}
                override={quorum.override} effective={quorum.effective} allowInherit readOnly={readOnly}
                className="border-b border-line bg-sunken" />
            {quorum.cas.length === 0 ? (
                <div className="pl-8 pr-3 py-2 text-[11px] text-ink-muted">No CAs in this space.</div>
            ) : quorum.cas.map((ca) => (
                <QuorumRow key={ca.id}
                    label={ca.label || ca.name} sublabel="CA administrators / operators"
                    value={caValues[ca.id] ?? ''} onChange={(s) => onCaChange(ca.id, s)}
                    override={ca.override} effective={ca.effective} allowInherit max={quorum.effective} readOnly={readOnly}
                    className="border-b border-line last:border-b-0 bg-sunken pl-8" />
            ))}
            <div className="px-3 py-2 text-[11px] text-ink-muted border-t border-line">
                {!readOnly && <>Blank = inherit the parent value. A CA can require fewer approvals than its space, never more. </>}
                {INITIATOR_EXCLUDED}
            </div>
        </div>
    );
};

export default SystemQuorumCard;
