import React from 'react';
import { inputClass, labelClass, FieldHint } from '@shared/components/forms';
import { CheckboxList, GroupedCheckboxList } from '@shared/components/CheckboxList';
import { apiGet } from '../../api/client';
import type { EkuCatalog, UsageCatalog } from '../../hooks/useOidCatalog';
import {
    CT_ENABLED_HINT, CT_LOG_IDS_HINT, CatalogGapNotice, DurationHint, InheritanceHint,
    REQUESTED_USAGE_HINT, caDisplayName, caRowId,
} from '../profileHelpers';
import { type ProfileFormMode, parseListField } from './profileFormCore';
import { type CertProfileFormState, expiryProblems } from './certProfile';
import { periodText } from '@shared/periodText';
import type { KeyPolicyLists } from './keyPolicy';
import { KeyPolicyEditor, type ParentKeyPolicy } from './KeyPolicyEditor';
import { groupEkuOptions, keyUsageOptions } from './pickerCatalogs';
import { type CtLogChoice, canonicalCtLogIds, ctLogOptions, noEnabledLogChosen, unknownCtLogIds } from './ctLogChoices';
import type { FieldProblem } from '@shared/components/CheckboxList';

export const checkboxClass = 'w-4 h-4 bg-raised border-line-strong rounded';

const cpId = (p: any): string => p.id || p.certProfileId;

const keyListsOf = (p: any): KeyPolicyLists => ({
    algorithms: parseListField(p?.allowedKeyAlgorithms),
    sizes: parseListField(p?.allowedKeySizes),
    signatures: parseListField(p?.allowedSignatureAlgorithms),
});

/**
 * The parent's effective key lists, from GET .../resolved so a parent that itself inherits is
 * read correctly. Until that answers (or if it fails) the parent's own row stands in.
 */
const useParentResolved = (parentId: string, parentProfiles: any[]): { keys: ParentKeyPolicy | null; effective: any | null } => {
    const [resolved, setResolved] = React.useState<{ id: string; profile: any } | null>(null);
    React.useEffect(() => {
        if (!parentId) return;
        let active = true;
        apiGet<any>(`/api/v1/admin/cert-profiles/${parentId}/resolved`)
            .then((r) => { if (active && r) setResolved({ id: parentId, profile: r }); })
            .catch(() => { /* keep the row's own values */ });
        return () => { active = false; };
    }, [parentId]);
    if (!parentId) return { keys: null, effective: null };
    const row = parentProfiles.find((pr) => cpId(pr) === parentId);
    const effective = resolved?.id === parentId ? resolved.profile : row ?? null;
    return { keys: effective ? { name: row?.name ?? 'parent', lists: keyListsOf(effective) } : null, effective };
};

/** The parent's effective value of a percent field, for an empty input's placeholder. */
const parentPercent = (parent: any | null, key: 'expiryWarningPercent' | 'expiryAlertPercent', fallback: number): string =>
    parent ? `parent: ${parent[key] ?? fallback}` : `default ${fallback}`;

/**
 * The expiry warning settings: when the soft (amber) warning and the alert (red) start, as a share
 * of the certificate's lifetime with an optional longest window, or never for certificates that
 * renew themselves. With inheritance, an override switch decides whether the parent's settings
 * bind this profile (it may then only warn earlier) or are replaced by the values set here.
 */
const ExpiryWarningFields: React.FC<{ value: CertProfileFormState; onChange: (next: CertProfileFormState) => void; parent: any | null }> = ({ value: f, onChange, parent }) => {
    const set = <K extends keyof CertProfileFormState>(key: K, v: CertProfileFormState[K]) => onChange({ ...f, [key]: v });
    const inherits = f.inheritanceEnabled && !!f.inheritsFromId;
    const problems = expiryProblems(f);
    return (
        <fieldset className="border border-line rounded p-3 space-y-3">
            <legend className="px-1 text-xs font-semibold text-ink">Expiry warning</legend>
            <FieldHint>
                A certificate shows a warning (amber) when this share of its lifetime remains, and an alert (red) later; by default 30 % and 10 %:
                a 90-day certificate warns 27 days and alerts 9 days before it expires, a 10-hour one 3 hours and 1 hour before. A window, when set,
                caps how early either starts. A CA certificate whose profile sets neither keeps 30 days and 7 days. Each certificate keeps the
                instants it was given at issuance; saving a change here re-computes them for this profile&apos;s valid certificates.
            </FieldHint>
            <label className="flex items-center gap-2 text-xs text-ink">
                <input type="checkbox" checked={f.expiryNeverWarn} onChange={(e) => set('expiryNeverWarn', e.target.checked)} className={checkboxClass} />
                Renewed automatically: never warn
            </label>
            {f.expiryNeverWarn && <FieldHint className="ml-6">Its certificates raise no expiry warning or e-mail. One that expires without a successor still shows as expired, not replaced.</FieldHint>}
            {inherits && (
                <>
                    <label className="flex items-center gap-2 text-xs text-ink">
                        <input type="checkbox" checked={f.expiryWarningOverridesParent} onChange={(e) => set('expiryWarningOverridesParent', e.target.checked)} className={checkboxClass} />
                        Override the parent&apos;s expiry warning settings
                    </label>
                    <FieldHint className="ml-6">
                        {f.expiryWarningOverridesParent
                            ? 'The values set here are used as they are; empty ones are inherited from the parent.'
                            : 'Empty values are inherited. A value set here may only make the warning earlier than the parent\u2019s (a larger percent, a longer window); a later one is clamped to the parent\u2019s, and never-warn holds only when the parent never warns too.'}
                    </FieldHint>
                </>
            )}
            <div className={`grid grid-cols-1 md:grid-cols-2 gap-3 ${f.expiryNeverWarn ? 'opacity-60' : ''}`}>
                <div>
                    <label className={labelClass} htmlFor="cp-expiry-warning-percent">Warning at % of lifetime left</label>
                    <input id="cp-expiry-warning-percent" type="number" min={1} max={100} placeholder={inherits ? parentPercent(parent, 'expiryWarningPercent', 30) : 'default 30'}
                        value={f.expiryWarningPercent} onChange={(e) => set('expiryWarningPercent', e.target.value)} className={inputClass} disabled={f.expiryNeverWarn} />
                </div>
                <div>
                    <label className={labelClass} htmlFor="cp-expiry-warning-window">Longest warning window (ISO 8601)</label>
                    <input id="cp-expiry-warning-window" type="text" placeholder={inherits && parent?.expiryWarningMaxWindow ? `parent: ${parent.expiryWarningMaxWindow}` : 'no cap, e.g. P30D'}
                        value={f.expiryWarningMaxWindow} onChange={(e) => set('expiryWarningMaxWindow', e.target.value)} className={inputClass} disabled={f.expiryNeverWarn} />
                    {f.expiryWarningMaxWindow.trim() && <FieldHint>= {periodText(f.expiryWarningMaxWindow)}</FieldHint>}
                </div>
                <div>
                    <label className={labelClass} htmlFor="cp-expiry-alert-percent">Alert at % of lifetime left</label>
                    <input id="cp-expiry-alert-percent" type="number" min={1} max={100} placeholder={inherits ? parentPercent(parent, 'expiryAlertPercent', 10) : 'default 10'}
                        value={f.expiryAlertPercent} onChange={(e) => set('expiryAlertPercent', e.target.value)} className={inputClass} disabled={f.expiryNeverWarn} />
                </div>
                <div>
                    <label className={labelClass} htmlFor="cp-expiry-alert-window">Longest alert window (ISO 8601)</label>
                    <input id="cp-expiry-alert-window" type="text" placeholder={inherits && parent?.expiryAlertMaxWindow ? `parent: ${parent.expiryAlertMaxWindow}` : 'no cap, e.g. P7D'}
                        value={f.expiryAlertMaxWindow} onChange={(e) => set('expiryAlertMaxWindow', e.target.value)} className={inputClass} disabled={f.expiryNeverWarn} />
                    {f.expiryAlertMaxWindow.trim() && <FieldHint>= {periodText(f.expiryAlertMaxWindow)}</FieldHint>}
                </div>
            </div>
            {inherits && parent?.expiryNeverWarn && !f.expiryWarningOverridesParent && <FieldHint>The parent never warns.</FieldHint>}
            {problems.map((msg) => <FieldHint key={msg} tone="warn">{msg}</FieldHint>)}
        </fieldset>
    );
};

/**
 * The CT logs a profile submits to, as a checklist of the catalog with an Every enabled log /
 * Only these logs switch. Shown while CT is on, and also while stored ids name no log, so they can
 * be removed (the server refuses them).
 */
const CtLogPicker: React.FC<{ value: CertProfileFormState; onChange: (next: CertProfileFormState) => void; ctLogs: CtLogChoice[] | null }> = ({ value: f, onChange, ctLogs }) => {
    const ids = canonicalCtLogIds(f.ctLogIds, ctLogs);
    const unknown = unknownCtLogIds(f.ctLogsMode === 'only' ? ids : [], ctLogs);
    if (!f.ctEnabled && unknown.length === 0) return null;
    const problems: FieldProblem[] = [];
    if (ctLogs === null) problems.push({ tone: 'info', message: 'The CT log list could not be loaded, so the stored ids are shown as they are and kept.' });
    else if (ctLogs.length === 0) problems.push({ tone: 'warn', message: 'No CT logs are configured, so nothing is submitted whatever is chosen here. A system operator adds logs under the CT log settings.' });
    if (unknown.length) problems.push({ tone: 'crit', message: 'Remove the unknown logs: they name no configured CT log, and the server refuses them.' });
    if (f.ctLogsMode === 'only' && noEnabledLogChosen(ids, ctLogs)) problems.push({ tone: 'warn', message: 'None of the ticked logs is enabled, so nothing is submitted until one is.' });
    return (
        <CheckboxList id="cp-ct-logs" legend="CT Logs" columns={1}
            value={ids} onChange={(next) => onChange({ ...f, ctLogIds: next })}
            options={ctLogOptions(ctLogs ?? [])}
            ceiling={{ anyLabel: 'Every enabled log', onlyLabel: 'Only these logs' }}
            mode={f.ctLogsMode} onModeChange={(m) => onChange({ ...f, ctLogsMode: m })}
            unknown={ctLogs ? { label: 'Unknown logs, no longer configured:', format: (id) => `unknown log ${id}`, tone: 'crit' } : { label: 'Stored ids:' }}
            hint={CT_LOG_IDS_HINT} problems={problems} />
    );
};

/// <summary>
/// The certificate profile fields, used unchanged by the new-profile page and the edit view.
/// Nothing is read-only in edit mode: the server accepts every field on update.
/// </summary>
export const CertProfileForm: React.FC<{
    value: CertProfileFormState;
    onChange: (next: CertProfileFormState) => void;
    mode: ProfileFormMode;
    /** The profile being edited, left out of the parent choices. */
    profileId?: string;
    parentProfiles: any[];
    authorities: any[];
    ekuCatalog: EkuCatalog;
    keyUsageCatalog: UsageCatalog;
    /** The CT log catalog; null while loading or when it could not be read. */
    ctLogs: CtLogChoice[] | null;
    /** What the application finds this profile by name for; its name, CA scope and kind are then fixed. */
    systemPurpose?: string | null;
}> = ({ value: f, onChange, profileId, parentProfiles, authorities, ekuCatalog, keyUsageCatalog, ctLogs, systemPurpose }) => {
    const set = <K extends keyof CertProfileFormState>(key: K, v: CertProfileFormState[K]) => onChange({ ...f, [key]: v });
    const { keys: parent, effective: parentEffective } = useParentResolved(f.inheritanceEnabled ? f.inheritsFromId : '', parentProfiles);
    return (
        <div className="space-y-3 max-w-3xl">
            <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                <div>
                    <label className={labelClass}>Name</label>
                    <input type="text" value={f.name} onChange={(e) => set('name', e.target.value)} className={inputClass} disabled={!!systemPurpose} aria-describedby={systemPurpose ? 'cp-name-fixed' : undefined} />
                    {systemPurpose && <FieldHint id="cp-name-fixed">Fixed: {systemPurpose}, and it is found by this name. Its CA scope and kind are fixed too.</FieldHint>}
                </div>
                <div><label className={labelClass}>Description</label><input type="text" value={f.description} onChange={(e) => set('description', e.target.value)} className={inputClass} /></div>
                <div>
                    <label className={labelClass}>Validity Period Min (ISO 8601)</label>
                    <input type="text" placeholder="e.g. P90D" value={f.validityPeriodMin} onChange={(e) => set('validityPeriodMin', e.target.value)} className={inputClass} aria-describedby="cp-validity-min-hint" />
                    <DurationHint id="cp-validity-min-hint" value={f.validityPeriodMin} />
                </div>
                <div>
                    <label className={labelClass}>Validity Period Max (ISO 8601)</label>
                    <input type="text" placeholder="e.g. P1Y" value={f.validityPeriodMax} onChange={(e) => set('validityPeriodMax', e.target.value)} className={inputClass} aria-describedby="cp-validity-max-hint" />
                    <DurationHint id="cp-validity-max-hint" value={f.validityPeriodMax} />
                </div>
                <div>
                    <label className={labelClass}>Inherits From</label>
                    <select value={f.inheritsFromId} onChange={(e) => set('inheritsFromId', e.target.value)} className={inputClass}>
                        <option value="">-- None (standalone) --</option>
                        {parentProfiles.filter((pr) => cpId(pr) !== profileId).map((pr) => <option key={cpId(pr)} value={cpId(pr)}>{pr.name}</option>)}
                    </select>
                </div>
                <div>
                    <label className={labelClass}>CA Scope</label>
                    <select value={f.certificateAuthorityId} onChange={(e) => set('certificateAuthorityId', e.target.value)} className={inputClass} disabled={!!systemPurpose}>
                        <option value="">-- System-wide --</option>
                        {authorities.map((a) => <option key={caRowId(a)} value={caRowId(a)}>{caDisplayName(a)}</option>)}
                    </select>
                </div>
            </div>
            <div className="flex flex-wrap gap-4">
                <label className="flex items-center gap-2 text-xs text-ink"><input type="checkbox" checked={f.isCaProfile} onChange={(e) => set('isCaProfile', e.target.checked)} className={checkboxClass} disabled={!!systemPurpose} />CA Profile</label>
                <label className="flex items-center gap-2 text-xs text-ink"><input type="checkbox" checked={f.ctEnabled} onChange={(e) => set('ctEnabled', e.target.checked)} className={checkboxClass} />CT Enabled</label>
                <label className="flex items-center gap-2 text-xs text-ink"><input type="checkbox" checked={f.inheritanceEnabled} onChange={(e) => set('inheritanceEnabled', e.target.checked)} className={checkboxClass} />Enable Inheritance</label>
            </div>
            {f.ctEnabled && <FieldHint>{CT_ENABLED_HINT}</FieldHint>}
            <CtLogPicker value={f} onChange={onChange} ctLogs={ctLogs} />
            <InheritanceHint inheritsFromId={f.inheritsFromId} inheritanceEnabled={f.inheritanceEnabled} />
            <div>
                <label className="flex items-center gap-2 text-xs text-ink"><input type="checkbox" checked={f.allowWildcard} onChange={(e) => set('allowWildcard', e.target.checked)} className={checkboxClass} />Allow wildcard SAN/CN entries</label>
                <FieldHint className="ml-6">
                    When disabled, any DNS SAN or CN containing <code className="font-mono">*</code> is rejected at issuance. Structural rules
                    still apply when enabled: at most one <code className="font-mono">*</code>, in the leftmost label, and the name must have at least two labels.
                </FieldHint>
            </div>
            <div>
                <CheckboxList id="cp-key-usages" legend="Key Usages" value={f.keyUsages} onChange={(next) => set('keyUsages', next)}
                    options={keyUsageOptions(keyUsageCatalog.options, keyUsageCatalog.label)} hint={REQUESTED_USAGE_HINT} />
                <CatalogGapNotice missing={keyUsageCatalog.missingFromCatalog} kind="key usage" />
            </div>
            <div>
                <GroupedCheckboxList id="cp-ekus" legend="Extended Key Usages" value={f.extendedKeyUsages} onChange={(next) => set('extendedKeyUsages', next)}
                    groups={groupEkuOptions(ekuCatalog.options, ekuCatalog.label)} hint={REQUESTED_USAGE_HINT} />
                <CatalogGapNotice missing={ekuCatalog.missingFromCatalog} kind="extended key usage" />
            </div>
            <KeyPolicyEditor id="cp-keys" value={f.keyPolicy} onChange={(next) => set('keyPolicy', next)} parent={parent} />
            <ExpiryWarningFields value={f} onChange={onChange} parent={parentEffective} />
        </div>
    );
};

export default CertProfileForm;
