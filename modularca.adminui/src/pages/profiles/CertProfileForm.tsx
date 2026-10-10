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
import type { CertProfileFormState } from './certProfile';
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
const useParentKeyPolicy = (parentId: string, parentProfiles: any[]): ParentKeyPolicy | null => {
    const [resolved, setResolved] = React.useState<{ id: string; lists: KeyPolicyLists } | null>(null);
    React.useEffect(() => {
        if (!parentId) return;
        let active = true;
        apiGet<any>(`/api/v1/admin/cert-profiles/${parentId}/resolved`)
            .then((r) => { if (active && r) setResolved({ id: parentId, lists: keyListsOf(r) }); })
            .catch(() => { /* keep the row's own lists */ });
        return () => { active = false; };
    }, [parentId]);
    if (!parentId) return null;
    const row = parentProfiles.find((pr) => cpId(pr) === parentId);
    const lists = resolved?.id === parentId ? resolved.lists : row ? keyListsOf(row) : null;
    return lists ? { name: row?.name ?? 'parent', lists } : null;
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
    const parent = useParentKeyPolicy(f.inheritanceEnabled ? f.inheritsFromId : '', parentProfiles);
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
        </div>
    );
};

export default CertProfileForm;
