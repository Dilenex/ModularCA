import React from 'react';
import { inputClass, labelClass, FieldHint } from '@shared/components/forms';
import { StatusBadge } from '@shared/components/cards/StatusBadge';
import { GroupedCheckboxList } from '@shared/components/CheckboxList';
import { NameConstraintsEditor } from '@shared/components/NameConstraintsEditor';
import type { EkuCatalog } from '../../hooks/useOidCatalog';
import {
    InheritanceHint, MAX_PATH_LENGTH_HINT,
    caCertId, caDisplayName,
} from '../profileHelpers';
import type { ProfileFormMode } from './profileFormCore';
import type { SigningProfileFormState } from './signingProfile';
import { CertificatePoliciesEditor } from './CertificatePoliciesTable';
import { checkboxClass } from './CertProfileForm';
import { type KeyPolicyState, fromEditorState, setMode, toEditorState } from './keyPolicy';
import { KeyPolicyEditor } from './KeyPolicyEditor';
import { groupEkuOptions } from './pickerCatalogs';

const sameList = (a: readonly string[], b: readonly string[]) => a.length === b.length && a.every((v, i) => v === b[i]);

/** The ticked algorithms, whatever the mode; marked explicit so ticking every family never collapses to []. */
const tickedAlgorithms = (s: KeyPolicyState): string[] =>
    fromEditorState({ ...setMode(s, 'only'), explicit: { ...s.explicit, algorithms: true } }).algorithms;

const algorithmState = (list: string[], mode: KeyPolicyState['mode']): KeyPolicyState => setMode(toEditorState({ algorithms: list }), mode);

/**
 * Editor state for Allowed Algorithms. The form keeps the list and its mode; this keeps the editor's
 * extra state and starts over when either is changed from outside, as Cancel does.
 */
const useAlgorithmEditor = (
    list: string[], mode: KeyPolicyState['mode'], onChange: (list: string[], mode: KeyPolicyState['mode']) => void,
): [KeyPolicyState, (s: KeyPolicyState) => void] => {
    const [state, setState] = React.useState(() => algorithmState(list, mode));
    const current = state.mode === mode && sameList(tickedAlgorithms(state), list) ? state : algorithmState(list, mode);
    const update = (next: KeyPolicyState) => { setState(next); onChange(tickedAlgorithms(next), next.mode); };
    return [current, update];
};

const spId = (p: any): string => p.id || p.signingProfileId;
const cpId = (p: any): string => p.id || p.certProfileId;

/// <summary>
/// The signing profile fields, used unchanged by the new-profile page and the edit view.
/// Nothing is read-only in edit mode: the server accepts every field on update, the issuer
/// included (a new issuer is authorised again by the controller).
/// </summary>
export const SigningProfileForm: React.FC<{
    value: SigningProfileFormState;
    onChange: (next: SigningProfileFormState) => void;
    mode: ProfileFormMode;
    /** The profile being edited, left out of the parent choices. */
    profileId?: string;
    parentProfiles: any[];
    authorities: any[];
    certProfiles: any[];
    ekuCatalog: EkuCatalog;
}> = ({ value: f, onChange, profileId, parentProfiles, authorities, certProfiles, ekuCatalog }) => {
    const set = <K extends keyof SigningProfileFormState>(key: K, v: SigningProfileFormState[K]) => onChange({ ...f, [key]: v });
    const toggle = (list: string[], v: string) => (list.includes(v) ? list.filter((x) => x !== v) : [...list, v]);
    const [algorithms, setAlgorithmState] = useAlgorithmEditor(f.allowedAlgorithms, f.allowedAlgorithmsMode,
        (list, mode) => onChange({ ...f, allowedAlgorithms: list, allowedAlgorithmsMode: mode }));
    return (
        <div className="space-y-3 max-w-3xl">
            <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                <div><label className={labelClass}>Name</label><input type="text" value={f.name} onChange={(e) => set('name', e.target.value)} className={inputClass} /></div>
                <div><label className={labelClass}>Description</label><input type="text" value={f.description} onChange={(e) => set('description', e.target.value)} className={inputClass} /></div>
                <div>
                    <label className={labelClass}>Issuer</label>
                    <select value={f.issuerId} onChange={(e) => set('issuerId', e.target.value)} className={inputClass} aria-describedby="sp-issuer-hint">
                        <option value="">-- Select Issuing Authority --</option>
                        {authorities.map((a) => <option key={caCertId(a)} value={caCertId(a)}>{caDisplayName(a)}</option>)}
                    </select>
                    <FieldHint id="sp-issuer-hint" tone={f.issuerId ? 'muted' : 'warn'}>
                        {f.issuerId
                            ? 'Every certificate issued through this profile is signed by this authority.'
                            : 'Required. A signing profile with no issuing authority cannot sign anything; Save stays disabled until one is chosen.'}
                    </FieldHint>
                </div>
                <div>
                    <label className={labelClass}>Max Path Length</label>
                    <input type="text" inputMode="numeric" value={f.maxPathLength} onChange={(e) => set('maxPathLength', e.target.value.replace(/\D/g, ''))} className={inputClass} aria-describedby="sp-maxpath-hint" />
                    <FieldHint id="sp-maxpath-hint">{MAX_PATH_LENGTH_HINT}</FieldHint>
                </div>
            </div>
            <fieldset>
                <legend className={labelClass}>Name Constraints</legend>
                <NameConstraintsEditor idPrefix="sp-nc"
                    permitted={f.nameConstraintsPermitted} excluded={f.nameConstraintsExcluded}
                    onChange={(nc) => onChange({ ...f, nameConstraintsPermitted: nc.permitted, nameConstraintsExcluded: nc.excluded })} />
            </fieldset>
            <GroupedCheckboxList id="sp-ekus" legend="Allowed EKUs" value={f.allowedEkus} onChange={(next) => set('allowedEkus', next)}
                groups={groupEkuOptions(ekuCatalog.options, ekuCatalog.label)} ceiling={{ anyLabel: 'Any EKU' }}
                mode={f.allowedEkusMode} onModeChange={(m) => set('allowedEkusMode', m)}
                hint="A ceiling: a cert profile's EKUs that are not ticked here are left out of the certificate. Any leaves the list empty, which the server reads as unrestricted." />
            <div className="flex flex-wrap gap-4">
                <label className="flex items-center gap-2 text-xs text-ink"><input type="checkbox" checked={f.isDefault} onChange={(e) => set('isDefault', e.target.checked)} className={checkboxClass} />Default Profile</label>
                <label className="flex items-center gap-2 text-xs text-ink"><input type="checkbox" checked={f.inhibitAnyPolicy} onChange={(e) => set('inhibitAnyPolicy', e.target.checked)} className={checkboxClass} />Inhibit Any Policy</label>
                <label className="flex items-center gap-2 text-xs text-ink"><input type="checkbox" checked={f.inheritanceEnabled} onChange={(e) => set('inheritanceEnabled', e.target.checked)} className={checkboxClass} />Enable Inheritance</label>
            </div>
            <div>
                <label className={labelClass}>Inherits From</label>
                <select value={f.inheritsFromId} onChange={(e) => set('inheritsFromId', e.target.value)} className={inputClass}>
                    <option value="">-- None (standalone) --</option>
                    {parentProfiles.filter((pr) => spId(pr) !== profileId).map((pr) => <option key={spId(pr)} value={spId(pr)}>{pr.name}</option>)}
                </select>
                <InheritanceHint inheritsFromId={f.inheritsFromId} inheritanceEnabled={f.inheritanceEnabled} />
                {f.inheritanceEnabled && f.inheritsFromId && (
                    <FieldHint tone="warn">Signing profile inheritance is stored but not yet applied at issuance: only certificate and request profiles are resolved against a parent today. This setting has no effect until that lands.</FieldHint>
                )}
            </div>
            <div>
                <label className="flex items-center gap-2 text-xs text-ink"><input type="checkbox" checked={f.extendedKeyUsageCritical} onChange={(e) => set('extendedKeyUsageCritical', e.target.checked)} className={checkboxClass} />Mark Extended Key Usage extension as critical</label>
                <FieldHint className="ml-6">RFC 5280 §4.2.1.12 recommends marking the EKU extension critical when the certificate&apos;s purpose is restricted (e.g. a cert that must only be used for client auth).</FieldHint>
            </div>
            <CertificatePoliciesEditor id="sp-policies" rows={f.policies} critical={f.policiesCritical} notices={f.policyNotices}
                onChange={(next) => onChange({ ...f, policies: next.rows, policiesCritical: next.critical })} />
            <KeyPolicyEditor id="sp-algorithms" scope="algorithms" legend="Allowed Algorithms" value={algorithms} onChange={setAlgorithmState} />
            <div>
                <label className={labelClass}>Allowed Cert Profiles</label>
                <div className="max-h-40 overflow-y-auto bg-ground border border-line rounded p-2 space-y-1">
                    {certProfiles.length === 0 && <span className="text-xs text-ink-muted">No cert profiles available</span>}
                    {certProfiles.map((cp) => {
                        const cid = cpId(cp);
                        return (
                            <label key={cid} className="flex items-center gap-2 text-sm text-ink cursor-pointer hover:bg-hover px-1 rounded">
                                <input type="checkbox" checked={f.allowedCertProfileIds.includes(cid)} onChange={() => set('allowedCertProfileIds', toggle(f.allowedCertProfileIds, cid))} className="accent-accent" />
                                <span>{cp.name}</span>
                                {cp.isCaProfile && <StatusBadge status="active" label="CA" />}
                            </label>
                        );
                    })}
                </div>
            </div>
        </div>
    );
};

export default SigningProfileForm;
