import React from 'react';
import { inputClass, labelClass, FieldHint } from '@shared/components/forms';
import { caDisplayName, caRowId } from '../profileHelpers';
import type { ProfileFormMode } from './profileFormCore';
import { type SshRequestProfileFormState, unbindsCa } from './sshRequestProfile';
import { checkboxClass } from './CertProfileForm';
import { SSH_PROFILE_TYPE_HINT, SSH_PROFILE_TYPE_OPTIONS, type SshProfileTypeChoice } from '../sshProfileType';

type IdListKey = 'allowedSshSigningProfileIds' | 'allowedSshCertProfileIds';

/// <summary>
/// The SSH request profile fields, used unchanged by the new-profile page and the edit view.
/// In edit mode a profile bound to a CA cannot be moved to Any CA (the update endpoint reads a
/// null CA as "unchanged"), so that one option is disabled; another CA can still be chosen.
/// </summary>
export const SshRequestProfileForm: React.FC<{
    value: SshRequestProfileFormState;
    onChange: (next: SshRequestProfileFormState) => void;
    mode: ProfileFormMode;
    signingProfiles: any[];
    certProfiles: any[];
    authorities: any[];
}> = ({ value: f, onChange, mode, signingProfiles, certProfiles, authorities }) => {
    const set = <K extends keyof SshRequestProfileFormState>(key: K, v: SshRequestProfileFormState[K]) => onChange({ ...f, [key]: v });
    const toggleId = (key: IdListKey, id: string) => set(key, f[key].includes(id) ? f[key].filter((x) => x !== id) : [...f[key], id]);
    const unbindLocked = mode === 'edit' && !!f.boundCertificateAuthorityId;
    const checkboxList = (items: any[], emptyText: string, key: IdListKey) => (
        <div className="max-h-40 overflow-y-auto bg-ground border border-line rounded p-2 space-y-1">
            {items.length === 0 && <span className="text-xs text-ink-muted">{emptyText}</span>}
            {items.map((it) => (
                <label key={it.id} className="flex items-center gap-2 text-sm text-ink cursor-pointer hover:bg-hover px-1 rounded">
                    <input type="checkbox" checked={f[key].includes(it.id)} onChange={() => toggleId(key, it.id)} className="accent-accent" />
                    <span>{it.name}</span>
                </label>
            ))}
        </div>
    );
    return (
        <div className="space-y-3 max-w-3xl">
            <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                <div><label className={labelClass}>Name</label><input type="text" value={f.name} onChange={(e) => set('name', e.target.value)} className={inputClass} placeholder="e.g. Developer Access" /></div>
                <div><label className={labelClass}>Description</label><input type="text" value={f.description} onChange={(e) => set('description', e.target.value)} className={inputClass} placeholder="Optional" /></div>
                <div>
                    <label className={labelClass}>Max Validity (hours)</label>
                    <input type="text" inputMode="numeric" value={f.maxValidityHours} onChange={(e) => set('maxValidityHours', e.target.value.replace(/\D/g, ''))} className={inputClass} aria-describedby="ssh-rp-validity-hint" />
                    <FieldHint id="ssh-rp-validity-hint">Whole hours, not an ISO 8601 duration: 720 is thirty days. Blank or 0 falls back to 720.</FieldHint>
                </div>
                <div>
                    <label className={labelClass}>CA Scope</label>
                    <select value={f.certificateAuthorityId} onChange={(e) => set('certificateAuthorityId', e.target.value)} className={inputClass} aria-describedby="ssh-rp-ca-hint">
                        <option value="" disabled={unbindLocked && !unbindsCa(f, mode)}>-- Any CA --</option>
                        {authorities.map((a) => <option key={caRowId(a)} value={caRowId(a)}>{caDisplayName(a)}</option>)}
                    </select>
                    {unbindLocked && (
                        <FieldHint id="ssh-rp-ca-hint" tone={unbindsCa(f, mode) ? 'warn' : 'muted'}>
                            This profile is bound to a CA, and the server cannot move a bound profile back to Any CA. Another CA can be chosen; for no CA, create a new profile.
                        </FieldHint>
                    )}
                </div>
                <div>
                    <label htmlFor="ssh-rp-type" className={labelClass}>Certificate type</label>
                    <select id="ssh-rp-type" value={f.certificateType} onChange={(e) => set('certificateType', e.target.value as SshProfileTypeChoice)} className={inputClass} aria-describedby="ssh-rp-type-hint">
                        {SSH_PROFILE_TYPE_OPTIONS.map((o) => <option key={o.value} value={o.value}>{o.label}</option>)}
                    </select>
                    <FieldHint id="ssh-rp-type-hint">{SSH_PROFILE_TYPE_HINT} The self-service request form offers a profile only when its type is User or Either.</FieldHint>
                </div>
            </div>
            <div className="flex flex-wrap gap-4">
                <label className="flex items-center gap-2 text-xs text-ink"><input type="checkbox" checked={f.requireApproval} onChange={(e) => set('requireApproval', e.target.checked)} className={checkboxClass} />Require Approval</label>
            </div>
            <div><label className={labelClass}>Allowed SSH Signing Profiles</label>{checkboxList(signingProfiles, 'No signing profiles available', 'allowedSshSigningProfileIds')}</div>
            <div><label className={labelClass}>Allowed SSH Cert Profiles</label>{checkboxList(certProfiles, 'No cert profiles available', 'allowedSshCertProfileIds')}</div>
        </div>
    );
};

export default SshRequestProfileForm;
