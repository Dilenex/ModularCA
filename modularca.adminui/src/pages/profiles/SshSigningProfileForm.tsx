import React from 'react';
import { inputClass, labelClass, FieldHint } from '@shared/components/forms';
import { GroupedCheckboxList } from '@shared/components/CheckboxList';
import { FORCE_COMMAND_HINT, SSH_EXTENSION_OPTIONS, sshExtensionTitle } from '../profileHelpers';
import { groupSshExtensions } from './pickerCatalogs';
import type { ProfileFormMode } from './profileFormCore';
import { ChipListInput } from '@shared/components/ChipListInput';
import { type SshSigningProfileFormState, validateSourceAddress } from './sshSigningProfile';
import { checkboxClass } from './CertProfileForm';

/// <summary>
/// The SSH signing profile fields, used unchanged by the new-profile page and the edit view.
/// Nothing is read-only in edit mode: the server accepts every field on update, the CA key
/// included (a new key is fenced and authorised again by the controller).
/// </summary>
export const SshSigningProfileForm: React.FC<{
    value: SshSigningProfileFormState;
    onChange: (next: SshSigningProfileFormState) => void;
    mode: ProfileFormMode;
    caKeys: any[];
}> = ({ value: f, onChange, caKeys }) => {
    const set = <K extends keyof SshSigningProfileFormState>(key: K, v: SshSigningProfileFormState[K]) => onChange({ ...f, [key]: v });
    const signsNothing = !f.allowUserCerts && !f.allowHostCerts;
    return (
        <div className="space-y-3 max-w-3xl">
            <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                <div><label className={labelClass}>Name</label><input type="text" value={f.name} onChange={(e) => set('name', e.target.value)} className={inputClass} placeholder="e.g. Default User Signing" /></div>
                <div><label className={labelClass}>Description</label><input type="text" value={f.description} onChange={(e) => set('description', e.target.value)} className={inputClass} placeholder="Optional" /></div>
                <div>
                    <label className={labelClass}>SSH CA Key</label>
                    <select value={f.sshCaKeyId} onChange={(e) => set('sshCaKeyId', e.target.value)} className={inputClass}>
                        <option value="">-- Select CA Key --</option>
                        {caKeys.map((k) => <option key={k.id} value={k.id}>{k.name} ({k.keyType})</option>)}
                    </select>
                </div>
                <div>
                    <label className={labelClass}>Max Validity (hours)</label>
                    <input type="text" inputMode="numeric" value={f.maxValidityHours} onChange={(e) => set('maxValidityHours', e.target.value.replace(/\D/g, ''))} className={inputClass} aria-describedby="ssh-sp-validity-hint" />
                    <FieldHint id="ssh-sp-validity-hint">Whole hours, not an ISO 8601 duration: 720 is thirty days. Blank or 0 falls back to 720.</FieldHint>
                </div>
                <div>
                    <label className={labelClass}>Force Command (optional)</label>
                    <input type="text" value={f.forceCommand} onChange={(e) => set('forceCommand', e.target.value)} className={inputClass} placeholder="e.g. /usr/bin/rsync" aria-describedby="ssh-sp-force-hint" />
                    <FieldHint id="ssh-sp-force-hint" tone={f.forceCommand.trim() ? 'warn' : 'muted'}>{FORCE_COMMAND_HINT}</FieldHint>
                </div>
                <div>
                    <label htmlFor="ssh-sp-source" className={labelClass}>Source Address Restrictions</label>
                    <ChipListInput id="ssh-sp-source" value={f.sourceAddressRestrictions} onChange={(next) => set('sourceAddressRestrictions', next)}
                        validate={validateSourceAddress} mono placeholder="e.g. 10.0.0.0/8, then Enter" aria-describedby="ssh-sp-source-hint" />
                    <FieldHint id="ssh-sp-source-hint">Addresses or CIDR networks the certificate may be used from; sshd refuses connections from anywhere else. Empty means no restriction.</FieldHint>
                </div>
            </div>
            <div>
                <div className="flex flex-wrap gap-4">
                    <label className="flex items-center gap-2 text-xs text-ink"><input type="checkbox" checked={f.allowUserCerts} onChange={(e) => set('allowUserCerts', e.target.checked)} className={checkboxClass} />Allow User Certs</label>
                    <label className="flex items-center gap-2 text-xs text-ink"><input type="checkbox" checked={f.allowHostCerts} onChange={(e) => set('allowHostCerts', e.target.checked)} className={checkboxClass} />Allow Host Certs</label>
                </div>
                {signsNothing && (
                    <FieldHint tone="warn">This profile allows neither user nor host certificates, so it can sign nothing and will not appear in the signing form. Tick at least one before saving.</FieldHint>
                )}
            </div>
            <GroupedCheckboxList id="ssh-sp-default-ext" legend="Default Extensions" value={f.defaultExtensions} onChange={(next) => set('defaultExtensions', next)}
                groups={groupSshExtensions(SSH_EXTENSION_OPTIONS, sshExtensionTitle)}
                hint="Applied only when a request names no extensions of its own; a request that lists any extension replaces this set entirely. These are defaults, not a ceiling: the SSH cert profile's Allowed Extensions decide what a request may ask for." />
        </div>
    );
};

export default SshSigningProfileForm;
