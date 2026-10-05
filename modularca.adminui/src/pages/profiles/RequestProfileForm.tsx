import React from 'react';
import { inputClass, labelClass } from '@shared/components/forms';
import { RequestProfileRulesEditor } from '../../components/RequestProfileRulesEditor';
import { InheritanceHint, caDisplayName, caRowId } from '../profileHelpers';
import type { ProfileFormMode } from './profileFormCore';
import type { RequestProfileFormState } from './requestProfile';
import { checkboxClass } from './CertProfileForm';

const cpId = (p: any): string => p.id || p.certProfileId;

/// <summary>
/// The request profile fields, used unchanged by the new-profile page and the edit view.
/// Nothing is read-only in edit mode: the server accepts every field on update.
/// </summary>
export const RequestProfileForm: React.FC<{
    value: RequestProfileFormState;
    onChange: (next: RequestProfileFormState) => void;
    mode: ProfileFormMode;
    /** The profile being edited, left out of the parent choices. */
    profileId?: string;
    parentProfiles: any[];
    certProfiles: any[];
    authorities: any[];
}> = ({ value: f, onChange, profileId, parentProfiles, certProfiles, authorities }) => {
    const set = <K extends keyof RequestProfileFormState>(key: K, v: RequestProfileFormState[K]) => onChange({ ...f, [key]: v });
    return (
        <div className="space-y-3 max-w-3xl">
            <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                <div><label className={labelClass}>Name</label><input type="text" value={f.name} onChange={(e) => set('name', e.target.value)} className={inputClass} placeholder="e.g. Standard TLS Request" /></div>
                <div><label className={labelClass}>Description</label><input type="text" value={f.description} onChange={(e) => set('description', e.target.value)} className={inputClass} placeholder="Optional description" /></div>
                <div>
                    <label className={labelClass}>Default Certificate Profile</label>
                    <select value={f.defaultCertProfileId} onChange={(e) => set('defaultCertProfileId', e.target.value)} className={inputClass}>
                        <option value="">-- None --</option>
                        {certProfiles.map((cp) => <option key={cpId(cp)} value={cpId(cp)}>{cp.name}</option>)}
                    </select>
                </div>
                <div>
                    <label className={labelClass}>Inherits From</label>
                    <select value={f.inheritsFromId} onChange={(e) => set('inheritsFromId', e.target.value)} className={inputClass}>
                        <option value="">-- None (standalone) --</option>
                        {parentProfiles.filter((pr) => pr.id !== profileId).map((pr) => <option key={pr.id} value={pr.id}>{pr.name}</option>)}
                    </select>
                </div>
                <div>
                    <label className={labelClass}>CA Scope</label>
                    <select value={f.certificateAuthorityId} onChange={(e) => set('certificateAuthorityId', e.target.value)} className={inputClass}>
                        <option value="">-- System-wide --</option>
                        {authorities.map((a) => <option key={caRowId(a)} value={caRowId(a)}>{caDisplayName(a)}</option>)}
                    </select>
                </div>
            </div>
            <div className="flex flex-wrap gap-4">
                <label className="flex items-center gap-2 text-xs text-ink"><input type="checkbox" checked={f.requireApproval} onChange={(e) => set('requireApproval', e.target.checked)} className={checkboxClass} />Require Approval</label>
                <label className="flex items-center gap-2 text-xs text-ink"><input type="checkbox" checked={f.inheritanceEnabled} onChange={(e) => set('inheritanceEnabled', e.target.checked)} className={checkboxClass} />Enable Inheritance</label>
            </div>
            <InheritanceHint inheritsFromId={f.inheritsFromId} inheritanceEnabled={f.inheritanceEnabled} />
            <RequestProfileRulesEditor value={f.rules} onChange={(rules) => set('rules', rules)} />
            <div>
                <label className={labelClass}>Allowed Cert Profiles</label>
                <div className="max-h-40 overflow-y-auto bg-ground border border-line rounded p-2 space-y-1">
                    {certProfiles.length === 0 && <span className="text-xs text-ink-muted">No cert profiles available</span>}
                    {certProfiles.map((cp) => {
                        const cid = cpId(cp);
                        return (
                            <label key={cid} className="flex items-center gap-2 text-sm text-ink cursor-pointer hover:bg-hover px-1 rounded">
                                <input type="checkbox" checked={f.allowedCertProfileIds.includes(cid)}
                                    onChange={(e) => set('allowedCertProfileIds', e.target.checked ? [...f.allowedCertProfileIds, cid] : f.allowedCertProfileIds.filter((x) => x !== cid))}
                                    className="accent-accent" />
                                <span>{cp.name}</span>
                            </label>
                        );
                    })}
                </div>
            </div>
        </div>
    );
};

export default RequestProfileForm;
