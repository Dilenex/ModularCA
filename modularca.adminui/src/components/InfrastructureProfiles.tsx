import React, { useCallback, useEffect, useState } from 'react';
import type { NoticeInput } from '@shared/notifications/notice';
import { InlineNotice } from '@shared/components/InlineNotice';
import { inputClass, labelClass } from '@shared/components/forms';
import { errorNotice } from '@shared-auth/api/notices';
import { StepUpOps } from '@shared/generated';
import { apiGet, apiPutWithMfa } from '../api/client';
import { useStepUp } from './StepUpMfaContext';
import { ConstraintPanel } from './ConstraintPanel';
import {
    DEFAULT_CHOICE, changedRoles, choicesFor, otherDefaultNames, roleConstraintGroups, roleLabel, savedChoices, sharedConstraintGroup, toRequest,
    type InfrastructureChoices, type InfrastructureProfilesAnswer,
} from '../pages/infrastructureProfiles';

const dateText = (iso: string) => new Date(iso).toLocaleDateString('en-US', { year: 'numeric', month: 'short', day: 'numeric' });

/// <summary>
/// The certificate profile each of a CA's own certificates is issued under (OCSP responder, TSA
/// signer, CMP signer): a picker per certificate on the left, and on the right what the profile
/// each picker holds gives its certificate, which follows the pickers before anything is saved.
/// Saving changes nothing that is already issued; the choice applies at the next reissue.
/// </summary>
const InfrastructureProfiles: React.FC<{ caId: string }> = ({ caId }) => {
    const { requireStepUp } = useStepUp();
    const [answer, setAnswer] = useState<InfrastructureProfilesAnswer | null>(null);
    const [choices, setChoices] = useState<InfrastructureChoices>({});
    const [loadError, setLoadError] = useState<NoticeInput | null>(null);
    const [saveError, setSaveError] = useState<NoticeInput | null>(null);
    const [saved, setSaved] = useState<string | null>(null);
    const [saving, setSaving] = useState(false);

    const load = useCallback(async () => {
        try {
            const data = await apiGet<InfrastructureProfilesAnswer>(`/api/v1/admin/authorities/${caId}/infrastructure-profiles`);
            setAnswer(data);
            setChoices(savedChoices(data.roles));
            setLoadError(null);
        } catch (err) {
            setLoadError(errorNotice(err, 'Failed to load the certificate profiles of this CA'));
        }
    }, [caId]);

    useEffect(() => { load(); }, [load]);

    if (loadError) return <InlineNotice notice={loadError} variant="line" />;
    if (!answer) return <p className="text-xs text-ink-muted">Loading certificate profiles…</p>;

    const changed = changedRoles(answer.roles, choices);

    const save = async () => {
        setSaving(true);
        setSaveError(null);
        setSaved(null);
        try {
            const res = await apiPutWithMfa<any>(
                `/api/v1/admin/authorities/${caId}/infrastructure-profiles`,
                toRequest(choices),
                requireStepUp,
                StepUpOps.UpdateCa,
                caId,
            );
            setSaved(res?.message ?? 'Saved.');
            await load();
        } catch (err: any) {
            if (err?.message !== 'Step-up MFA cancelled') setSaveError(errorNotice(err, 'Save failed'));
        } finally {
            setSaving(false);
        }
    };

    return (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 items-start">
            <div className="space-y-4">
                <p className="text-xs text-ink-muted">
                    The certificate profile each of this CA's own certificates is issued under. A profile
                    named here cannot be deleted, and the default ones cannot be renamed.
                </p>
                {answer.roles.map((role) => (
                    <div key={role.key}>
                        <label htmlFor={`infra-profile-${role.key}`} className={labelClass}>{roleLabel(role)}</label>
                        <select
                            id={`infra-profile-${role.key}`}
                            className={inputClass}
                            value={choices[role.key] ?? DEFAULT_CHOICE}
                            onChange={(e) => { setChoices({ ...choices, [role.key]: e.target.value }); setSaved(null); }}
                        >
                            <option value={DEFAULT_CHOICE}>Default ({role.defaultProfileName})</option>
                            {choicesFor(role, answer.candidates, otherDefaultNames(role, answer.roles)).map((c) => <option key={c.id} value={c.id}>{c.name}</option>)}
                        </select>
                    </div>
                ))}
                <div className="flex flex-wrap items-center gap-3">
                    <button
                        onClick={save}
                        disabled={saving || changed.length === 0}
                        className="px-3 py-1.5 text-sm bg-accent text-on-accent rounded hover:bg-accent-hover disabled:opacity-50 disabled:cursor-not-allowed transition-colors">
                        {saving ? 'Saving…' : 'Save Certificate Profiles'}
                    </button>
                    {changed.length > 0 && (
                        <span className="text-xs text-ink-muted">
                            Nothing is reissued by saving. Reissue below to apply the change to: {changed.map(roleLabel).join(', ')}.
                        </span>
                    )}
                    {saved && changed.length === 0 && <span className="text-xs text-ok">{saved}</span>}
                </div>
                {saveError && <InlineNotice notice={saveError} variant="line" />}
            </div>
            <div className="rounded border border-line bg-sunken p-3">
                <ConstraintPanel
                    groups={[...roleConstraintGroups(answer, choices), sharedConstraintGroup(answer, dateText)]}
                    empty="No certificate profile to show."
                />
            </div>
        </div>
    );
};

export default InfrastructureProfiles;
