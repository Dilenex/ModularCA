import React, { useCallback, useEffect, useState } from 'react';
import type { NoticeInput } from '@shared/notifications/notice';
import { InlineNotice } from '@shared/components/InlineNotice';
import { FieldHint, inputClass, labelClass } from '@shared/components/forms';
import { errorNotice } from '@shared-auth/api/notices';
import { StepUpOps } from '@shared/generated';
import { apiGet, apiPutWithMfa } from '../api/client';
import { useStepUp } from './StepUpMfaContext';
import {
    DEFAULT_CHOICE, changedRoles, choicesFor, roleLabel, savedChoices, toRequest,
    type InfrastructureChoices, type InfrastructureProfilesAnswer,
} from '../pages/infrastructureProfiles';

/// <summary>
/// The certificate profile each of a CA's own certificates is issued under (OCSP responder, TSA
/// signer, CMP signer), with a picker per certificate. Saving changes nothing that is already
/// issued; the choice applies at the next reissue.
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
        <div className="space-y-3 max-w-3xl">
            <p className="text-xs text-ink-muted">
                The certificate profile each of this CA's own certificates is issued under. A profile
                named here cannot be deleted, and the default ones cannot be renamed.
            </p>
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
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
                            {choicesFor(role, answer.candidates).map((c) => <option key={c.id} value={c.id}>{c.name}</option>)}
                        </select>
                        {role.problem && <FieldHint tone="warn">{role.problem}</FieldHint>}
                    </div>
                ))}
            </div>
            <div className="flex items-center gap-3">
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
    );
};

export default InfrastructureProfiles;
