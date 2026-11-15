import React, { useEffect, useState } from 'react';
import type { NoticeInput } from '@shared/notifications/notice';
import { InlineNotice } from '@shared/components/InlineNotice';
import { errorNotice } from '@shared-auth/api/notices';
import { StatusBadge } from '@shared/components/cards/StatusBadge';
import { actionButtonPrimary } from '@shared/components/actionButtons';
import { inputClass, labelClass, FieldHint } from '@shared/components/forms';
import { StepUpOps, type InstanceModeStatus } from '@shared/generated';
import { apiGet, apiPutWithMfa } from '../api/client';
import { useStepUp } from './StepUpMfaContext';
import ConfirmModal from './ConfirmModal';
import {
    INSTANCE_MODE_CHANGED_EVENT, INSTANCE_MODE_OPTIONS, type InstanceModeName,
    modeChangeBlocked, modeName, modeOption, modeTitle, setByText, crlDeadlineText,
} from '../pages/instanceMode';

const MODE_PATH = '/api/v1/admin/instance-mode';

/**
 * Settings, General: the instance mode. Shows the mode, who set it and when, and lets an
 * administrator set it by hand with a reason, behind a step-up. Setting the mode is allowed in
 * every mode, so this card is also the way out of DR mode.
 */
export const InstanceModeCard: React.FC = () => {
    const { requireStepUp } = useStepUp();
    const [status, setStatus] = useState<InstanceModeStatus | null>(null);
    const [loadError, setLoadError] = useState<NoticeInput | null>(null);
    const [chosen, setChosen] = useState<InstanceModeName>('full');
    const [reason, setReason] = useState('');
    const [confirming, setConfirming] = useState(false);
    const [saving, setSaving] = useState(false);
    const [saveError, setSaveError] = useState<NoticeInput | null>(null);

    useEffect(() => {
        let cancelled = false;
        apiGet<InstanceModeStatus>(MODE_PATH, { toast: false })
            .then((s) => { if (!cancelled) { setStatus(s); setChosen(modeName(s.mode)); } })
            .catch((err) => { if (!cancelled) setLoadError(errorNotice(err, 'The instance mode could not be read.')); });
        return () => { cancelled = true; };
    }, []);

    const blocked = modeChangeBlocked(status?.mode, chosen, reason);
    const chosenOption = modeOption(chosen);

    const save = async () => {
        setSaving(true);
        setSaveError(null);
        try {
            const next = await apiPutWithMfa<InstanceModeStatus>(
                MODE_PATH, { mode: chosen, reason: reason.trim() }, requireStepUp, StepUpOps.SetInstanceMode);
            setStatus(next);
            setChosen(modeName(next.mode));
            setReason('');
            window.dispatchEvent(new Event(INSTANCE_MODE_CHANGED_EVENT));
        } catch (err: any) {
            if (err?.message !== 'Step-up MFA cancelled')
                setSaveError(errorNotice(err, 'The mode was not changed.'));
        } finally {
            setSaving(false);
            setConfirming(false);
        }
    };

    const current = status ? modeName(status.mode) : null;

    return (
        <div className="bg-raised border border-line rounded-lg p-4 space-y-4">
            <div className="flex items-start justify-between gap-3">
                <div>
                    <h3 className="text-sm font-semibold text-ink">Instance mode</h3>
                    <p className="text-xs text-ink-muted mt-1">
                        What this instance may do right now. The instance's hub, when it has one, sets the mode; an
                        administrator can set it here as well, and whoever sets it last wins. It is kept on this host, not
                        in the database.
                    </p>
                </div>
                {current && (
                    <StatusBadge status={current === 'full' ? 'active' : current === 'dr' ? 'locked' : 'expired'} label={modeTitle(current)} />
                )}
            </div>

            {loadError && <InlineNotice notice={loadError} />}

            {status && (
                <>
                    <dl className="grid grid-cols-1 sm:grid-cols-3 gap-3 text-xs">
                        <div>
                            <dt className={labelClass}>Set by</dt>
                            <dd className="text-ink">{setByText(status)}</dd>
                        </div>
                        <div>
                            <dt className={labelClass}>When</dt>
                            <dd className="text-ink">{status.setAtUtc
                                ? new Date(status.setAtUtc).toLocaleString('en-US', { year: 'numeric', month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' })
                                : '-'}</dd>
                        </div>
                        <div>
                            <dt className={labelClass}>Reason</dt>
                            <dd className="text-ink">{status.reason || '-'}</dd>
                        </div>
                    </dl>

                    {/* A mode that signs no new CRL has a clock on it: say when the CRLs in force run out. */}
                    {crlDeadlineText(status) && (
                        <div className="rounded border border-warn/40 bg-warn-soft p-3 max-w-3xl" role="status">
                            <p className="text-xs text-warn">{crlDeadlineText(status)}</p>
                        </div>
                    )}

                    <fieldset className="space-y-2">
                        <legend className={labelClass}>Set the mode</legend>
                        {INSTANCE_MODE_OPTIONS.map((option) => (
                            <label key={option.value} className="flex items-start gap-3 p-3 border border-line rounded cursor-pointer hover:bg-hover">
                                <input
                                    type="radio"
                                    name="instance-mode"
                                    className="mt-0.5"
                                    checked={chosen === option.value}
                                    onChange={() => setChosen(option.value)}
                                />
                                <span className="text-xs">
                                    <span className="font-semibold text-ink">{option.label}</span>
                                    {current === option.value && <span className="text-ink-muted"> (current)</span>}
                                    <span className="block text-ink-muted mt-0.5">{option.summary}</span>
                                    <span className="block text-ink-muted mt-0.5"><span className="text-ink">Stops:</span> {option.stops}</span>
                                    <span className="block text-ink-muted mt-0.5"><span className="text-ink">Keeps:</span> {option.keeps}</span>
                                </span>
                            </label>
                        ))}
                    </fieldset>

                    <div>
                        <label htmlFor="instance-mode-reason" className={labelClass}>Reason</label>
                        <input
                            id="instance-mode-reason"
                            className={inputClass}
                            value={reason}
                            maxLength={500}
                            autoComplete="off"
                            placeholder="Why the mode is being changed"
                            onChange={(e) => setReason(e.target.value)}
                        />
                        <FieldHint>Recorded in the audit trail and shown here beside the mode.</FieldHint>
                        {status.hubConnection && (
                            <FieldHint tone="warn">
                                This instance has a hub connection. The hub can set the mode again at any time, and what it sets replaces what is set here.
                            </FieldHint>
                        )}
                    </div>

                    {saveError && <InlineNotice notice={saveError} />}

                    <div className="flex items-center gap-3">
                        <button
                            type="button"
                            className={actionButtonPrimary}
                            disabled={saving || blocked !== null}
                            title={blocked ?? undefined}
                            onClick={() => setConfirming(true)}
                        >
                            {saving ? 'Setting...' : `Set ${chosenOption.label === 'DR mode' ? 'DR mode' : `${chosenOption.label.toLowerCase()} mode`}`}
                        </button>
                        {blocked && current !== chosen && <span className="text-xs text-ink-muted">{blocked}</span>}
                    </div>

                    <ConfirmModal
                        isOpen={confirming}
                        title={`Set ${modeTitle(chosen).toLowerCase().replace('dr mode', 'DR mode')}`}
                        message={
                            <span className="block space-y-2">
                                <span className="block">{chosenOption.summary}</span>
                                <span className="block"><span className="font-semibold">Stops:</span> {chosenOption.stops}</span>
                                <span className="block"><span className="font-semibold">Keeps:</span> {chosenOption.keeps}</span>
                            </span>
                        }
                        confirmLabel="Set mode"
                        tone={chosen === 'full' ? 'accent' : chosen === 'dr' ? 'crit' : 'warn'}
                        loading={saving}
                        onConfirm={save}
                        onCancel={() => setConfirming(false)}
                    />
                </>
            )}
        </div>
    );
};

export default InstanceModeCard;
