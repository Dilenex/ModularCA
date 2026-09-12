import React from 'react';
import { selectFieldNotices, type Notice, type NoticeSeverity } from '../notifications/notice';

/**
 * Messages rendered next to the control they are about, instead of in the corner of the screen.
 *
 * The server has always known which field it was refusing — a diagnostic carries `field`, model
 * state is keyed by field, a profile refusal names its `parameter` — and the client threw that
 * away, so "Valid To exceeds the profile maximum" arrived in a toast eighteen inches from the Valid
 * To box and vanished before the operator looked up. Putting the sentence under the box is the
 * whole point; the toast is the fallback for messages that belong to no control.
 *
 * This component owns only the rendering. Which notices belong here is decided by
 * `fieldMatches`/`selectFieldNotices` in `notifications/notice.ts`, because reconciling
 * `extendedKeyUsages` with `ExtendedKeyUsages` with "Extended key usages" is logic, not markup,
 * and logic that lives in JSX cannot be tested.
 */

/** Colour per severity. Muted relative to the toast palette: this sits inside a form, not over it. */
const severityStyles: Record<NoticeSeverity, string> = {
    success: 'text-green-700 dark:text-green-400',
    error: 'text-red-700 dark:text-red-400',
    warning: 'text-amber-700 dark:text-amber-400',
    info: 'text-blue-700 dark:text-blue-400',
};

export interface FieldNoticesProps {
    /** The full set for this form. Filtering happens here so call sites pass the same array to every control. */
    notices: Notice[];
    /**
     * The name(s) this control answers to. An array because the same field has different names on
     * either side of the wire — the reissue form's `notAfter` input is `validTo` in a diagnostic
     * and `NotAfter` in model state — and only the form knows which spellings mean itself.
     */
    field: string | string[];
    /** Set this and point the control's `aria-describedby` at it, so the message is announced with the field. */
    id?: string;
    className?: string;
}

/**
 * Renders every notice scoped to this control, or nothing at all when there are none — so it can
 * be dropped under a field unconditionally without the call site guarding it.
 */
export const FieldNotices: React.FC<FieldNoticesProps> = ({ notices, field, id, className }) => {
    const matched = selectFieldNotices(notices, field);
    if (matched.length === 0) return null;

    return (
        <div id={id} className={`mt-1 space-y-1 ${className ?? ''}`}>
            {matched.map((notice, i) => (
                <p key={i} className={`text-[11px] break-words ${severityStyles[notice.severity ?? 'error']}`}>
                    {notice.title && notice.title !== notice.detail && (
                        <span className="font-semibold">{notice.title}: </span>
                    )}
                    {notice.detail}
                    {notice.items?.length ? ` ${notice.items.join('; ')}` : ''}
                    {notice.remediation && <span className="opacity-90"> {notice.remediation}</span>}
                    {/* Monospaced and selectable rather than copy-buttoned: inline space is tight, and
                        the same code is on the toast next to a copy button when one was raised. */}
                    {notice.code && <span className="ml-1 font-mono select-all opacity-80">[{notice.code}]</span>}
                </p>
            ))}
        </div>
    );
};

/**
 * Whether any notice is scoped to this control, for `aria-invalid` and a red border.
 *
 * A thin wrapper, but it keeps call sites from importing the filtering helper just to measure the
 * length of its result, and it reads as the question the markup is actually asking.
 */
export function hasFieldNotice(notices: Notice[], field: string | string[]): boolean {
    return selectFieldNotices(notices, field).length > 0;
}
