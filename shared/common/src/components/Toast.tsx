import React from 'react';
import { copyText } from '../clipboard';
import {
    isNotice, toNotice, type Notice, type NoticeInput, type NoticeSeverity,
} from '../notifications/notice';

/**
 * Shared because the four copies had already begun to diverge: two spelled the status icons as
 * literal glyphs and two as escapes. That difference was harmless, but it is the same drift
 * that turned api/client.ts into four incompatible clients, and the styles here encode the
 * dark-mode contrast convention that every SPA is supposed to follow.
 *
 * It now renders a {@link Notice} as distinct elements rather than one sentence. The server sends
 * a title, an explanation, a remediation and a stable code; concatenating them into a single
 * string threw away every cue a reader uses to skim — and made the code, which exists to be pasted
 * into a ticket, something you have to retype out of the middle of a paragraph. The string form is
 * still accepted and still renders the way it always did, because 238 call sites pass one.
 */

/** Severity of a toast. Historical name for {@link NoticeSeverity}; the two are the same union. */
export type ToastType = NoticeSeverity;

export interface ToastProps {
    id: string;
    type: ToastType;
    /** A plain sentence, as before, or the structured form. */
    message: NoticeInput;
    onDismiss: (id: string) => void;
}

const typeStyles: Record<ToastType, string> = {
    success: 'bg-green-50 dark:bg-green-900 border-green-500 text-green-800 dark:text-green-300',
    error: 'bg-red-50 dark:bg-red-900 border-red-500 text-red-800 dark:text-red-300',
    warning: 'bg-amber-50 dark:bg-amber-900 border-amber-500 text-amber-800 dark:text-amber-300',
    info: 'bg-blue-50 dark:bg-blue-900 border-blue-500 text-blue-800 dark:text-blue-300',
};

const typeIcons: Record<ToastType, string> = {
    success: '\u2713',
    error: '\u2715',
    warning: '\u26A0',
    info: '\u2139',
};

/**
 * Classes for the fixed stack every provider renders toasts into.
 *
 * Exported because three ToastProviders (shared, publicui, docsui) each declare that container and
 * they were already identical strings — the same copy-drift this file exists to stop.
 *
 * Wider than the previous `max-w-sm`: a policy refusal with a detail, a remediation and a code no
 * longer fits in 24rem, and the alternative to widening is a taller column of five-word lines. The
 * width is clamped against the viewport so the stack cannot overhang a narrow screen, and each
 * toast scrolls internally rather than the column growing without limit.
 */
export const toastViewportClass =
    'fixed top-4 right-4 z-[100] flex flex-col gap-2 w-[calc(100vw-2rem)] max-w-md';

/**
 * A code or correlation id, with a button that copies it.
 *
 * These two values are the only part of an error that is meant to leave the screen — they are what
 * turns "it did not work" into something a maintainer can find in a log. Monospaced and set apart
 * so they read as identifiers rather than prose, and `select-all` so a click selects the whole
 * token even when the copy button cannot be used.
 */
const CopyableToken: React.FC<{ label: string; value: string }> = ({ label, value }) => {
    const [copied, setCopied] = React.useState(false);

    const handleCopy = async () => {
        if (await copyText(value)) {
            setCopied(true);
            window.setTimeout(() => setCopied(false), 1500);
        }
    };

    return (
        <span className="inline-flex items-center gap-1 text-[11px]">
            <span className="opacity-70">{label}</span>
            <code className="font-mono select-all break-all">{value}</code>
            <button
                type="button"
                onClick={handleCopy}
                aria-label={`Copy ${label} ${value}`}
                className="px-1.5 py-0.5 rounded bg-black/5 dark:bg-black/20 hover:bg-black/10 dark:hover:bg-black/40 dark:hover:text-white transition-colors"
            >
                {copied ? 'Copied' : 'Copy'}
            </button>
        </span>
    );
};

export const Toast: React.FC<ToastProps> = ({ id, type, message, onDismiss }) => {
    const notice: Notice = toNotice(message, type);
    // A bare string keeps the old single-paragraph rendering; only a structured notice gets the
    // title/detail/remediation split. Nothing about the 238 string call sites changes visually.
    const structured = isNotice(message);
    const showTitle = structured && notice.title && notice.title !== notice.detail;

    // Assertive for the two severities that now persist: they report that the operator did not get
    // what they asked for, which is worth interrupting a screen reader for. Success and info are
    // receipts and wait their turn. Neither form takes focus — the operator may be mid-word in a
    // field, and a toast that moves the caret would be a worse bug than the one it is reporting.
    const urgent = type === 'error' || type === 'warning';

    return (
        <div
            role={urgent ? 'alert' : 'status'}
            aria-live={urgent ? 'assertive' : 'polite'}
            aria-atomic="true"
            // Escape closes the toast once focus is inside it — reached by tabbing to the dismiss
            // button. Deliberately not a document-level handler: Escape belongs to whichever modal
            // or menu the operator is actually in, and stealing it here would close two things at
            // once.
            onKeyDown={e => { if (e.key === 'Escape') { e.stopPropagation(); onDismiss(id); } }}
            className={`flex items-start gap-3 px-4 py-3 rounded-lg border-l-4 shadow-lg animate-slide-in motion-reduce:animate-none ${typeStyles[type]}`}
        >
            <span className="text-lg font-bold flex-shrink-0" aria-hidden="true">{typeIcons[type]}</span>
            {/* The body scrolls rather than the column growing: a policy refusal can carry a dozen
                violations, and a toast taller than the viewport has no dismiss button on screen. */}
            <div className="flex-1 min-w-0 space-y-1 max-h-[60vh] overflow-y-auto">
                {showTitle && <p className="text-sm font-semibold break-words">{notice.title}</p>}
                {notice.detail && <p className="text-sm break-words whitespace-pre-line">{notice.detail}</p>}
                {notice.items && notice.items.length > 0 && (
                    <ul className="text-xs list-disc list-outside pl-4 space-y-0.5">
                        {notice.items.map((item, i) => <li key={i} className="break-words">{item}</li>)}
                    </ul>
                )}
                {notice.remediation && <p className="text-xs opacity-90 break-words">{notice.remediation}</p>}
                {(notice.code || notice.correlationId) && (
                    <div className="flex flex-wrap items-center gap-x-3 gap-y-1 pt-0.5">
                        {notice.code && <CopyableToken label="Code" value={notice.code} />}
                        {notice.correlationId && <CopyableToken label="Correlation id" value={notice.correlationId} />}
                    </div>
                )}
            </div>
            <button
                onClick={() => onDismiss(id)}
                aria-label="Dismiss notification"
                className="text-current opacity-50 hover:opacity-100 flex-shrink-0"
            >
                &times;
            </button>
        </div>
    );
};
