import React from 'react';
import { copyText } from '../clipboard';
import { isNotice, toNotice, type NoticeInput, type NoticeSeverity } from '../notifications/notice';

/**
 * A notice rendered in the page, where the error used to be one red sentence.
 *
 * The toast already shows a refusal as distinct elements: a title, the explanation, what to do
 * about it, and a code that can be copied into a ticket. The same refusal rendered inline, under
 * the form that caused it or in place of the table that failed to load, was flattened to
 * `err.message` and lost the remediation. This is the inline counterpart of the toast's body, in
 * the same order, so the message an operator reads next to the control carries everything the
 * fading one in the corner did.
 *
 * Accepts the string arm too, so a call site that still holds a plain sentence renders exactly as
 * before; nothing has to change at once.
 */
export interface InlineNoticeProps {
    notice: NoticeInput | null | undefined;
    severity?: NoticeSeverity;
    /** `block` is the bordered panel; `line` is a bare paragraph for tight spots such as a dialog footer. */
    variant?: 'block' | 'line';
    className?: string;
    /** Called when the operator dismisses the notice; omit to render no dismiss control. */
    onDismiss?: () => void;
}

const blockStyles: Record<NoticeSeverity, string> = {
    error: 'bg-red-50 dark:bg-red-900/20 border-red-300 dark:border-red-700 text-red-800 dark:text-red-300',
    warning: 'bg-amber-50 dark:bg-amber-900/20 border-amber-300 dark:border-amber-700 text-amber-900 dark:text-amber-200',
    info: 'bg-blue-50 dark:bg-blue-900/20 border-blue-300 dark:border-blue-700 text-blue-900 dark:text-blue-200',
    success: 'bg-green-50 dark:bg-green-900/20 border-green-300 dark:border-green-700 text-green-900 dark:text-green-200',
};

const lineStyles: Record<NoticeSeverity, string> = {
    error: 'text-red-800 dark:text-red-400',
    warning: 'text-amber-800 dark:text-amber-300',
    info: 'text-blue-800 dark:text-blue-300',
    success: 'text-green-800 dark:text-green-300',
};

const Token: React.FC<{ label: string; value: string }> = ({ label, value }) => {
    const [copied, setCopied] = React.useState(false);
    const copy = async () => {
        if (await copyText(value)) {
            setCopied(true);
            window.setTimeout(() => setCopied(false), 1500);
        }
    };
    return (
        <span className="inline-flex items-center gap-1 text-[11px]">
            <span className="opacity-70">{label}</span>
            <code className="font-mono select-all break-all">{value}</code>
            <button type="button" onClick={copy} aria-label={`Copy ${label} ${value}`}
                className="px-1.5 py-0.5 rounded bg-black/5 dark:bg-black/20 hover:bg-black/10 dark:hover:bg-black/40 transition-colors">
                {copied ? 'Copied' : 'Copy'}
            </button>
        </span>
    );
};

export const InlineNotice: React.FC<InlineNoticeProps> = ({ notice, severity, variant = 'block', className = '', onDismiss }) => {
    if (notice == null || notice === '') return null;
    const n = toNotice(notice, severity);
    const sev: NoticeSeverity = n.severity ?? severity ?? 'error';
    const structured = isNotice(notice);
    const showTitle = structured && !!n.title && n.title !== n.detail;
    const urgent = sev === 'error' || sev === 'warning';

    if (variant === 'line') {
        // One paragraph: title, detail, remediation in prose, code in brackets. For places that
        // only ever had room for a sentence.
        return (
            <p role={urgent ? 'alert' : 'status'} className={`text-sm break-words ${lineStyles[sev]} ${className}`}>
                {showTitle && <span className="font-semibold">{n.title}: </span>}
                {n.detail}
                {n.items?.length ? ` ${n.items.join('; ')}` : ''}
                {n.remediation && <span className="opacity-90"> {n.remediation}</span>}
                {n.code && <span className="ml-1 font-mono text-xs select-all opacity-80">[{n.code}]</span>}
            </p>
        );
    }

    return (
        <div role={urgent ? 'alert' : 'status'} aria-live={urgent ? 'assertive' : 'polite'}
            className={`flex items-start gap-3 px-3 py-2 rounded-md border ${blockStyles[sev]} ${className}`}>
            <div className="flex-1 min-w-0 space-y-1">
                {showTitle && <p className="text-sm font-semibold break-words">{n.title}</p>}
                {n.detail && <p className="text-sm break-words whitespace-pre-line">{n.detail}</p>}
                {n.items && n.items.length > 0 && (
                    <ul className="text-xs list-disc list-outside pl-4 space-y-0.5">
                        {n.items.map((item, i) => <li key={i} className="break-words">{item}</li>)}
                    </ul>
                )}
                {n.remediation && <p className="text-xs opacity-90 break-words">{n.remediation}</p>}
                {(n.code || n.correlationId) && (
                    <div className="flex flex-wrap items-center gap-x-3 gap-y-1 pt-0.5">
                        {n.code && <Token label="Code" value={n.code} />}
                        {n.correlationId && <Token label="Correlation id" value={n.correlationId} />}
                    </div>
                )}
            </div>
            {onDismiss && (
                <button type="button" onClick={onDismiss} aria-label="Dismiss" className="text-current opacity-50 hover:opacity-100 flex-shrink-0">&times;</button>
            )}
        </div>
    );
};

export default InlineNotice;
