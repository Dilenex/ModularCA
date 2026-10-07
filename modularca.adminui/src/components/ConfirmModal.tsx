import React, { useEffect, useRef } from 'react';

/**
 * Confirmation dialog for destructive or irreversible actions.
 *
 * Announced as a modal dialog, labelled by its title and described by its message; Escape
 * cancels; focus lands on Cancel when it opens and returns to the opener when it closes, so a
 * keyboard user is never left behind it. Clicking the backdrop cancels too, except while the
 * confirmed action is running, when the dialog holds until it finishes.
 */
/** Fill of the confirm button: `crit` (the default) for destructive actions, `warn` for disruptive ones. */
export type ConfirmTone = 'crit' | 'warn' | 'ok' | 'accent';

const TONE_CLASS: Record<ConfirmTone, string> = {
    crit: 'px-4 py-2 text-sm font-medium bg-crit text-on-accent rounded hover:bg-crit-hover transition-colors',
    warn: 'px-4 py-2 text-sm font-medium bg-warn text-on-accent rounded hover:bg-warn-hover transition-colors',
    ok: 'px-4 py-2 text-sm font-medium bg-ok text-on-accent rounded hover:bg-ok-hover transition-colors',
    accent: 'px-4 py-2 text-sm font-medium bg-accent text-on-accent rounded hover:bg-accent-hover transition-colors',
};

interface ConfirmModalProps {
    isOpen: boolean;
    title: string;
    message: React.ReactNode;
    confirmLabel?: string;
    /** Replaces the confirm button's whole class string, so it must carry its own text colour; prefer `tone`. */
    confirmClass?: string;
    tone?: ConfirmTone;
    loading?: boolean;
    onConfirm: () => void;
    onCancel: () => void;
}

const ConfirmModal: React.FC<ConfirmModalProps> = ({ isOpen, title, message, confirmLabel = 'Confirm', confirmClass, tone = 'crit', loading, onConfirm, onCancel }) => {
    const cancelRef = useRef<HTMLButtonElement | null>(null);
    const openerRef = useRef<Element | null>(null);
    const titleId = React.useId();
    const messageId = React.useId();

    useEffect(() => {
        if (!isOpen) return;
        openerRef.current = document.activeElement;
        cancelRef.current?.focus();
        const onKey = (e: KeyboardEvent) => {
            if (e.key === 'Escape' && !loading) { e.stopPropagation(); onCancel(); }
        };
        document.addEventListener('keydown', onKey);
        return () => {
            document.removeEventListener('keydown', onKey);
            const opener = openerRef.current;
            if (opener instanceof HTMLElement && document.contains(opener)) opener.focus();
        };
    }, [isOpen, loading, onCancel]);

    if (!isOpen) return null;
    return (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-scrim" onMouseDown={(e) => { if (e.target === e.currentTarget && !loading) onCancel(); }}>
            <div role="dialog" aria-modal="true" aria-labelledby={titleId} aria-describedby={messageId}
                className="bg-raised border border-line rounded-lg shadow-2xl p-5 w-full max-w-sm mx-4 space-y-4">
                <h3 id={titleId} className="text-base font-semibold text-ink">{title}</h3>
                <div id={messageId} className="text-sm text-ink-muted">{message}</div>
                <div className="flex justify-end gap-3">
                    <button ref={cancelRef} onClick={onCancel} disabled={loading}
                        className="px-4 py-2 text-sm font-medium bg-raised border border-line-strong text-ink rounded hover:bg-hover transition-colors">
                        Cancel
                    </button>
                    <button onClick={onConfirm} disabled={loading}
                        className={confirmClass || TONE_CLASS[tone]}>
                        {loading ? 'Processing...' : confirmLabel}
                    </button>
                </div>
            </div>
        </div>
    );
};

export default ConfirmModal;
