import React, { useEffect, useRef } from 'react';

/**
 * Confirmation dialog for destructive or irreversible actions.
 *
 * Announced as a modal dialog, labelled by its title and described by its message; Escape
 * cancels; focus lands on Cancel when it opens and returns to the opener when it closes, so a
 * keyboard user is never left behind it. Clicking the backdrop cancels too, except while the
 * confirmed action is running, when the dialog holds until it finishes.
 */
interface ConfirmModalProps {
    isOpen: boolean;
    title: string;
    message: React.ReactNode;
    confirmLabel?: string;
    confirmClass?: string;
    loading?: boolean;
    onConfirm: () => void;
    onCancel: () => void;
}

const ConfirmModal: React.FC<ConfirmModalProps> = ({ isOpen, title, message, confirmLabel = 'Confirm', confirmClass, loading, onConfirm, onCancel }) => {
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
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50" onMouseDown={(e) => { if (e.target === e.currentTarget && !loading) onCancel(); }}>
            <div role="dialog" aria-modal="true" aria-labelledby={titleId} aria-describedby={messageId}
                className="bg-white dark:bg-gray-800 border border-gray-300 dark:border-gray-700 rounded-xl shadow-2xl p-6 w-full max-w-sm mx-4 space-y-4">
                <h3 id={titleId} className="text-lg font-bold text-gray-900 dark:text-white">{title}</h3>
                <div id={messageId} className="text-sm text-gray-600 dark:text-gray-400">{message}</div>
                <div className="flex justify-end gap-3">
                    <button ref={cancelRef} onClick={onCancel} disabled={loading}
                        className="px-4 py-2 text-sm bg-gray-200 dark:bg-gray-700 text-gray-700 dark:text-gray-300 rounded hover:bg-gray-300 dark:hover:bg-gray-600 transition-colors">
                        Cancel
                    </button>
                    <button onClick={onConfirm} disabled={loading}
                        className={confirmClass || "px-4 py-2 text-sm bg-red-600 text-white rounded hover:bg-red-700 transition-colors"}>
                        {loading ? 'Processing...' : confirmLabel}
                    </button>
                </div>
            </div>
        </div>
    );
};

export default ConfirmModal;
