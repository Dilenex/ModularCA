/**
 * Slide-over panel used by the shared DataTable for its column-visibility editor.
 *
 * Byte-identical in adminui and userui before this move. Shared because DataTable — which now
 * lives in shared/common — imports it, and a shared component may not reach back into a
 * consuming app for a dependency.
 */
import React, { useEffect } from 'react';

export interface DrawerProps {
    open: boolean;
    onClose: () => void;
    title?: React.ReactNode;
    /** Tailwind max-width class for the panel. Default 'max-w-lg', which holds a 32-character serial or a UUID on one line. */
    widthClass?: string;
    /** Optional sticky footer (e.g. an "Open full page" CTA). */
    footer?: React.ReactNode;
    children: React.ReactNode;
}

/**
 * Right-side slide-over panel for a read-only detail peek that keeps the underlying list in place.
 * Closes on backdrop click or Escape. For rich/editable detail, link to a full route from the
 * footer instead of growing this.
 */
export const Drawer: React.FC<DrawerProps> = ({ open, onClose, title, widthClass = 'max-w-lg', footer, children }) => {
    useEffect(() => {
        if (!open) return;
        const onKey = (e: KeyboardEvent) => { if (e.key === 'Escape') onClose(); };
        window.addEventListener('keydown', onKey);
        return () => window.removeEventListener('keydown', onKey);
    }, [open, onClose]);

    if (!open) return null;

    return (
        <div className="fixed inset-0 z-50">
            <div className="absolute inset-0 bg-scrim" onClick={onClose} aria-hidden="true" />
            <div className={`absolute right-0 top-0 h-full w-full ${widthClass} bg-raised border-l border-line shadow-2xl flex flex-col`}
                role="dialog" aria-modal="true">
                <div className="flex items-center justify-between gap-2 px-4 py-3 border-b border-line">
                    <div className="text-sm font-semibold text-ink min-w-0 truncate">{title}</div>
                    <button onClick={onClose} title="Close" className="text-ink-muted hover:text-ink text-xl leading-none px-1">×</button>
                </div>
                <div className="flex-1 overflow-y-auto p-4">{children}</div>
                {footer && <div className="border-t border-line p-3">{footer}</div>}
            </div>
        </div>
    );
};

// No default export: shared/README.md rule 3 keeps call sites greppable across five SPAs.
