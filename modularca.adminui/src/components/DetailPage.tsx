import React, { useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';

export type DetailMode = 'view' | 'edit';

export interface Breadcrumb {
    label: string;
    to?: string;
}

export interface DetailPageProps {
    /** Breadcrumb trail; the last item is the current page (usually no `to`). */
    breadcrumbs: Breadcrumb[];
    title: React.ReactNode;
    /** Status badge(s) shown beside the title. */
    status?: React.ReactNode;
    /** Secondary identity line under the title. */
    subtitle?: React.ReactNode;
    /** Right-aligned action bar (download / revoke …). */
    actions?: React.ReactNode;
    /** Explicit Back target; falls back to browser history. */
    backTo?: string;
    /** When false (default), the View/Edit toggle is shown but Edit is disabled (read-only entry). */
    editable?: boolean;
    /** Starting mode when editable. Default 'view'. */
    initialMode?: DetailMode;
    /** Unified save handler. When provided, a single Save button appears in Edit mode (next to a
     *  Cancel). Should persist all pending changes; resolve on success (the page returns to View) and
     *  reject on failure (the page stays in Edit). */
    onSave?: () => void | Promise<void>;
    /** Discard pending changes. Called by Cancel and whenever Edit is left (View toggle). */
    onCancel?: () => void;
    /** Grey out Save (e.g. nothing changed, or a validation error). */
    saveDisabled?: boolean;
    /** Body renderer — receives the active mode and a `setMode` helper (e.g. to return to view after save). */
    children: (mode: DetailMode, api: { setMode: (m: DetailMode) => void }) => React.ReactNode;
}

/**
 * Consistent shell for a single-entity detail route: breadcrumb + Back, an identity header with
 * status, a View/Edit toggle, and an action bar, then the sectioned body. The Edit toggle is
 * blocked for read-only entries (`editable` false) so the same shell serves both kinds of page.
 */
export const DetailPage: React.FC<DetailPageProps> = ({
    breadcrumbs, title, status, subtitle, actions, backTo, editable = false, initialMode = 'view',
    onSave, onCancel, saveDisabled, children,
}) => {
    const navigate = useNavigate();
    const [mode, setMode] = useState<DetailMode>(editable ? initialMode : 'view');
    const [saving, setSaving] = useState(false);
    const activeMode: DetailMode = editable ? mode : 'view';
    // Leaving edit always discards pending changes (Cancel button, or clicking the View toggle).
    const leaveEdit = () => { if (activeMode === 'edit') onCancel?.(); setMode('view'); };
    // Guarded setter handed to the body: can't switch to edit on a read-only entry.
    const setModeSafe = (m: DetailMode) => { if (m === 'edit' && !editable) return; if (m === 'view') leaveEdit(); else setMode('edit'); };

    const handleSave = async () => {
        if (!onSave || saveDisabled || saving) return;
        setSaving(true);
        try { await onSave(); setMode('view'); }
        catch { /* keep editing on failure — the handler surfaces the error */ }
        finally { setSaving(false); }
    };

    const segBtn = (m: DetailMode, label: string, disabled?: boolean) => (
        <button
            onClick={() => { if (disabled) return; if (m === 'view') leaveEdit(); else setMode('edit'); }}
            disabled={disabled}
            title={disabled ? 'This entry is read-only' : undefined}
            className={`px-3 py-1 text-xs font-medium transition-colors ${activeMode === m
                ? 'bg-accent text-on-accent'
                : 'bg-raised text-ink hover:bg-hover'}
                ${disabled ? 'opacity-40 cursor-not-allowed' : ''}`}>
            {label}
        </button>
    );

    return (
        <div className="p-3 sm:p-6 space-y-4 sm:space-y-6">
            <div className="flex items-center gap-2 text-xs text-ink-muted">
                <button onClick={() => (backTo ? navigate(backTo) : navigate(-1))}
                    className="px-2 py-1 rounded border border-line-strong bg-raised text-ink hover:bg-hover transition-colors">‹ Back</button>
                <nav className="flex items-center gap-1 min-w-0">
                    {breadcrumbs.map((b, i) => (
                        <span key={i} className="flex items-center gap-1 min-w-0">
                            {i > 0 && <span className="text-ink-faint">/</span>}
                            {b.to ? <Link to={b.to} className="hover:underline truncate">{b.label}</Link>
                                : <span className="text-ink truncate">{b.label}</span>}
                        </span>
                    ))}
                </nav>
            </div>

            <div className="flex items-start justify-between gap-4 flex-wrap">
                <div className="min-w-0">
                    <div className="flex items-center gap-3 flex-wrap">
                        <h1 className="text-xl font-semibold text-ink">{title}</h1>
                        {status}
                    </div>
                    {subtitle && <div className="text-sm text-ink-muted mt-1">{subtitle}</div>}
                </div>
                <div className="flex items-center gap-2 flex-wrap">
                    {/* View/Edit toggle — Edit is blocked for read-only entries. */}
                    <div className="inline-flex rounded border border-line-strong overflow-hidden">
                        {segBtn('view', 'View')}
                        {segBtn('edit', 'Edit', !editable)}
                    </div>
                    {actions}
                </div>
            </div>

            {children(activeMode, { setMode: setModeSafe })}

            {/* Unified Save / Cancel — pinned at the bottom of the page in Edit mode when a save
                handler is wired. Sticky so it stays reachable on long forms. */}
            {editable && activeMode === 'edit' && onSave && (
                <div className="sticky bottom-0 -mx-3 sm:-mx-6 px-3 sm:px-6 py-3 flex items-center justify-end gap-2 border-t border-line bg-ground/95 backdrop-blur supports-[backdrop-filter]:bg-ground/80">
                    <button onClick={leaveEdit} disabled={saving}
                        title="Discard changes and return to view"
                        className="px-4 py-2 text-sm font-medium bg-raised border border-line-strong text-ink rounded hover:bg-hover disabled:opacity-40 transition-colors">
                        Cancel
                    </button>
                    <button onClick={handleSave} disabled={saveDisabled || saving}
                        title={saveDisabled ? 'No unsaved changes' : 'Save all changes'}
                        className="px-4 py-2 text-sm font-medium bg-accent text-on-accent rounded hover:bg-accent-hover disabled:opacity-40 disabled:cursor-not-allowed transition-colors">
                        {saving ? 'Saving…' : 'Save'}
                    </button>
                </div>
            )}
        </div>
    );
};

/** A labelled section card for use inside a DetailPage body. */
export const DetailSection: React.FC<{ title?: string; children: React.ReactNode }> = ({ title, children }) => (
    <div className="bg-raised border border-line rounded-lg overflow-hidden">
        {title && (
            <div className="px-4 py-3 border-b border-line">
                <h3 className="text-sm font-semibold text-ink">{title}</h3>
            </div>
        )}
        <div className="p-4">{children}</div>
    </div>
);

export default DetailPage;
