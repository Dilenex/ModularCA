import React, { useState } from 'react';
import { useTablePrefs } from '../context/TablePrefsContext';
import { removeView, upsertView, type SavedView } from '../tableQuery';

/**
 * Saved views for one table: named filters the user can re-apply with one click.
 *
 * A view is a name plus the table's query string (its filters and sort, never the page),
 * stored beside the column preferences in the per-user preference store, so it follows the
 * user across browsers. "Expiring in 30 days on staging-ca-r1" becomes a chip above the table.
 */
export const SavedViews: React.FC<{
    tableId: string;
    /** The current filter, as `viewQuery` renders it; empty when nothing is filtered. */
    current: string;
    /** Applies a saved query string to the table. */
    onApply: (query: string) => void;
}> = ({ tableId, current, onApply }) => {
    const [prefs, setPrefs] = useTablePrefs<{ views: SavedView[] }>(`views:${tableId}`, { views: [] });
    const [naming, setNaming] = useState(false);
    const [name, setName] = useState('');

    const save = (e: React.FormEvent) => {
        e.preventDefault();
        if (!name.trim()) return;
        setPrefs({ views: upsertView(prefs.views, { name, query: current }) });
        setName('');
        setNaming(false);
    };

    const active = prefs.views.find(v => v.query === current)?.name ?? null;

    if (prefs.views.length === 0 && !current && !naming) return null;

    return (
        <div className="flex items-center gap-2 flex-wrap text-xs">
            {prefs.views.length > 0 && <span className="text-gray-500 dark:text-gray-400">Views:</span>}
            {prefs.views.map((v) => (
                <span key={v.name} className={`inline-flex items-center rounded border ${active === v.name ? 'border-blue-400 bg-blue-50 dark:bg-blue-900/40 text-blue-800 dark:text-blue-200' : 'border-gray-300 dark:border-gray-600 bg-gray-50 dark:bg-gray-900 text-gray-700 dark:text-gray-300'}`}>
                    <button type="button" onClick={() => onApply(v.query)} className="px-2 py-0.5 hover:underline" title={v.query || 'No filter'}>{v.name}</button>
                    <button type="button" onClick={() => setPrefs({ views: removeView(prefs.views, v.name) })} aria-label={`Delete view ${v.name}`} className="px-1.5 py-0.5 border-l border-gray-300 dark:border-gray-600 text-gray-500 hover:text-red-600">×</button>
                </span>
            ))}
            {current && !naming && !active && (
                <button type="button" onClick={() => setNaming(true)} className="px-2 py-0.5 rounded border border-dashed border-gray-400 dark:border-gray-600 text-gray-600 dark:text-gray-400 hover:border-blue-400 hover:text-blue-800 dark:hover:text-blue-300">
                    Save current view…
                </button>
            )}
            {naming && (
                <form onSubmit={save} className="inline-flex items-center gap-1">
                    <input
                        autoFocus
                        value={name}
                        onChange={(e) => setName(e.target.value)}
                        placeholder="View name"
                        maxLength={60}
                        className="px-2 py-0.5 rounded border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-900 text-gray-900 dark:text-white focus:outline-none focus:border-blue-500"
                    />
                    <button type="submit" className="px-2 py-0.5 rounded bg-blue-600 text-white hover:bg-blue-700">Save</button>
                    <button type="button" onClick={() => { setNaming(false); setName(''); }} className="px-2 py-0.5 text-gray-600 dark:text-gray-400 hover:underline">Cancel</button>
                </form>
            )}
        </div>
    );
};
