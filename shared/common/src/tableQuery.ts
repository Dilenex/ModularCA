/**
 * A table's page, sort and filters as they travel in the query string. Pure helpers; the
 * `useTableQuery` hook binds them to the router.
 *
 * Values equal to their defaults are left out of the URL, so a plain page link stays plain
 * and only what the user changed shows. The console's scope keys (`ca`, `tenant`, `scope`)
 * are never written or cleared here: scope belongs to the sidebar, not to any one table.
 */

/** A sort as `field` ascending or `-field` descending. */
export interface SortSpec {
    key: string;
    dir: 'asc' | 'desc';
}

export const SCOPE_KEYS: ReadonlySet<string> = new Set(['ca', 'tenant', 'scope']);

/** Parses `-field` / `field` / `field:desc`; null for nothing or an empty string. */
export function parseSort(raw: string | null | undefined): SortSpec | null {
    if (!raw) return null;
    const s = raw.trim();
    if (!s) return null;
    if (s.startsWith('-')) return s.length > 1 ? { key: s.slice(1), dir: 'desc' } : null;
    const [key, dir] = s.split(':');
    if (!key) return null;
    return { key, dir: dir === 'desc' ? 'desc' : 'asc' };
}

/** The wire form of a sort: `field` or `-field`. */
export function formatSort(sort: SortSpec | null | undefined): string {
    if (!sort) return '';
    return sort.dir === 'desc' ? `-${sort.key}` : sort.key;
}

/** What one table keeps in the URL. Every value is a string; pages parse what they need. */
export type TableQueryValues = Record<string, string>;

/**
 * Reads the keys named in `defaults` from a query string. A key absent from the URL takes
 * its default; an optional `prefix` (for a page with more than one table) namespaces the keys
 * as `prefix.key`.
 */
export function readTableQuery(search: string | URLSearchParams, defaults: TableQueryValues, prefix = ''): TableQueryValues {
    const params = typeof search === 'string' ? new URLSearchParams(search) : search;
    const out: TableQueryValues = {};
    for (const key of Object.keys(defaults)) {
        const raw = params.get(prefix ? `${prefix}.${key}` : key);
        out[key] = raw == null ? defaults[key] : raw;
    }
    return out;
}

/**
 * Writes table values into a copy of the query string. Values equal to their default are
 * removed rather than written; every other parameter (the scope, other tables) is kept.
 */
export function writeTableQuery(search: string | URLSearchParams, values: TableQueryValues, defaults: TableQueryValues, prefix = ''): URLSearchParams {
    const params = new URLSearchParams(typeof search === 'string' ? search : search.toString());
    for (const key of Object.keys(defaults)) {
        if (SCOPE_KEYS.has(key)) continue;
        const name = prefix ? `${prefix}.${key}` : key;
        const value = values[key] ?? defaults[key];
        if (value === defaults[key] || value === '') params.delete(name);
        else params.set(name, value);
    }
    return params;
}

/**
 * The part of a query string a saved view keeps: the table's own keys, minus the page (a view
 * is a filter, not a position). Scope keys are left out too; a view applies to whatever scope
 * the user is in when they pick it.
 */
export function viewQuery(values: TableQueryValues, defaults: TableQueryValues): string {
    const params = new URLSearchParams();
    for (const key of Object.keys(defaults).sort()) {
        if (key === 'page' || SCOPE_KEYS.has(key)) continue;
        const value = values[key] ?? defaults[key];
        if (value !== defaults[key] && value !== '') params.set(key, value);
    }
    return params.toString();
}

/** A saved view: a name and the filter it re-applies. */
export interface SavedView {
    name: string;
    query: string;
}

/** Adds or replaces a view by name, keeping the list ordered by name. */
export function upsertView(views: SavedView[], view: SavedView): SavedView[] {
    const name = view.name.trim();
    if (!name) return views;
    const next = views.filter(v => v.name.toLowerCase() !== name.toLowerCase());
    next.push({ name, query: view.query });
    return next.sort((a, b) => a.name.localeCompare(b.name));
}

/** Removes a view by name. */
export function removeView(views: SavedView[], name: string): SavedView[] {
    return views.filter(v => v.name !== name);
}
