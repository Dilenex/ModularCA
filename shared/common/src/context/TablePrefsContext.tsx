import React, { createContext, useCallback, useContext, useEffect, useRef, useState } from 'react';

/**
 * Per-user UI preference persistence for tables, shared by adminui and userui.
 *
 * The hook itself was byte-identical in both SPAs. Its one app-specific dependency was the
 * authenticated API client, which `shared/common` may not import (rule 1 in shared/README.md) —
 * so the transport arrives through a provider instead, the same way `StepUpMfaModal` takes
 * `apiPost` as a prop rather than reaching for a client of its own.
 *
 * Storage is two-tier and unchanged from the original:
 *   - localStorage is the instant, per-browser fast path, read synchronously on mount.
 *   - `/api/v1/me/preferences` is the cross-device source of truth, fetched once per session and
 *     used to hydrate a browser that has no local copy yet.
 *
 * Every update writes both. A browser that already has a local value keeps using it — that value
 * is this browser's latest — while the backend copy seeds new browsers and devices.
 */

/** The two client calls the preference store needs. Supplied by the consuming SPA. */
export interface TablePrefsTransport {
    apiGet: <T = any>(path: string) => Promise<T>;
    apiPut: <T = any>(path: string, body?: object) => Promise<T>;
}

const TablePrefsContext = createContext<TablePrefsTransport | null>(null);

/**
 * Supplies the API client to every {@link useTablePrefs} call below it. Mount once, at the app
 * root, alongside the other providers.
 */
export const TablePrefsProvider: React.FC<{
    transport: TablePrefsTransport;
    children: React.ReactNode;
}> = ({ transport, children }) => (
    <TablePrefsContext.Provider value={transport}>{children}</TablePrefsContext.Provider>
);

const LS_PREFIX = 'modca:pref:';

// Session-wide cache of the backend preferences map so N tables don't each hit the endpoint.
// Module-level, so it is per-bundle: each SPA gets its own, which is what we want.
let backendCache: Record<string, any> | null = null;
let backendPromise: Promise<Record<string, any>> | null = null;

function loadBackendPrefs(transport: TablePrefsTransport | null): Promise<Record<string, any>> {
    if (backendCache) return Promise.resolve(backendCache);
    // No provider — local-only mode. Resolve empty rather than throwing, so a table still renders
    // with its defaults instead of taking the page down over a stored column width.
    if (!transport) return Promise.resolve({});
    if (!backendPromise) {
        backendPromise = transport
            .apiGet<Record<string, any>>('/api/v1/me/preferences')
            .then((data) => { backendCache = data || {}; return backendCache; })
            .catch(() => { backendCache = {}; return backendCache!; });
    }
    return backendPromise;
}

/**
 * Reads/writes a single namespaced preference (e.g. "table:certificates").
 *
 * @param key      Stable, app-defined key. Use a "namespace:id" form.
 * @param defaults Shape returned before anything is stored; stored partials are shallow-merged
 *                 over it.
 */
export function useTablePrefs<T extends object>(key: string, defaults: T): [T, (next: T) => void] {
    const transport = useContext(TablePrefsContext);
    const lsKey = LS_PREFIX + key;

    const [value, setValue] = useState<T>(() => {
        try {
            const raw = localStorage.getItem(lsKey);
            if (raw) return { ...defaults, ...JSON.parse(raw) };
        } catch { /* ignore malformed local copy */ }
        return defaults;
    });

    // Whether this browser already had a stored copy (then local wins over backend hydrate).
    const hadLocal = useRef<boolean>(false);
    useEffect(() => {
        try { hadLocal.current = localStorage.getItem(lsKey) != null; } catch { /* ignore */ }
    }, [lsKey]);

    // One-time backend hydrate for browsers without a local copy.
    const hydrated = useRef(false);
    useEffect(() => {
        let cancelled = false;
        loadBackendPrefs(transport).then((all) => {
            if (cancelled || hydrated.current) return;
            hydrated.current = true;
            const remote = all[key];
            if (remote && !hadLocal.current) setValue({ ...defaults, ...remote });
        });
        return () => { cancelled = true; };
        // defaults intentionally excluded — it's a fresh object literal each render.
        // eslint-disable-next-line react-hooks/exhaustive-deps
    }, [key, transport]);

    const update = useCallback((next: T) => {
        setValue(next);
        try { localStorage.setItem(lsKey, JSON.stringify(next)); } catch { /* quota/private mode */ }
        hadLocal.current = true;
        if (backendCache) backendCache[key] = next;
        // Fire-and-forget cross-device sync; failure is non-fatal (localStorage still holds it).
        transport?.apiPut(`/api/v1/me/preferences/${encodeURIComponent(key)}`, next as object)
            .catch(() => { /* offline ok */ });
    }, [key, lsKey, transport]);

    return [value, update];
}
