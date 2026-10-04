import React, { createContext, useCallback, useContext, useEffect, useMemo, useState } from 'react';
import { useSearchParams } from 'react-router-dom';
import { useAuth } from './AuthContext';
import { consoleCas, spacesOf, type CaCapabilities, type SpaceOption } from '../authz';
import {
    ALL_SCOPE, MINE_SCOPE, canScopeToAll, defaultScope, gateAllows, parseScope, readStoredScope, rewriteLegacyScope, sameScope, scopeCaId, withScope, type Scope,
} from '../scope';
import type { Gate } from '../gates';
import { PORTAL } from '../portal';

/**
 * The console's selected CA scope and the checks that depend on it.
 *
 * The scope is read from the URL (`?ca=<label>` / `?space=<slug>` / `?scope=…`), then from the
 * browser's remembered choice, then from a default derived from the caller's capabilities.
 * Changing it writes the URL and the remembered choice. Under the `/user` portal the scope is
 * always `mine`; the switcher there offers the way over to the console. A pre-0.4.0
 * `?tenant=<slug>`, in the URL or remembered, is rewritten to `?space=<slug>`.
 */
export interface ScopeContextValue {
    scope: Scope;
    setScope: (scope: Scope) => void;
    /** The `caId` to send with scoped list queries, or `null` for no single-CA filter. */
    caId: string | null;
    /** The `spaceId` a space scope is confined to, or `null`. */
    spaceId: string | null;
    /** Whether a row belonging to `rowCaId` is inside the scope: the CA, any CA of the space, or everything under "all". */
    inScope: (rowCaId: string | null | undefined) => boolean;
    /** `?caId=…` / `?spaceId=…` (with `&` when `hasQuery`) for the scope, or an empty string. */
    caQuery: (hasQuery?: boolean) => string;
    /** The CAs the caller may scope to. */
    cas: CaCapabilities[];
    /** The spaces the caller may scope to. */
    spaces: SpaceOption[];
    /** Whether "all CAs" is an offered scope. */
    canScopeToAll: boolean;
    /**
     * Whether the caller passes a gate under the current scope: a scoped gate is checked on
     * the selected CA (or anywhere, under "all CAs"); an unscoped one at system scope.
     */
    allows: (gate: Gate | undefined) => boolean;
    /**
     * Set while the URL names a scope other than the one the user usually works in. A link
     * can carry any scope; following it must not silently move the user, so the shell shows
     * where they are and offers the way back. `keep` adopts the link's scope as the usual one;
     * `leave` returns to the usual scope on the current page.
     */
    linkScope: { usual: Scope; keep: () => void; leave: () => void } | null;
}

const ScopeContext = createContext<ScopeContextValue>({
    scope: ALL_SCOPE,
    setScope: () => { },
    caId: null,
    spaceId: null,
    inScope: () => true,
    caQuery: () => '',
    cas: [],
    spaces: [],
    canScopeToAll: false,
    allows: () => false,
    linkScope: null,
});

export const useScope = () => useContext(ScopeContext);

const storageKey = (username: string) => `modca:scope:${username}`;

function readStored(username: string): string | null {
    try { return readStoredScope(localStorage, storageKey(username)); } catch { return null; }
}

function writeStored(username: string, params: URLSearchParams): void {
    try { localStorage.setItem(storageKey(username), params.toString()); } catch { /* private mode / quota */ }
}

export const ScopeProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
    const { user, capabilities, loading } = useAuth();
    const [rawSearchParams, setSearchParams] = useSearchParams();
    const username = user?.username ?? '';

    // A bookmark from before 0.4.0 says ?tenant=<slug>. Read it as ?space= now and rewrite the
    // URL in place, so history keeps one entry. Remove in 0.5.
    const legacy = useMemo(() => rewriteLegacyScope(rawSearchParams), [rawSearchParams]);
    const searchParams = legacy ?? rawSearchParams;
    useEffect(() => {
        if (legacy) setSearchParams(legacy, { replace: true });
    }, [legacy, setSearchParams]);

    // The scope the user usually works in: their last explicit choice, else a default from
    // their capabilities. A scope named in the URL applies to this visit only; it is never
    // written to storage on its own, so a link cannot quietly move someone's usual scope.
    // Bumped on every write to storage so `usual` re-reads it.
    const [storeVersion, setStoreVersion] = useState(0);
    const usual = useMemo<Scope>(() => {
        const stored = username ? readStored(username) : null;
        const remembered = stored ? parseScope(stored, capabilities) : null;
        return remembered ?? defaultScope(capabilities);
        // eslint-disable-next-line react-hooks/exhaustive-deps
    }, [capabilities, username, storeVersion]);

    const fromUrl = useMemo<Scope | null>(() => {
        if (PORTAL !== 'admin') return null;
        const parsed = parseScope(searchParams, capabilities);
        // "Mine" is the self-service portal, not a console scope; a link naming it is ignored here.
        return parsed && parsed.kind !== 'mine' ? parsed : null;
    }, [searchParams, capabilities]);

    const scope = useMemo<Scope>(() => {
        if (PORTAL === 'user') return MINE_SCOPE;
        return fromUrl ?? usual;
    }, [fromUrl, usual]);

    const setScope = useCallback((next: Scope) => {
        if (sameScope(next, scope)) return;
        if (username) { writeStored(username, withScope('', next)); setStoreVersion(v => v + 1); }
        setSearchParams(withScope(searchParams, next), { replace: true });
    }, [scope, username, searchParams, setSearchParams]);

    const linkScope = useMemo(() => {
        if (loading || !fromUrl || sameScope(fromUrl, usual)) return null;
        return {
            usual,
            keep: () => { if (username) { writeStored(username, withScope('', fromUrl)); setStoreVersion(v => v + 1); } },
            leave: () => setSearchParams(withScope(searchParams, usual), { replace: true }),
        };
    }, [loading, fromUrl, usual, username, searchParams, setSearchParams]);

    const allows = useCallback((gate: Gate | undefined): boolean => gateAllows(capabilities, gate, scope), [capabilities, scope]);

    const caId = scopeCaId(scope);
    const spaceId = scope.kind === 'space' ? scope.spaceId : null;
    // The CAs a space scope covers: the ones the caller can administer in that space.
    const spaceCaIds = useMemo(() => new Set(scope.kind === 'space' ? consoleCas(capabilities).filter(c => c.spaceId === scope.spaceId).map(c => c.id) : []), [scope, capabilities]);
    const inScope = useCallback((rowCaId: string | null | undefined) => {
        if (caId) return rowCaId === caId;
        if (spaceId) return !!rowCaId && spaceCaIds.has(rowCaId);
        return true;
    }, [caId, spaceId, spaceCaIds]);
    const caQuery = useCallback((hasQuery = false) => {
        const sep = hasQuery ? '&' : '?';
        if (caId) return `${sep}caId=${encodeURIComponent(caId)}`;
        if (spaceId) return `${sep}spaceId=${encodeURIComponent(spaceId)}`;
        return '';
    }, [caId, spaceId]);

    const value = useMemo<ScopeContextValue>(() => ({
        scope,
        setScope,
        caId,
        spaceId,
        inScope,
        caQuery,
        cas: consoleCas(capabilities),
        spaces: spacesOf(capabilities),
        canScopeToAll: canScopeToAll(capabilities),
        allows,
        linkScope,
    }), [scope, setScope, caId, spaceId, inScope, caQuery, capabilities, allows, linkScope]);

    return <ScopeContext.Provider value={value}>{children}</ScopeContext.Provider>;
};
