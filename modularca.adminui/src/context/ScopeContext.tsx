import React, { createContext, useCallback, useContext, useEffect, useMemo } from 'react';
import { useSearchParams } from 'react-router-dom';
import type { Capability } from '@shared/generated';
import { useAuth } from './AuthContext';
import { can, canAnywhere, consoleCas, type CaCapabilities } from '../authz';
import {
    ALL_SCOPE, MINE_SCOPE, canScopeToAll, defaultScope, parseScope, sameScope, scopeCaId, withScope, type Scope,
} from '../scope';
import type { Gate } from '../gates';
import { PORTAL } from '../portal';

/**
 * The console's selected CA scope and the checks that depend on it.
 *
 * The scope is read from the URL (`?ca=<label>` / `?scope=…`), then from the browser's
 * remembered choice, then from a default derived from the caller's capabilities. Changing it
 * writes the URL and the remembered choice. Under the `/user` portal the scope is always
 * `mine`; the switcher there offers the way over to the console.
 */
export interface ScopeContextValue {
    scope: Scope;
    setScope: (scope: Scope) => void;
    /** The `caId` to send with scoped list queries, or `null` for no filter. */
    caId: string | null;
    /** Whether a row belonging to `rowCaId` is inside the scope (everything is, under "all"). */
    inScope: (rowCaId: string | null | undefined) => boolean;
    /** `?caId=…` (or `&caId=…` when `hasQuery`) for the scope, or an empty string. */
    caQuery: (hasQuery?: boolean) => string;
    /** The CAs the caller may scope to. */
    cas: CaCapabilities[];
    /** Whether "all CAs" is an offered scope. */
    canScopeToAll: boolean;
    /**
     * Whether the caller passes a gate under the current scope: a scoped gate is checked on
     * the selected CA (or anywhere, under "all CAs"); an unscoped one at system scope.
     */
    allows: (gate: Gate | undefined) => boolean;
}

const ScopeContext = createContext<ScopeContextValue>({
    scope: ALL_SCOPE,
    setScope: () => { },
    caId: null,
    inScope: () => true,
    caQuery: () => '',
    cas: [],
    canScopeToAll: false,
    allows: () => false,
});

export const useScope = () => useContext(ScopeContext);

const storageKey = (username: string) => `modca:scope:${username}`;

function readStored(username: string): string | null {
    try { return localStorage.getItem(storageKey(username)); } catch { return null; }
}

function writeStored(username: string, params: URLSearchParams): void {
    try { localStorage.setItem(storageKey(username), params.toString()); } catch { /* private mode / quota */ }
}

export const ScopeProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
    const { user, capabilities, loading } = useAuth();
    const [searchParams, setSearchParams] = useSearchParams();
    const username = user?.username ?? '';

    const scope = useMemo<Scope>(() => {
        if (PORTAL === 'user') return MINE_SCOPE;
        const fromUrl = parseScope(searchParams, capabilities);
        if (fromUrl) return fromUrl;
        const stored = username ? readStored(username) : null;
        const remembered = stored ? parseScope(stored, capabilities) : null;
        return remembered ?? defaultScope(capabilities);
    }, [searchParams, capabilities, username]);

    // Remember a scope that arrived by URL, so the next plain navigation keeps it.
    useEffect(() => {
        if (loading || !username || PORTAL === 'user') return;
        if (parseScope(searchParams, capabilities)) writeStored(username, withScope('', scope));
    }, [loading, username, searchParams, capabilities, scope]);

    const setScope = useCallback((next: Scope) => {
        if (sameScope(next, scope)) return;
        if (username) writeStored(username, withScope('', next));
        setSearchParams(withScope(searchParams, next), { replace: true });
    }, [scope, username, searchParams, setSearchParams]);

    const allows = useCallback((gate: Gate | undefined): boolean => {
        if (!gate) return true;
        const capability: Capability = gate.requires;
        if (!gate.scoped) return can(capabilities, capability);
        switch (scope.kind) {
            case 'ca': return can(capabilities, capability, scope.caId);
            case 'all': return canAnywhere(capabilities, capability);
            case 'mine': return false;
        }
    }, [capabilities, scope]);

    const caId = scopeCaId(scope);
    const inScope = useCallback((rowCaId: string | null | undefined) => !caId || rowCaId === caId, [caId]);
    const caQuery = useCallback((hasQuery = false) => caId ? `${hasQuery ? '&' : '?'}caId=${encodeURIComponent(caId)}` : '', [caId]);

    const value = useMemo<ScopeContextValue>(() => ({
        scope,
        setScope,
        caId,
        inScope,
        caQuery,
        cas: consoleCas(capabilities),
        canScopeToAll: canScopeToAll(capabilities),
        allows,
    }), [scope, setScope, caId, inScope, caQuery, capabilities, allows]);

    return <ScopeContext.Provider value={value}>{children}</ScopeContext.Provider>;
};
