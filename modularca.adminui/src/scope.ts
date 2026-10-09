import { can, canAnywhere, canInSpace, canOnCaInSpace, canSpaceWide, canUseSshTab, consoleCas, spacesOf, type EffectiveCapabilities } from './authz';
import type { Gate } from './gates';

/**
 * The console's CA scope: what the scoped tables list and what the scoped nav entries are
 * checked against.
 *
 * Four kinds of value. `all` is every CA the caller may see, offered only to callers with a
 * system-scoped capability. `space` is every CA of one space. `ca` is one CA, named by its label
 * (labels are unique across the instance), whether it belongs to a space or is an instance CA
 * (no space), which the switcher groups under "Instance". `mine` is the self-service view (my certificates,
 * my requests), which is what the `/user` portal is.
 *
 * The scope lives in the URL, as `?space=<slug>`, `?space=<slug>&ca=<label>`, `?ca=<label>`
 * (an instance CA) or `?scope=mine`, so a link carries its scope and reload and the back button keep it. The last
 * choice is also remembered per browser so a fresh navigation without a query string opens
 * where the user left off.
 */
export type Scope =
    | { kind: 'all' }
    | { kind: 'space'; spaceId: string; slug: string; name: string }
    | { kind: 'ca'; caId: string; label: string; spaceId: string | null; spaceSlug: string }
    | { kind: 'mine' };

export const ALL_SCOPE: Scope = { kind: 'all' };
export const MINE_SCOPE: Scope = { kind: 'mine' };

/** Query-string keys the scope is carried in. */
export const SCOPE_CA_PARAM = 'ca';
export const SCOPE_SPACE_PARAM = 'space';
export const SCOPE_KIND_PARAM = 'scope';

/** The key a space scope was carried in before 0.4.0. Remove in 0.5. */
export const LEGACY_SCOPE_SPACE_PARAM = 'tenant';

/** The CA scope for one administrable CA; an instance CA has a null space and an empty slug. */
export function caScope(ca: { id: string; label: string; spaceId: string | null; spaceSlug: string }): Scope {
    return { kind: 'ca', caId: ca.id, label: ca.label, spaceId: ca.spaceId ?? null, spaceSlug: ca.spaceId == null ? '' : ca.spaceSlug };
}

/**
 * The query string with a pre-0.4.0 `?tenant=<slug>` moved to `?space=<slug>`, or `null` when
 * it carries none. A `space` already present wins and the legacy key is dropped. Bookmarks and
 * stored scopes use it; remove in 0.5.
 */
export function rewriteLegacyScope(search: string | URLSearchParams): URLSearchParams | null {
    const params = new URLSearchParams(typeof search === 'string' ? search : search.toString());
    const legacy = params.get(LEGACY_SCOPE_SPACE_PARAM);
    if (legacy === null) return null;
    params.delete(LEGACY_SCOPE_SPACE_PARAM);
    if (!params.has(SCOPE_SPACE_PARAM)) params.set(SCOPE_SPACE_PARAM, legacy);
    return params;
}

/** Where a remembered scope lives: `localStorage` in the browser. */
export interface ScopeStorage {
    getItem(key: string): string | null;
    setItem(key: string, value: string): void;
}

/**
 * The scope remembered under `key`. One stored before 0.4.0 (`tenant=<slug>`) is translated to
 * `space=<slug>` and written back, so the translation happens once. Remove it in 0.5.
 */
export function readStoredScope(storage: ScopeStorage, key: string): string | null {
    const stored = storage.getItem(key);
    const rewritten = stored ? rewriteLegacyScope(stored) : null;
    if (!rewritten) return stored;
    storage.setItem(key, rewritten.toString());
    return rewritten.toString();
}

/**
 * Reads a scope from a query string. `?ca=<label>` wins when the label names a CA the caller
 * may scope to; labels are unique across the instance, so the label alone resolves it, and a
 * `?space=<slug>` beside it is optional but must be the CA's own. `?space=<slug>` alone is a
 * space scope; `?scope=mine` or `?scope=all` otherwise. Anything else (an unknown label or
 * slug, a CA the caller cannot see, a space that is not the CA's, nothing at all) is `null`,
 * so the caller falls back to a default.
 */
export function parseScope(search: string | URLSearchParams, caps: EffectiveCapabilities): Scope | null {
    const params = typeof search === 'string' ? new URLSearchParams(search) : search;
    const slug = params.get(SCOPE_SPACE_PARAM);
    const space = slug ? spacesOf(caps).find(s => s.slug === slug) ?? null : null;
    if (slug && !space) return null;
    const label = params.get(SCOPE_CA_PARAM);
    if (label) {
        const ca = consoleCas(caps).find(c => c.label === label);
        return ca && (!space || ca.spaceId === space.id) ? caScope(ca) : null;
    }
    if (space) return { kind: 'space', spaceId: space.id, slug: space.slug, name: space.name };
    const kind = params.get(SCOPE_KIND_PARAM);
    if (kind === 'mine') return MINE_SCOPE;
    if (kind === 'all') return canScopeToAll(caps) ? ALL_SCOPE : null;
    return null;
}

/** Writes a scope into a copy of the query string, replacing any scope already there. */
export function withScope(search: string | URLSearchParams, scope: Scope): URLSearchParams {
    const params = new URLSearchParams(typeof search === 'string' ? search : search.toString());
    params.delete(SCOPE_CA_PARAM);
    params.delete(SCOPE_SPACE_PARAM);
    params.delete(LEGACY_SCOPE_SPACE_PARAM);
    params.delete(SCOPE_KIND_PARAM);
    if (scope.kind === 'ca') {
        if (scope.spaceId != null) params.set(SCOPE_SPACE_PARAM, scope.spaceSlug);
        params.set(SCOPE_CA_PARAM, scope.label);
    } else if (scope.kind === 'space') {
        params.set(SCOPE_SPACE_PARAM, scope.slug);
    } else {
        params.set(SCOPE_KIND_PARAM, scope.kind);
    }
    return params;
}

/** "All CAs" is offered only to callers holding something at system scope. */
export function canScopeToAll(caps: EffectiveCapabilities): boolean {
    return caps.system.length > 0;
}

/**
 * Where the console opens when the URL carries no scope: "all CAs" for a system-scoped
 * caller; otherwise their space when everything they administer sits in one space;
 * otherwise the first CA they may scope to; otherwise (nothing to administer) the
 * self-service view.
 */
export function defaultScope(caps: EffectiveCapabilities): Scope {
    if (canScopeToAll(caps)) return ALL_SCOPE;
    const spaces = spacesOf(caps);
    if (spaces.length === 1) return { kind: 'space', spaceId: spaces[0].id, slug: spaces[0].slug, name: spaces[0].name };
    const first = consoleCas(caps)[0];
    if (first) return caScope(first);
    return MINE_SCOPE;
}

/** The space id a scope is confined to, or `null` when it spans spaces or is an instance CA. */
export function scopeSpaceId(scope: Scope): string | null {
    return scope.kind === 'space' ? scope.spaceId : scope.kind === 'ca' ? scope.spaceId : null;
}

/** The CA id to send as a `caId` filter for this scope, or `null` for no filter. */
export function scopeCaId(scope: Scope): string | null {
    return scope.kind === 'ca' ? scope.caId : null;
}

/** A short label for the scope, for the switcher and page headers. */
export function scopeLabel(scope: Scope): string {
    switch (scope.kind) {
        case 'all': return 'All CAs';
        case 'mine': return 'Mine';
        case 'space': return scope.name;
        case 'ca': return scope.label;
    }
}

/** Two scopes are the same when they name the same thing. */
export function sameScope(a: Scope, b: Scope): boolean {
    if (a.kind !== b.kind) return false;
    if (a.kind === 'ca' && b.kind === 'ca') return a.caId === b.caId;
    if (a.kind === 'space' && b.kind === 'space') return a.spaceId === b.spaceId;
    return true;
}

/**
 * Whether `gate` admits the caller under `scope`, as the server would answer the page's calls.
 * An unscoped gate is checked at system scope, a scoped one on the selected CA. Across a space or
 * all CAs a scoped gate needs the capability on a CA there or at system scope, since the CA-scoped
 * list endpoints refuse a route naming no CA otherwise; a `spaceWide` gate also admits a
 * space-wide grant over a space with no CA yet. A gate with an `ssh` tab also admits, under any
 * console scope, whoever can use that tab.
 */
export function gateAllows(caps: EffectiveCapabilities, gate: Gate | undefined, scope: Scope): boolean {
    if (!gate) return true;
    if (gate.ssh && scope.kind !== 'mine' && canUseSshTab(caps, gate.ssh)) return true;
    const capability = gate.requires;
    if (!gate.scoped) return can(caps, capability);
    switch (scope.kind) {
        case 'ca': return can(caps, capability, scope.caId);
        case 'space': return gate.spaceWide ? canInSpace(caps, capability, scope.spaceId) : canOnCaInSpace(caps, capability, scope.spaceId);
        case 'all': return canAnywhere(caps, capability) || (!!gate.spaceWide && canSpaceWide(caps, capability));
        case 'mine': return false;
    }
}
