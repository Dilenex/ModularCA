import { consoleCas, type EffectiveCapabilities } from './authz';

/**
 * The console's CA scope: what the scoped tables list and what the scoped nav entries are
 * checked against.
 *
 * Three kinds of value. `all` is every CA the caller may see, offered only to callers with a
 * system-scoped capability. `ca` is one CA, named by label. `mine` is the self-service view
 * (my certificates, my requests), which is what the `/user` portal is.
 *
 * The scope lives in the URL, as `?ca=<label>` or `?scope=mine`, so a link carries its scope
 * and reload and the back button keep it. The last choice is also remembered per browser so a
 * fresh navigation without a query string opens where the user left off.
 */
export type Scope =
    | { kind: 'all' }
    | { kind: 'ca'; caId: string; label: string }
    | { kind: 'mine' };

export const ALL_SCOPE: Scope = { kind: 'all' };
export const MINE_SCOPE: Scope = { kind: 'mine' };

/** Query-string keys the scope is carried in. */
export const SCOPE_CA_PARAM = 'ca';
export const SCOPE_KIND_PARAM = 'scope';

/**
 * Reads a scope from a query string. `?ca=<label>` wins when the label names a CA the caller
 * may scope to; `?scope=mine` or `?scope=all` otherwise. Anything else (an unknown label, a
 * CA the caller cannot see, nothing at all) is `null`, so the caller falls back to a default.
 */
export function parseScope(search: string | URLSearchParams, caps: EffectiveCapabilities): Scope | null {
    const params = typeof search === 'string' ? new URLSearchParams(search) : search;
    const label = params.get(SCOPE_CA_PARAM);
    if (label) {
        const ca = consoleCas(caps).find(c => c.label === label);
        return ca ? { kind: 'ca', caId: ca.id, label: ca.label } : null;
    }
    const kind = params.get(SCOPE_KIND_PARAM);
    if (kind === 'mine') return MINE_SCOPE;
    if (kind === 'all') return canScopeToAll(caps) ? ALL_SCOPE : null;
    return null;
}

/** Writes a scope into a copy of the query string, replacing any scope already there. */
export function withScope(search: string | URLSearchParams, scope: Scope): URLSearchParams {
    const params = new URLSearchParams(typeof search === 'string' ? search : search.toString());
    params.delete(SCOPE_CA_PARAM);
    params.delete(SCOPE_KIND_PARAM);
    if (scope.kind === 'ca') params.set(SCOPE_CA_PARAM, scope.label);
    else params.set(SCOPE_KIND_PARAM, scope.kind);
    return params;
}

/** "All CAs" is offered only to callers holding something at system scope. */
export function canScopeToAll(caps: EffectiveCapabilities): boolean {
    return caps.system.length > 0;
}

/**
 * Where the console opens when the URL carries no scope: "all CAs" for a system-scoped
 * caller, otherwise the first CA they may scope to, otherwise (nothing to administer) the
 * self-service view.
 */
export function defaultScope(caps: EffectiveCapabilities): Scope {
    if (canScopeToAll(caps)) return ALL_SCOPE;
    const first = consoleCas(caps)[0];
    if (first) return { kind: 'ca', caId: first.id, label: first.label };
    return MINE_SCOPE;
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
        case 'ca': return scope.label;
    }
}

/** Two scopes are the same when they name the same thing. */
export function sameScope(a: Scope, b: Scope): boolean {
    if (a.kind !== b.kind) return false;
    return a.kind !== 'ca' || b.kind !== 'ca' || a.caId === b.caId;
}
