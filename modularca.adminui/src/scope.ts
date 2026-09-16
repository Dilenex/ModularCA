import { consoleCas, tenantsOf, type EffectiveCapabilities } from './authz';

/**
 * The console's CA scope: what the scoped tables list and what the scoped nav entries are
 * checked against.
 *
 * Four kinds of value. `all` is every CA the caller may see, offered only to callers with a
 * system-scoped capability. `tenant` is every CA of one tenant. `ca` is one CA, named by label
 * within its tenant (labels are unique per tenant, not globally). `mine` is the self-service
 * view (my certificates, my requests), which is what the `/user` portal is.
 *
 * The scope lives in the URL, as `?tenant=<slug>`, `?tenant=<slug>&ca=<label>` or
 * `?scope=mine`, so a link carries its scope and reload and the back button keep it. The last
 * choice is also remembered per browser so a fresh navigation without a query string opens
 * where the user left off.
 */
export type Scope =
    | { kind: 'all' }
    | { kind: 'tenant'; tenantId: string; slug: string; name: string }
    | { kind: 'ca'; caId: string; label: string; tenantId: string; tenantSlug: string }
    | { kind: 'mine' };

export const ALL_SCOPE: Scope = { kind: 'all' };
export const MINE_SCOPE: Scope = { kind: 'mine' };

/** Query-string keys the scope is carried in. */
export const SCOPE_CA_PARAM = 'ca';
export const SCOPE_TENANT_PARAM = 'tenant';
export const SCOPE_KIND_PARAM = 'scope';

/** The CA scope for one administrable CA. */
export function caScope(ca: { id: string; label: string; tenantId: string; tenantSlug: string }): Scope {
    return { kind: 'ca', caId: ca.id, label: ca.label, tenantId: ca.tenantId, tenantSlug: ca.tenantSlug };
}

/**
 * Reads a scope from a query string. `?ca=<label>` wins when the label names a CA the caller
 * may scope to (within `?tenant=<slug>` when given, since labels repeat across tenants);
 * `?tenant=<slug>` alone is a tenant scope; `?scope=mine` or `?scope=all` otherwise. Anything
 * else (an unknown label or slug, a CA the caller cannot see, nothing at all) is `null`, so
 * the caller falls back to a default.
 */
export function parseScope(search: string | URLSearchParams, caps: EffectiveCapabilities): Scope | null {
    const params = typeof search === 'string' ? new URLSearchParams(search) : search;
    const slug = params.get(SCOPE_TENANT_PARAM);
    const tenant = slug ? tenantsOf(caps).find(t => t.slug === slug) ?? null : null;
    if (slug && !tenant) return null;
    const label = params.get(SCOPE_CA_PARAM);
    if (label) {
        const ca = consoleCas(caps).find(c => c.label === label && (!tenant || c.tenantId === tenant.id));
        return ca ? caScope(ca) : null;
    }
    if (tenant) return { kind: 'tenant', tenantId: tenant.id, slug: tenant.slug, name: tenant.name };
    const kind = params.get(SCOPE_KIND_PARAM);
    if (kind === 'mine') return MINE_SCOPE;
    if (kind === 'all') return canScopeToAll(caps) ? ALL_SCOPE : null;
    return null;
}

/** Writes a scope into a copy of the query string, replacing any scope already there. */
export function withScope(search: string | URLSearchParams, scope: Scope): URLSearchParams {
    const params = new URLSearchParams(typeof search === 'string' ? search : search.toString());
    params.delete(SCOPE_CA_PARAM);
    params.delete(SCOPE_TENANT_PARAM);
    params.delete(SCOPE_KIND_PARAM);
    if (scope.kind === 'ca') {
        params.set(SCOPE_TENANT_PARAM, scope.tenantSlug);
        params.set(SCOPE_CA_PARAM, scope.label);
    } else if (scope.kind === 'tenant') {
        params.set(SCOPE_TENANT_PARAM, scope.slug);
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
 * caller; otherwise their tenant when everything they administer sits in one tenant;
 * otherwise the first CA they may scope to; otherwise (nothing to administer) the
 * self-service view.
 */
export function defaultScope(caps: EffectiveCapabilities): Scope {
    if (canScopeToAll(caps)) return ALL_SCOPE;
    const tenants = tenantsOf(caps);
    if (tenants.length === 1) return { kind: 'tenant', tenantId: tenants[0].id, slug: tenants[0].slug, name: tenants[0].name };
    const first = consoleCas(caps)[0];
    if (first) return caScope(first);
    return MINE_SCOPE;
}

/** The tenant id a scope is confined to, or `null` when it spans tenants. */
export function scopeTenantId(scope: Scope): string | null {
    return scope.kind === 'tenant' ? scope.tenantId : scope.kind === 'ca' ? scope.tenantId : null;
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
        case 'tenant': return scope.name;
        case 'ca': return scope.label;
    }
}

/** Two scopes are the same when they name the same thing. */
export function sameScope(a: Scope, b: Scope): boolean {
    if (a.kind !== b.kind) return false;
    if (a.kind === 'ca' && b.kind === 'ca') return a.caId === b.caId;
    if (a.kind === 'tenant' && b.kind === 'tenant') return a.tenantId === b.tenantId;
    return true;
}
