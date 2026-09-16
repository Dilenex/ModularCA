import { describe, expect, it } from 'vitest';
import { Capabilities } from '@shared/generated';
import type { EffectiveCapabilities } from '@adminui/authz';
import {
    ALL_SCOPE, MINE_SCOPE, canScopeToAll, caScope, defaultScope, parseScope, sameScope, scopeCaId, scopeLabel, scopeTenantId, withScope,
} from '@adminui/scope';

/**
 * The console's CA scope as it travels in the URL. A link must carry its scope, an unknown or
 * inaccessible CA in the URL must fall back rather than scope to nothing, and "all CAs" must
 * only be offered to callers holding something at system scope.
 */
const caA = { id: 'a', label: 'ca-a', name: 'A', isSshCa: false, tenantId: 't1', tenantName: 'Tenant One', tenantSlug: 'one', capabilities: [Capabilities.CaManage] };
const caB = { id: 'b', label: 'ca-b', name: 'B', isSshCa: false, tenantId: 't1', tenantName: 'Tenant One', tenantSlug: 'one', capabilities: [Capabilities.CertRequest] };
const caC = { id: 'c', label: 'ca-a', name: 'C', isSshCa: false, tenantId: 't2', tenantName: 'Tenant Two', tenantSlug: 'two', capabilities: [Capabilities.CaManage] };
const scopeA = { kind: 'ca' as const, caId: 'a', label: 'ca-a', tenantId: 't1', tenantSlug: 'one' };
const tenantOne = { kind: 'tenant' as const, tenantId: 't1', slug: 'one', name: 'Tenant One' };

const operator: EffectiveCapabilities = { system: [], cas: [caA, caB] };
const systemAdmin: EffectiveCapabilities = { system: [Capabilities.SystemManage], cas: [caA] };
const requester: EffectiveCapabilities = { system: [], cas: [caB] };

describe('parseScope', () => {
    it('reads ?ca=<label> for a CA the caller may administer', () => {
        expect(parseScope('?ca=ca-a', operator)).toEqual(scopeA);
        expect(parseScope(new URLSearchParams('ca=ca-a&page=2'), operator)).toEqual(scopeA);
    });

    it('rejects a CA the caller only requests on, and an unknown label', () => {
        expect(parseScope('?ca=ca-b', operator)).toBeNull();
        expect(parseScope('?ca=zzz', operator)).toBeNull();
    });

    it('reads ?scope=mine for anyone and ?scope=all only for system-scoped callers', () => {
        expect(parseScope('?scope=mine', requester)).toEqual(MINE_SCOPE);
        expect(parseScope('?scope=all', systemAdmin)).toEqual(ALL_SCOPE);
        expect(parseScope('?scope=all', operator)).toBeNull();
        expect(parseScope('?scope=bogus', systemAdmin)).toBeNull();
        expect(parseScope('', systemAdmin)).toBeNull();
    });

    it('prefers a CA label over a scope kind when both are present', () => {
        expect(parseScope('?scope=all&ca=ca-a', systemAdmin)).toEqual(scopeA);
    });
});

describe('withScope', () => {
    it('writes the scope and replaces whatever scope was there, keeping other parameters', () => {
        expect(withScope('?scope=all&page=3', scopeA).toString()).toBe('page=3&tenant=one&ca=ca-a');
        expect(withScope('?ca=ca-a', ALL_SCOPE).toString()).toBe('scope=all');
        expect(withScope('', MINE_SCOPE).toString()).toBe('scope=mine');
    });

    it('round-trips through parseScope', () => {
        const scope = scopeA;
        expect(parseScope(withScope('', scope), operator)).toEqual(scope);
    });
});

describe('defaultScope', () => {
    it('is all CAs for a system-scoped caller', () => {
        expect(canScopeToAll(systemAdmin)).toBe(true);
        expect(defaultScope(systemAdmin)).toEqual(ALL_SCOPE);
    });

    it('is the tenant when everything administrable sits in one, the first CA across tenants, and mine when there is none', () => {
        expect(canScopeToAll(operator)).toBe(false);
        expect(defaultScope(operator)).toEqual(tenantOne);
        expect(defaultScope({ system: [], cas: [caA, caC] })).toEqual(scopeA);
        expect(defaultScope(requester)).toEqual(MINE_SCOPE);
    });
});

describe('scope helpers', () => {
    it('yield a caId filter only for a single-CA scope', () => {
        expect(scopeCaId(scopeA)).toBe('a');
        expect(scopeCaId(ALL_SCOPE)).toBeNull();
        expect(scopeCaId(MINE_SCOPE)).toBeNull();
    });

    it('label and compare scopes by what they name', () => {
        expect(scopeLabel(ALL_SCOPE)).toBe('All CAs');
        expect(scopeLabel(MINE_SCOPE)).toBe('Mine');
        expect(scopeLabel(scopeA)).toBe('ca-a');
        expect(sameScope({ ...scopeA, label: 'x' }, { ...scopeA, label: 'y' })).toBe(true);
        expect(sameScope(scopeA, { ...scopeA, caId: 'b' })).toBe(false);
        expect(sameScope(tenantOne, { ...tenantOne, name: 'renamed' })).toBe(true);
        expect(sameScope(tenantOne, { ...tenantOne, tenantId: 't2' })).toBe(false);
        expect(sameScope(ALL_SCOPE, MINE_SCOPE)).toBe(false);
        expect(sameScope(MINE_SCOPE, { kind: 'mine' })).toBe(true);
    });
});

describe('tenant scope', () => {
    const twoTenants: EffectiveCapabilities = { system: [], cas: [caA, caC] };

    it('reads ?tenant=<slug> for a tenant the caller administers something in', () => {
        expect(parseScope('?tenant=one', twoTenants)).toEqual(tenantOne);
        expect(parseScope('?tenant=nope', twoTenants)).toBeNull();
        expect(parseScope('?tenant=one', requester)).toBeNull(); // requester-only in that tenant
    });

    it('resolves a CA label within the named tenant, since labels repeat across tenants', () => {
        expect(parseScope('?tenant=two&ca=ca-a', twoTenants)).toEqual(caScope(caC));
        expect(parseScope('?tenant=one&ca=ca-a', twoTenants)).toEqual(scopeA);
        expect(parseScope('?ca=ca-a', twoTenants)).toEqual(scopeA); // no tenant: first match
        expect(parseScope('?tenant=two&ca=zzz', twoTenants)).toBeNull();
    });

    it('writes the tenant into the URL and round-trips', () => {
        expect(withScope('?page=2', tenantOne).toString()).toBe('page=2&tenant=one');
        expect(parseScope(withScope('', tenantOne), twoTenants)).toEqual(tenantOne);
        expect(parseScope(withScope('', caScope(caC)), twoTenants)).toEqual(caScope(caC));
    });

    it('names the tenant a scope is confined to', () => {
        expect(scopeTenantId(tenantOne)).toBe('t1');
        expect(scopeTenantId(caScope(caC))).toBe('t2');
        expect(scopeTenantId(ALL_SCOPE)).toBeNull();
        expect(scopeLabel(tenantOne)).toBe('Tenant One');
    });
});
