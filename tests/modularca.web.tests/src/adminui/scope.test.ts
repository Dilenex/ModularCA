import { describe, expect, it } from 'vitest';
import { Capabilities } from '@shared/generated';
import type { EffectiveCapabilities } from '@adminui/authz';
import {
    ALL_SCOPE, MINE_SCOPE, canScopeToAll, caScope, defaultScope, parseScope, readStoredScope, rewriteLegacyScope, sameScope, scopeCaId, scopeLabel, scopeSpaceId, withScope,
    type ScopeStorage,
} from '@adminui/scope';

/**
 * The console's CA scope as it travels in the URL. A link must carry its scope, an unknown or
 * inaccessible CA in the URL must fall back rather than scope to nothing, and "all CAs" must
 * only be offered to callers holding something at system scope.
 */
const caA = { id: 'a', label: 'ca-a', name: 'A', isSshCa: false, spaceId: 't1', spaceName: 'Space One', spaceSlug: 'one', capabilities: [Capabilities.CaManage] };
const caB = { id: 'b', label: 'ca-b', name: 'B', isSshCa: false, spaceId: 't1', spaceName: 'Space One', spaceSlug: 'one', capabilities: [Capabilities.CertRequest] };
const caC = { id: 'c', label: 'ca-c', name: 'C', isSshCa: false, spaceId: 't2', spaceName: 'Space Two', spaceSlug: 'two', capabilities: [Capabilities.CaManage] };
const scopeA = { kind: 'ca' as const, caId: 'a', label: 'ca-a', spaceId: 't1', spaceSlug: 'one' };
const spaceOne = { kind: 'space' as const, spaceId: 't1', slug: 'one', name: 'Space One' };

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
        expect(withScope('?scope=all&page=3', scopeA).toString()).toBe('page=3&space=one&ca=ca-a');
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

    it('is the space when everything administrable sits in one, the first CA across spaces, and mine when there is none', () => {
        expect(canScopeToAll(operator)).toBe(false);
        expect(defaultScope(operator)).toEqual(spaceOne);
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
        expect(sameScope(spaceOne, { ...spaceOne, name: 'renamed' })).toBe(true);
        expect(sameScope(spaceOne, { ...spaceOne, spaceId: 't2' })).toBe(false);
        expect(sameScope(ALL_SCOPE, MINE_SCOPE)).toBe(false);
        expect(sameScope(MINE_SCOPE, { kind: 'mine' })).toBe(true);
    });
});

describe('space scope', () => {
    const twoSpaces: EffectiveCapabilities = { system: [], cas: [caA, caC] };

    it('reads ?space=<slug> for a space the caller administers something in', () => {
        expect(parseScope('?space=one', twoSpaces)).toEqual(spaceOne);
        expect(parseScope('?space=nope', twoSpaces)).toBeNull();
        expect(parseScope('?space=one', requester)).toBeNull(); // requester-only in that space
    });

    it('resolves a CA label alone, since labels are unique across the instance; a space beside it must be its own', () => {
        expect(parseScope('?ca=ca-c', twoSpaces)).toEqual(caScope(caC));
        expect(parseScope('?space=two&ca=ca-c', twoSpaces)).toEqual(caScope(caC));
        expect(parseScope('?space=one&ca=ca-a', twoSpaces)).toEqual(scopeA);
        expect(parseScope('?space=one&ca=ca-c', twoSpaces)).toBeNull();
        expect(parseScope('?space=two&ca=zzz', twoSpaces)).toBeNull();
    });

    it('writes the space into the URL and round-trips', () => {
        expect(withScope('?page=2', spaceOne).toString()).toBe('page=2&space=one');
        expect(parseScope(withScope('', spaceOne), twoSpaces)).toEqual(spaceOne);
        expect(parseScope(withScope('', caScope(caC)), twoSpaces)).toEqual(caScope(caC));
    });

    it('names the space a scope is confined to', () => {
        expect(scopeSpaceId(spaceOne)).toBe('t1');
        expect(scopeSpaceId(caScope(caC))).toBe('t2');
        expect(scopeSpaceId(ALL_SCOPE)).toBeNull();
        expect(scopeLabel(spaceOne)).toBe('Space One');
    });
});

describe('instance CA scope (no space)', () => {
    const signing = { id: 'sys', label: 'system-signing-ca', name: 'System Signing CA', isSshCa: false, spaceId: null, spaceName: '', spaceSlug: '', capabilities: [Capabilities.CaManage] };
    const caps: EffectiveCapabilities = { system: [], cas: [caC, signing, caA] };
    const instanceScope = { kind: 'ca' as const, caId: 'sys', label: 'system-signing-ca', spaceId: null, spaceSlug: '' };

    it('has a null space and no slug', () => {
        expect(caScope(signing)).toEqual(instanceScope);
        expect(scopeSpaceId(caScope(signing))).toBeNull();
        expect(scopeCaId(caScope(signing))).toBe('sys');
    });

    it('is written as ?ca=<label> with no space, and read back', () => {
        expect(withScope('?page=2', instanceScope).toString()).toBe('page=2&ca=system-signing-ca');
        expect(parseScope(withScope('', instanceScope), caps)).toEqual(instanceScope);
    });

    it('resolves a bare ?ca=<label>, and refuses a space beside it, which an instance CA has none of', () => {
        expect(parseScope('?ca=system-signing-ca', caps)).toEqual(instanceScope);
        expect(parseScope('?space=two&ca=system-signing-ca', caps)).toBeNull();
    });

    it('does not make the instance a space scope', () => {
        expect(defaultScope({ system: [], cas: [signing] })).toEqual(instanceScope);
        expect(parseScope('?space=', caps)).toBeNull();
    });
});

/**
 * Bookmarks and remembered scopes from before 0.4.0 say `tenant=<slug>`. They are read as
 * `space=<slug>` for one release, and the URL and the stored value are rewritten once.
 */
describe('the pre-0.4.0 ?tenant= scope', () => {
    const twoSpaces: EffectiveCapabilities = { system: [], cas: [caA, caC] };

    it('is rewritten to ?space=, keeping every other parameter', () => {
        expect(rewriteLegacyScope('?tenant=one&page=2')!.toString()).toBe('page=2&space=one');
        expect(rewriteLegacyScope('?tenant=one&ca=ca-a')!.toString()).toBe('ca=ca-a&space=one');
        expect(parseScope(rewriteLegacyScope('?tenant=one')!, twoSpaces)).toEqual(spaceOne);
    });

    it('leaves a query string without it alone, and lets a ?space= already there win', () => {
        expect(rewriteLegacyScope('?space=one&page=2')).toBeNull();
        expect(rewriteLegacyScope('')).toBeNull();
        expect(rewriteLegacyScope('?space=two&tenant=one')!.toString()).toBe('space=two');
    });

    it('is not read as a scope by itself, and is dropped when a scope is written', () => {
        expect(parseScope('?tenant=one', twoSpaces)).toBeNull();
        expect(withScope('?tenant=one&page=2', spaceOne).toString()).toBe('page=2&space=one');
    });

    it('is translated in storage once, on load', () => {
        const store = new Map<string, string>([['modca:scope:alice', 'tenant=one']]);
        const writes: string[] = [];
        const storage: ScopeStorage = {
            getItem: (k) => store.get(k) ?? null,
            setItem: (k, v) => { writes.push(v); store.set(k, v); },
        };
        expect(readStoredScope(storage, 'modca:scope:alice')).toBe('space=one');
        expect(store.get('modca:scope:alice')).toBe('space=one');
        expect(readStoredScope(storage, 'modca:scope:alice')).toBe('space=one');
        expect(writes).toEqual(['space=one']);
        expect(parseScope(readStoredScope(storage, 'modca:scope:alice')!, twoSpaces)).toEqual(spaceOne);
        expect(readStoredScope(storage, 'modca:scope:nobody')).toBeNull();
    });
});
