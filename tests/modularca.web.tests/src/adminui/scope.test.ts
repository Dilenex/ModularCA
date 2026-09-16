import { describe, expect, it } from 'vitest';
import { Capabilities } from '@shared/generated';
import type { EffectiveCapabilities } from '@adminui/authz';
import {
    ALL_SCOPE, MINE_SCOPE, canScopeToAll, defaultScope, parseScope, sameScope, scopeCaId, scopeLabel, withScope,
} from '@adminui/scope';

/**
 * The console's CA scope as it travels in the URL. A link must carry its scope, an unknown or
 * inaccessible CA in the URL must fall back rather than scope to nothing, and "all CAs" must
 * only be offered to callers holding something at system scope.
 */
const caA = { id: 'a', label: 'ca-a', name: 'A', isSshCa: false, capabilities: [Capabilities.CaManage] };
const caB = { id: 'b', label: 'ca-b', name: 'B', isSshCa: false, capabilities: [Capabilities.CertRequest] };

const operator: EffectiveCapabilities = { system: [], cas: [caA, caB] };
const systemAdmin: EffectiveCapabilities = { system: [Capabilities.SystemManage], cas: [caA] };
const requester: EffectiveCapabilities = { system: [], cas: [caB] };

describe('parseScope', () => {
    it('reads ?ca=<label> for a CA the caller may administer', () => {
        expect(parseScope('?ca=ca-a', operator)).toEqual({ kind: 'ca', caId: 'a', label: 'ca-a' });
        expect(parseScope(new URLSearchParams('ca=ca-a&page=2'), operator)).toEqual({ kind: 'ca', caId: 'a', label: 'ca-a' });
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
        expect(parseScope('?scope=all&ca=ca-a', systemAdmin)).toEqual({ kind: 'ca', caId: 'a', label: 'ca-a' });
    });
});

describe('withScope', () => {
    it('writes the scope and replaces whatever scope was there, keeping other parameters', () => {
        expect(withScope('?scope=all&page=3', { kind: 'ca', caId: 'a', label: 'ca-a' }).toString()).toBe('page=3&ca=ca-a');
        expect(withScope('?ca=ca-a', ALL_SCOPE).toString()).toBe('scope=all');
        expect(withScope('', MINE_SCOPE).toString()).toBe('scope=mine');
    });

    it('round-trips through parseScope', () => {
        const scope = { kind: 'ca' as const, caId: 'a', label: 'ca-a' };
        expect(parseScope(withScope('', scope), operator)).toEqual(scope);
    });
});

describe('defaultScope', () => {
    it('is all CAs for a system-scoped caller', () => {
        expect(canScopeToAll(systemAdmin)).toBe(true);
        expect(defaultScope(systemAdmin)).toEqual(ALL_SCOPE);
    });

    it('is the first administrable CA otherwise, and mine when there is none', () => {
        expect(canScopeToAll(operator)).toBe(false);
        expect(defaultScope(operator)).toEqual({ kind: 'ca', caId: 'a', label: 'ca-a' });
        expect(defaultScope(requester)).toEqual(MINE_SCOPE);
    });
});

describe('scope helpers', () => {
    it('yield a caId filter only for a single-CA scope', () => {
        expect(scopeCaId({ kind: 'ca', caId: 'a', label: 'ca-a' })).toBe('a');
        expect(scopeCaId(ALL_SCOPE)).toBeNull();
        expect(scopeCaId(MINE_SCOPE)).toBeNull();
    });

    it('label and compare scopes by what they name', () => {
        expect(scopeLabel(ALL_SCOPE)).toBe('All CAs');
        expect(scopeLabel(MINE_SCOPE)).toBe('Mine');
        expect(scopeLabel({ kind: 'ca', caId: 'a', label: 'ca-a' })).toBe('ca-a');
        expect(sameScope({ kind: 'ca', caId: 'a', label: 'x' }, { kind: 'ca', caId: 'a', label: 'y' })).toBe(true);
        expect(sameScope({ kind: 'ca', caId: 'a', label: 'x' }, { kind: 'ca', caId: 'b', label: 'x' })).toBe(false);
        expect(sameScope(ALL_SCOPE, MINE_SCOPE)).toBe(false);
        expect(sameScope(MINE_SCOPE, { kind: 'mine' })).toBe(true);
    });
});
