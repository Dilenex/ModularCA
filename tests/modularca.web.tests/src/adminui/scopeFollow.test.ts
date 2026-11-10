import { describe, expect, it } from 'vitest';
import { ALL_SCOPE, MINE_SCOPE, scopeCaId, scopeKey, type Scope } from '@adminui/scope';
import { caIdForRef, rowsInScope, sshSigningProfileCaRef } from '@adminui/pages/scopedRows';
import { msaeScopeFollow, msaeSelectedCa, msaeSetupPath } from '@adminui/pages/msaeScope';

/**
 * Pages that follow the scope switcher: Dashboard, Profiles and Distribution. They used to key
 * their loads on the scoped CA id alone, which is null for every space and for "all CAs", so a
 * switch between two spaces (or between a space and "all") reloaded nothing.
 */
const spaceOne: Scope = { kind: 'space', spaceId: 't1', slug: 'one', name: 'Space One' };
const spaceTwo: Scope = { kind: 'space', spaceId: 't2', slug: 'two', name: 'Space Two' };
const caA: Scope = { kind: 'ca', caId: 'a', label: 'ca-a', spaceId: 't1', spaceSlug: 'one' };
const caB: Scope = { kind: 'ca', caId: 'b', label: 'ca-b', spaceId: 't1', spaceSlug: 'one' };

describe('scopeKey', () => {
    it('tells two spaces apart, which the CA id alone did not', () => {
        // The old key: `scopeCaId ?? 'all'`.
        expect(scopeCaId(spaceOne) ?? 'all').toBe(scopeCaId(spaceTwo) ?? 'all');
        expect(scopeKey(spaceOne)).not.toBe(scopeKey(spaceTwo));
    });

    it('tells a space from "all CAs", and one CA from another', () => {
        expect(scopeKey(spaceOne)).not.toBe(scopeKey(ALL_SCOPE));
        expect(scopeKey(caA)).not.toBe(scopeKey(caB));
        expect(scopeKey(caA)).not.toBe(scopeKey(spaceOne));
        expect(scopeKey(MINE_SCOPE)).not.toBe(scopeKey(ALL_SCOPE));
    });

    it('is the same for the same scope however it was built', () => {
        expect(scopeKey({ ...spaceOne, name: 'Renamed' })).toBe(scopeKey(spaceOne));
        expect(scopeKey(ALL_SCOPE)).toBe(scopeKey({ kind: 'all' }));
    });
});

/** The flat authority list from /admin/authorities: a CA id and its certificate id. */
const authorities = [
    { id: 'a', certificateId: 'cert-a', spaceId: 't1' },
    { id: 'b', certificateId: 'cert-b', spaceId: 't1' },
    { id: 'c', certificateId: 'cert-c', spaceId: 't2' },
];
/** `inScope` as ScopeContext builds it for each kind of scope. */
const inSpace = (space: string) => (caId: string | null | undefined) => !!caId && authorities.some(a => a.id === caId && a.spaceId === space);
const inCa = (id: string) => (caId: string | null | undefined) => caId === id;
const inAll = () => true;

describe('caIdForRef', () => {
    it('resolves a CA id or a CA certificate id to the CA id', () => {
        expect(caIdForRef('b', authorities)).toBe('b');
        expect(caIdForRef('cert-c', authorities)).toBe('c');
    });

    it('is null for nothing, and for a reference no listed CA matches', () => {
        expect(caIdForRef(null, authorities)).toBeNull();
        expect(caIdForRef('', authorities)).toBeNull();
        expect(caIdForRef('cert-z', authorities)).toBeNull();
    });
});

describe('rowsInScope', () => {
    // CRL schedules name their CA by certificate (caCertificateId), older rows by caId.
    const schedules = [
        { name: 'one-a', caCertificateId: 'cert-a' },
        { name: 'one-b', caId: 'b' },
        { name: 'two-c', caCertificateId: 'cert-c' },
        { name: 'unbound' },
    ];
    const refOf = (s: { caCertificateId?: string; caId?: string }) => s.caCertificateId || s.caId;
    const names = (rows: { name: string }[]) => rows.map(r => r.name);

    it('keeps the rows of the CAs a space scope covers', () => {
        expect(names(rowsInScope(schedules, refOf, authorities, inSpace('t1')))).toEqual(['one-a', 'one-b']);
        expect(names(rowsInScope(schedules, refOf, authorities, inSpace('t2')))).toEqual(['two-c']);
    });

    it('keeps one CA under a CA scope', () => {
        expect(names(rowsInScope(schedules, refOf, authorities, inCa('a')))).toEqual(['one-a']);
    });

    it('keeps every row under "all CAs"', () => {
        expect(names(rowsInScope(schedules, refOf, authorities, inAll))).toEqual(['one-a', 'one-b', 'two-c', 'unbound']);
    });

    it('keeps rows that name no CA when asked to, as signing profiles with no issuer yet', () => {
        expect(names(rowsInScope(schedules, refOf, authorities, inSpace('t2'), { keepUnbound: true }))).toEqual(['two-c', 'unbound']);
    });

    it('drops a row whose CA is not in the list under a narrower scope', () => {
        expect(rowsInScope([{ name: 'gone', caId: 'z' }], refOf, authorities, inCa('a'))).toEqual([]);
    });
});

/**
 * Request Profiles and the SSH profile tabs never followed the scope switcher. They narrow like
 * Signing Profiles: a profile bound to a CA the scope covers, or bound to none, is kept.
 */
describe('profile tabs that had ignored the scope', () => {
    const names = (rows: { name: string }[]) => rows.map(r => r.name);

    describe('Request Profiles, by the CA a profile is bound to', () => {
        const profiles = [
            { name: 'a-bound', certificateAuthorityId: 'a' },
            { name: 'c-bound', certificateAuthorityId: 'c' },
            { name: 'system-wide', certificateAuthorityId: null },
        ];
        const refOf = (p: { certificateAuthorityId: string | null }) => p.certificateAuthorityId;

        it('keeps the space\'s CAs\' profiles and the system-wide ones under a space scope', () => {
            expect(names(rowsInScope(profiles, refOf, authorities, inSpace('t1'), { keepUnbound: true }))).toEqual(['a-bound', 'system-wide']);
            expect(names(rowsInScope(profiles, refOf, authorities, inSpace('t2'), { keepUnbound: true }))).toEqual(['c-bound', 'system-wide']);
        });

        it('keeps the CA\'s and the system-wide ones under a CA scope, and every one under "all CAs"', () => {
            expect(names(rowsInScope(profiles, refOf, authorities, inCa('c'), { keepUnbound: true }))).toEqual(['c-bound', 'system-wide']);
            expect(names(rowsInScope(profiles, refOf, authorities, inAll, { keepUnbound: true }))).toEqual(['a-bound', 'c-bound', 'system-wide']);
        });
    });

    describe('SSH signing profiles, by the SSH CA of their key', () => {
        const sshCas = [{ id: 'ssh-1' }, { id: 'ssh-2' }];
        const keys = [
            { id: 'k1', certificateAuthorityId: 'ssh-1' },
            { id: 'k2', certificateAuthorityId: 'ssh-2' },
        ];
        const profiles = [
            { name: 'one', sshCaKeyId: 'k1' },
            { name: 'two', sshCaKeyId: 'k2' },
            { name: 'unlisted-key', sshCaKeyId: 'k9' },
            { name: 'no-key', sshCaKeyId: null },
        ];
        const refOf = (p: { sshCaKeyId: string | null }) => sshSigningProfileCaRef(p, keys);

        it('names the CA of the profile\'s key', () => {
            expect(sshSigningProfileCaRef({ sshCaKeyId: 'k2' }, keys)).toBe('ssh-2');
        });

        it('names no CA for a profile with no key, and an unknown one for a key not listed', () => {
            expect(sshSigningProfileCaRef({ sshCaKeyId: null }, keys)).toBeNull();
            expect(sshSigningProfileCaRef({}, keys)).toBeNull();
            // The key id itself, which no CA has, so the row is out of a narrower scope, not unbound.
            expect(sshSigningProfileCaRef({ sshCaKeyId: 'k9' }, keys)).toBe('k9');
        });

        it('keeps one SSH CA\'s profiles and those with no key under that CA\'s scope', () => {
            expect(names(rowsInScope(profiles, refOf, sshCas, inCa('ssh-1'), { keepUnbound: true }))).toEqual(['one', 'no-key']);
        });

        it('keeps every profile under "all CAs"', () => {
            expect(names(rowsInScope(profiles, refOf, sshCas, inAll, { keepUnbound: true }))).toEqual(['one', 'two', 'unlisted-key', 'no-key']);
        });
    });
});

/**
 * Windows Autoenrollment names its CA in the URL and took it from there before the scope, so
 * picking another CA in the switcher changed nothing on the page. It now follows a CA picked
 * there, as Protocol Configuration does, and stays put for a scope that names no single CA.
 */
describe('Windows Autoenrollment and the scope switcher', () => {
    describe('msaeSelectedCa', () => {
        it('shows the CA the URL names, whatever the scope', () => {
            expect(msaeSelectedCa('c', caA, authorities)).toBe('c');
            expect(msaeSelectedCa('c', ALL_SCOPE, authorities)).toBe('c');
        });

        it('opens on the scoped CA when the URL names none', () => {
            expect(msaeSelectedCa(undefined, caB, authorities)).toBe('b');
            // Before the list has loaded, too.
            expect(msaeSelectedCa(undefined, caB, [])).toBe('b');
        });

        it('opens on the first CA of the scoped space, else the first listed', () => {
            expect(msaeSelectedCa(undefined, spaceTwo, authorities)).toBe('c');
            expect(msaeSelectedCa(undefined, ALL_SCOPE, authorities)).toBe('a');
            expect(msaeSelectedCa(undefined, { ...spaceTwo, spaceId: 't9' }, authorities)).toBe('a');
        });

        it('is empty while there is nothing to choose from', () => {
            expect(msaeSelectedCa(undefined, ALL_SCOPE, [])).toBe('');
        });
    });

    describe('msaeScopeFollow', () => {
        it('moves to the CA picked in the switcher', () => {
            // The bug: on /authorities/windows/a, switching the scope from CA a to CA b.
            expect(msaeScopeFollow(scopeKey(caA), caB, 'a')).toBe('b');
            expect(msaeScopeFollow(scopeKey(ALL_SCOPE), caB, 'a')).toBe('b');
            expect(msaeScopeFollow(scopeKey(spaceOne), caB, 'a')).toBe('b');
        });

        it('stays while the scope has not changed, so a link or the page\'s picker can name another CA', () => {
            expect(msaeScopeFollow(scopeKey(caA), caA, 'c')).toBeNull();
            expect(msaeScopeFollow(scopeKey(caA), { ...caA, label: 'renamed' }, 'c')).toBeNull();
        });

        it('stays when the new scope names no single CA', () => {
            expect(msaeScopeFollow(scopeKey(caA), spaceTwo, 'a')).toBeNull();
            expect(msaeScopeFollow(scopeKey(caA), ALL_SCOPE, 'a')).toBeNull();
            expect(msaeScopeFollow(scopeKey(caA), MINE_SCOPE, 'a')).toBeNull();
        });

        it('stays when the page already shows the CA picked', () => {
            expect(msaeScopeFollow(scopeKey(ALL_SCOPE), caB, 'b')).toBeNull();
        });

        it('moves from the bare path too', () => {
            expect(msaeScopeFollow(scopeKey(ALL_SCOPE), caB, undefined)).toBe('b');
        });
    });

    it('builds the page path for a CA', () => {
        expect(msaeSetupPath('b')).toBe('/authorities/windows/b');
    });
});
