import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { describe, expect, it } from 'vitest';
import { ALL_SCOPE, MINE_SCOPE, scopeCaId, scopeKey, type Scope } from '@adminui/scope';
import { caIdForRef, parentsOutside, rowsInScope, sshSigningProfileCaRef } from '@adminui/pages/scopedRows';
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
 * The profile lists send the scope to the server (`caQuery()`: caId or spaceId), which narrows
 * by the console's own rule over the CAs the database holds. Signing Profiles, Request Profiles
 * and SSH Signing still filter what comes back, because they place a row by the CAs and keys the
 * caller is shown; SSH Request has nothing left to filter. Either way a list shows exactly what
 * the console's filter alone showed.
 */
describe('profile lists narrowed by the server', () => {
    const names = (rows: { name: string }[]) => rows.map(r => r.name);

    /** The database's CAs: the ones the caller is shown, and one of space t1 it is not. */
    const dbCas = [...authorities, { id: 'hidden', certificateId: 'cert-hidden', spaceId: 't1' }];
    type View = { caId?: string; spaceId?: string };
    /** The server's view of a list (ProfileListScopeTests pins the real one): unbound rows, and rows whose CA is the view's or in its space. */
    const serverView = <T,>(rows: T[], refOf: (row: T) => string | null | undefined, view: View): T[] => rows.filter(row => {
        const ref = refOf(row);
        // Without a view the server lists everything, a row whose CA is gone included.
        if (!ref || (!view.caId && !view.spaceId)) return true;
        const ca = dbCas.find(c => c.id === ref || c.certificateId === ref);
        return !!ca && (!view.caId || ca.id === view.caId) && (!view.spaceId || ca.spaceId === view.spaceId);
    });
    /** Each scope as the console holds it: the query it sends and the `inScope` it filters by. */
    const scopes: { name: string; view: View; inScope: (caId: string | null | undefined) => boolean }[] = [
        { name: 'all CAs', view: {}, inScope: inAll },
        { name: 'CA a', view: { caId: 'a' }, inScope: inCa('a') },
        { name: 'CA c', view: { caId: 'c' }, inScope: inCa('c') },
        { name: 'space one', view: { spaceId: 't1' }, inScope: inSpace('t1') },
        { name: 'space two', view: { spaceId: 't2' }, inScope: inSpace('t2') },
    ];

    // A signing profile names its issuer by the CA's certificate id; the console also takes a CA id.
    const signing = [
        { name: 'a-issued', issuerId: 'cert-a' },
        { name: 'b-issued-by-ca-id', issuerId: 'b' },
        { name: 'c-issued', issuerId: 'cert-c' },
        { name: 'hidden-issued', issuerId: 'cert-hidden' },
        { name: 'issuer-gone', issuerId: 'cert-z' },
        { name: 'no-issuer', issuerId: null },
    ];
    const request = [
        { name: 'a-bound', certificateAuthorityId: 'a' },
        { name: 'c-bound', certificateAuthorityId: 'c' },
        { name: 'hidden-bound', certificateAuthorityId: 'hidden' },
        { name: 'system-wide', certificateAuthorityId: null },
    ];

    it.each(scopes)('shows the same signing profiles under $name as the console\'s filter alone', ({ view, inScope }) => {
        const before = rowsInScope(signing, p => p.issuerId, authorities, inScope, { keepUnbound: true });
        const after = rowsInScope(serverView(signing, p => p.issuerId, view), p => p.issuerId, authorities, inScope, { keepUnbound: true });
        expect(names(after)).toEqual(names(before));
    });

    it.each(scopes)('shows the same request profiles under $name as the console\'s filter alone', ({ view, inScope }) => {
        const before = rowsInScope(request, p => p.certificateAuthorityId, authorities, inScope, { keepUnbound: true });
        const after = rowsInScope(serverView(request, p => p.certificateAuthorityId, view), p => p.certificateAuthorityId, authorities, inScope, { keepUnbound: true });
        expect(names(after)).toEqual(names(before));
    });

    it('still filters where the server keeps a row of a CA the caller is not shown', () => {
        // The server's space view holds the profile of the space's hidden CA; the console never showed it.
        expect(names(serverView(signing, p => p.issuerId, { spaceId: 't1' }))).toContain('hidden-issued');
        expect(names(rowsInScope(serverView(signing, p => p.issuerId, { spaceId: 't1' }), p => p.issuerId, authorities, inSpace('t1'), { keepUnbound: true })))
            .toEqual(['a-issued', 'b-issued-by-ca-id', 'no-issuer']);
        expect(names(rowsInScope(serverView(request, p => p.certificateAuthorityId, { spaceId: 't1' }), p => p.certificateAuthorityId, authorities, inSpace('t1'), { keepUnbound: true })))
            .toEqual(['a-bound', 'system-wide']);
    });

    describe('SSH, under a CA scope (a space scope shows the SSH sentence and loads nothing)', () => {
        const sshCas = [{ id: 'ssh-1' }, { id: 'ssh-2' }];
        const keys = [
            { id: 'k1', certificateAuthorityId: 'ssh-1' },
            { id: 'k2', certificateAuthorityId: 'ssh-2' },
        ];
        // The database also holds a key of ssh-1 that the caller's key list does not.
        const dbKeys = [...keys, { id: 'k-hidden', certificateAuthorityId: 'ssh-1' }];
        const sshSigning = [
            { name: 'one', sshCaKeyId: 'k1' },
            { name: 'two', sshCaKeyId: 'k2' },
            { name: 'hidden-key', sshCaKeyId: 'k-hidden' },
            { name: 'key-gone', sshCaKeyId: 'k9' },
            { name: 'no-key', sshCaKeyId: null },
        ];
        const sshRequest = [
            { name: 'one', certificateAuthorityId: 'ssh-1' },
            { name: 'two', certificateAuthorityId: 'ssh-2' },
            { name: 'any-ca', certificateAuthorityId: null },
        ];
        /** The server's CA view of SSH signing profiles: no key, or a key of that CA. */
        const serverSigning = (caId?: string) => sshSigning.filter(p => {
            if (!caId || !p.sshCaKeyId) return true;
            return dbKeys.find(k => k.id === p.sshCaKeyId)?.certificateAuthorityId === caId;
        });
        const refOf = (p: { sshCaKeyId: string | null }) => sshSigningProfileCaRef(p, keys);

        it.each([undefined, 'ssh-1', 'ssh-2'])('shows the same SSH signing profiles under CA %s as the console\'s filter alone', (caId) => {
            const inScope = caId ? inCa(caId) : inAll;
            const before = rowsInScope(sshSigning, refOf, sshCas, inScope, { keepUnbound: true });
            const after = rowsInScope(serverSigning(caId), refOf, sshCas, inScope, { keepUnbound: true });
            expect(names(after)).toEqual(names(before));
        });

        it('still filters SSH signing profiles whose key the caller cannot list', () => {
            expect(names(serverSigning('ssh-1'))).toEqual(['one', 'hidden-key', 'no-key']);
            expect(names(rowsInScope(serverSigning('ssh-1'), refOf, sshCas, inCa('ssh-1'), { keepUnbound: true }))).toEqual(['one', 'no-key']);
        });

        it.each([undefined, 'ssh-1', 'ssh-2'])('needs no filter for SSH request profiles under CA %s: the server\'s view is the console\'s', (caId) => {
            const view = sshRequest.filter(p => !caId || !p.certificateAuthorityId || p.certificateAuthorityId === caId);
            expect(names(view)).toEqual(names(rowsInScope(sshRequest, p => p.certificateAuthorityId, sshCas, caId ? inCa(caId) : inAll, { keepUnbound: true })));
        });
    });

    describe('parentsOutside', () => {
        it('names the parents a narrowed list left out, once each', () => {
            const rows = [
                { id: 'p1', inheritanceEnabled: true, inheritsFromId: 'base' },
                { id: 'p2', inheritanceEnabled: true, inheritsFromId: 'other-ca' },
                { id: 'p3', inheritanceEnabled: true, inheritsFromId: 'other-ca' },
                { id: 'base', inheritanceEnabled: false, inheritsFromId: null },
            ];
            expect(parentsOutside(rows)).toEqual(['other-ca']);
        });

        it('is empty when every parent is listed, and for a parent of a profile that does not inherit', () => {
            expect(parentsOutside([{ id: 'p1', inheritanceEnabled: true, inheritsFromId: 'base' }, { id: 'base' }])).toEqual([]);
            expect(parentsOutside([{ id: 'p1', inheritanceEnabled: false, inheritsFromId: 'elsewhere' }])).toEqual([]);
            expect(parentsOutside([])).toEqual([]);
        });
    });

    describe('the pages', () => {
        const page = (file: string) => readFileSync(resolve(__dirname, '../../../../modularca.adminui/src/pages', file), 'utf8');
        const profiles = page('ProfileManagement.tsx');

        it.each([
            ['Signing Profiles', profiles, '/api/v1/admin/signing-profiles'],
            ['SSH Signing', profiles, '/api/v1/admin/ssh/profiles/signing'],
            ['SSH Cert', profiles, '/api/v1/admin/ssh/profiles/cert'],
            ['SSH Request', profiles, '/api/v1/admin/ssh/profiles/request'],
            ['Request Profiles', page('RequestProfiles.tsx'), '/api/v1/admin/request-profiles'],
            ['the Dashboard\'s signing profiles', page('Dashboard.tsx'), '/api/v1/admin/signing-profiles'],
        ])('%s sends the scope with its list', (_name, source, path) => {
            expect(source).toMatch(new RegExp('apiGet<any>\\(`' + path.replace(/\//g, '\\/') + '\\$\\{(caQuery\\(\\)|scoped)\\}`\\)'));
        });

        it('reloads each list when the scope changes, as Certificate Profiles does', () => {
            // Certificate Profiles and the four other tabs in the file, and Request Profiles in its own.
            expect(profiles.match(/\}, \[currentScope\]\);/g)).toHaveLength(5);
            expect(page('RequestProfiles.tsx').match(/\}, \[currentScope\]\);/g)).toHaveLength(1);
        });

        it('keeps the console\'s own filter on the lists that place a row by what the caller is shown', () => {
            expect(profiles.match(/rows=\{visibleProfiles\}/g)).toHaveLength(2);
            expect(profiles).toContain('rowsInScope(profiles, (p) => p.issuerId, authorities, inScope, { keepUnbound: true })');
            expect(profiles).toContain('rowsInScope(profiles, (p) => sshSigningProfileCaRef(p, caKeys), cas, inScope, { keepUnbound: true })');
            expect(page('RequestProfiles.tsx')).toContain('rowsInScope(profiles, (p) => p.certificateAuthorityId, cas, inScope, { keepUnbound: true })');
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
