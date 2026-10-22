import { describe, expect, it } from 'vitest';
import { designatedCertProfileIds, offeredCertProfiles, settleCertProfile, type CertProfileOption } from '@adminui/pages/requestCertProfiles';

/** The certificate profile picker of the request form, held to what the request profile designates. */

const all: CertProfileOption[] = [
    { id: 'main', name: 'Main Certificate Profile' },
    { id: 'tls', name: 'TLS Server' },
    { id: 'user', name: 'User Authentication and Email' },
];

describe('the profiles a request profile designates', () => {
    it('are its default first, then its allowed list, none twice', () => {
        expect(designatedCertProfileIds('tls', ['user', 'tls'])).toEqual(['tls', 'user']);
        expect(designatedCertProfileIds(null, ['user'])).toEqual(['user']);
        expect(designatedCertProfileIds('tls', null)).toEqual(['tls']);
        expect(designatedCertProfileIds(undefined, undefined)).toEqual([]);
        expect(designatedCertProfileIds('', [''])).toEqual([]);
    });
});

describe("an operator's picker", () => {
    it('offers every profile when the request profile designates none', () => {
        expect(offeredCertProfiles(all, [])).toEqual(all);
    });

    it('offers only the designated ones, in their order, when it designates any', () => {
        expect(offeredCertProfiles(all, ['user', 'tls']).map((p) => p.id)).toEqual(['user', 'tls']);
        expect(offeredCertProfiles(all, ['gone', 'tls']).map((p) => p.id)).toEqual(['tls']);
        expect(offeredCertProfiles(all, ['gone'])).toEqual([]);
    });
});

describe('the profile the picker holds', () => {
    it('is the first designated one that is offered', () => {
        expect(settleCertProfile('main', all, ['tls', 'user'], false)).toBe('tls');
        expect(settleCertProfile('', all, ['gone', 'user'], false)).toBe('user');
    });

    it('stays as chosen while still offered and nothing is designated', () => {
        expect(settleCertProfile('user', all, [], true)).toBe('user');
    });

    it('is cleared where every profile is offered and the choice is gone', () => {
        expect(settleCertProfile('gone', all, [], true)).toBe('');
        expect(settleCertProfile('', all, [], true)).toBe('');
    });

    it('is the first offered where the list is the designated one', () => {
        expect(settleCertProfile('gone', [all[1]], [], false)).toBe('tls');
        expect(settleCertProfile('gone', [], [], false)).toBe('');
    });
});
