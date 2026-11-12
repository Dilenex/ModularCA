import { describe, expect, it } from 'vitest';
import {
    caAdmitsCertProfile, casInScope, certProfilesOf, defaultSigningProfileId, requestCas, requestProfilesOf,
    selectionsForCa, settleCa, signingProfilesOf,
    type PickerScope, type RequestCa, type ScopedCertProfile, type SigningProfileRow,
} from '@adminui/pages/requestCaPicker';

/**
 * The CA picker at the top of the certificate request form.
 *
 * Two spaces, east and west; east has two CAs. There is an instance CA (no space) and a signing
 * profile with no issuer, which only a system-scoped caller is listed. The rows are shaped as
 * `GET /api/v1/user/signing-profiles` and `GET /api/v1/user/request-profiles` return them; the
 * server's `SelfServiceProfileListTests` holds the same rules equal to the real submit check.
 */

const EAST = 'space-east';
const WEST = 'space-west';

const signing: SigningProfileRow[] = [
    { id: 'sp-east1-a', name: 'East One TLS', caId: 'ca-east1', caName: 'East One', caSpaceId: EAST },
    { id: 'sp-east1-b', name: 'East One Users', isDefault: true, caId: 'ca-east1', caName: 'East One', caSpaceId: EAST },
    { id: 'sp-east2', name: 'East Two', caId: 'ca-east2', caName: 'East Two', caSpaceId: EAST },
    { id: 'sp-west', name: 'West', caId: 'ca-west', caName: 'West', caSpaceId: WEST },
    { id: 'sp-instance', name: 'Instance', caId: 'ca-instance', caName: 'Instance Root', caSpaceId: null },
    { id: 'sp-no-issuer', name: 'No issuer', isDefault: true, caId: null, caName: null, caSpaceId: null },
];

const requests = [
    { id: 'rp-east1', certificateAuthorityId: 'ca-east1' },
    { id: 'rp-east2', certificateAuthorityId: 'ca-east2' },
    { id: 'rp-west', certificateAuthorityId: 'ca-west' },
    { id: 'rp-unbound', certificateAuthorityId: null },
    { id: 'rp-unbound-too' },
];

const certs: ScopedCertProfile[] = [
    { id: 'cp-instance-wide', name: 'Instance-wide', spaceId: null, certificateAuthorityId: null },
    { id: 'cp-east', name: 'East space', spaceId: EAST, certificateAuthorityId: null },
    { id: 'cp-east1', name: 'East One only', spaceId: EAST, certificateAuthorityId: 'ca-east1' },
    { id: 'cp-east2', name: 'East Two only', spaceId: EAST, certificateAuthorityId: 'ca-east2' },
    { id: 'cp-west', name: 'West space', spaceId: WEST },
    { id: 'cp-instance-ca', name: 'Instance CA only', spaceId: null, certificateAuthorityId: 'ca-instance' },
];

const ALL: PickerScope = { kind: 'all' };
const MINE: PickerScope = { kind: 'mine' };
const ids = (rows: { id: string }[]) => rows.map(r => r.id);
const ca = (id: string): RequestCa => requestCas(signing).find(c => c.id === id)!;

/** The CA the picker opens on: what the lists and the scope settle from nothing chosen. */
const opensOn = (rows: SigningProfileRow[], scope: PickerScope) => settleCa('', casInScope(requestCas(rows), scope));

describe('the CAs a caller can request from', () => {
    it('are the CAs of the listed signing profiles, once each, by name', () => {
        expect(requestCas(signing)).toEqual([
            { id: 'ca-east1', name: 'East One', spaceId: EAST },
            { id: 'ca-east2', name: 'East Two', spaceId: EAST },
            { id: 'ca-instance', name: 'Instance Root', spaceId: null },
            { id: 'ca-west', name: 'West', spaceId: WEST },
        ]);
    });

    it('leave out a signing profile with no issuer: there is no "No CA" entry', () => {
        expect(requestCas([signing[5]])).toEqual([]);
        expect(requestCas([{ id: 'sp-old-server' }])).toEqual([]);
        for (const c of requestCas(signing)) expect(ids(signingProfilesOf(signing, c.id))).not.toContain('sp-no-issuer');
    });

    it('leave out a CA the caller can see the profiles of and cannot submit against', () => {
        expect(ids(requestCas(signing, (id) => id !== 'ca-east2'))).toEqual(['ca-east1', 'ca-instance', 'ca-west']);
    });

    it('fall back to the id for a CA with no name', () => {
        expect(requestCas([{ id: 'sp', caId: 'ca-x', caName: null }])).toEqual([{ id: 'ca-x', name: 'ca-x', spaceId: null }]);
    });
});

describe('the CA the picker opens on', () => {
    it('is none when the caller can use several and the scope names no CA', () => {
        expect(opensOn(signing, ALL)).toBe('');
        expect(opensOn(signing, MINE)).toBe('');
    });

    it('is the only CA when the caller can use one, as a badge that keeps one CA leaves it', () => {
        const one = signing.filter(p => p.caId === 'ca-west');
        expect(casInScope(requestCas(one), MINE)).toHaveLength(1);
        expect(opensOn(one, MINE)).toBe('ca-west');
        expect(opensOn(one, ALL)).toBe('ca-west');
    });

    it('is the scoped CA when the console is scoped to one, and that CA is the only one offered', () => {
        const scope: PickerScope = { kind: 'ca', caId: 'ca-east2' };
        expect(ids(casInScope(requestCas(signing), scope))).toEqual(['ca-east2']);
        expect(opensOn(signing, scope)).toBe('ca-east2');
    });

    it('is none, with nothing offered, when the scoped CA has no signing profile to request against', () => {
        const scope: PickerScope = { kind: 'ca', caId: 'ca-ssh' };
        expect(casInScope(requestCas(signing), scope)).toEqual([]);
        expect(opensOn(signing, scope)).toBe('');
    });

    it('is none under a space scope with several CAs, which lists that space\'s CAs only', () => {
        const scope: PickerScope = { kind: 'space', spaceId: EAST };
        expect(ids(casInScope(requestCas(signing), scope))).toEqual(['ca-east1', 'ca-east2']);
        expect(opensOn(signing, scope)).toBe('');
    });

    it('is the space\'s CA under a space scope with one; an instance CA is in no space', () => {
        const scope: PickerScope = { kind: 'space', spaceId: WEST };
        expect(ids(casInScope(requestCas(signing), scope))).toEqual(['ca-west']);
        expect(opensOn(signing, scope)).toBe('ca-west');
    });
});

describe('the CA the picker holds when the scope moves', () => {
    const offered = (scope: PickerScope) => casInScope(requestCas(signing), scope);

    it('keeps a choice the new scope still offers', () => {
        expect(settleCa('ca-east1', offered({ kind: 'space', spaceId: EAST }))).toBe('ca-east1');
        expect(settleCa('ca-east1', offered(ALL))).toBe('ca-east1');
    });

    it('drops a choice the new scope does not offer', () => {
        expect(settleCa('ca-west', offered({ kind: 'space', spaceId: EAST }))).toBe('');
    });

    it('moves to the CA a new CA scope names', () => {
        expect(settleCa('ca-east1', offered({ kind: 'ca', caId: 'ca-west' }))).toBe('ca-west');
    });
});

describe('the profiles of the chosen CA', () => {
    it('are none while no CA is chosen', () => {
        expect(signingProfilesOf(signing, '')).toEqual([]);
        expect(requestProfilesOf(requests, '')).toEqual([]);
        expect(certProfilesOf(certs, null)).toEqual([]);
    });

    it('signing profiles: that CA\'s only', () => {
        expect(ids(signingProfilesOf(signing, 'ca-east1'))).toEqual(['sp-east1-a', 'sp-east1-b']);
        expect(ids(signingProfilesOf(signing, 'ca-west'))).toEqual(['sp-west']);
    });

    it('the signing profile preselected is the CA\'s default, failing that its first', () => {
        expect(defaultSigningProfileId(signing, 'ca-east1')).toBe('sp-east1-b');
        expect(defaultSigningProfileId(signing, 'ca-east2')).toBe('sp-east2');
        // Another CA's default, or the one with no issuer, is never the choice.
        expect(defaultSigningProfileId(signing, 'ca-west')).toBe('sp-west');
        expect(defaultSigningProfileId(signing, '')).toBe('');
    });

    it('a CA with exactly one signing profile still lists it, preselected', () => {
        expect(ids(signingProfilesOf(signing, 'ca-east2'))).toEqual(['sp-east2']);
        expect(selectionsForCa('ca-east2', signing).signingProfileId).toBe('sp-east2');
    });

    it('request profiles: those bound to the CA and the unbound ones', () => {
        expect(ids(requestProfilesOf(requests, 'ca-east1'))).toEqual(['rp-east1', 'rp-unbound', 'rp-unbound-too']);
        expect(ids(requestProfilesOf(requests, 'ca-west'))).toEqual(['rp-west', 'rp-unbound', 'rp-unbound-too']);
    });

    it('unbound request profiles are offered for every CA', () => {
        for (const c of requestCas(signing)) {
            expect(ids(requestProfilesOf(requests, c.id))).toEqual(expect.arrayContaining(['rp-unbound', 'rp-unbound-too']));
        }
        // An instance CA with no request profile of its own gets the unbound ones and no other.
        expect(ids(requestProfilesOf(requests, 'ca-instance'))).toEqual(['rp-unbound', 'rp-unbound-too']);
    });

    it('certificate profiles: what the CA admits, in the order given', () => {
        expect(ids(certProfilesOf(certs, ca('ca-east1')))).toEqual(['cp-instance-wide', 'cp-east', 'cp-east1']);
        expect(ids(certProfilesOf(certs, ca('ca-east2')))).toEqual(['cp-instance-wide', 'cp-east', 'cp-east2']);
        expect(ids(certProfilesOf(certs, ca('ca-west')))).toEqual(['cp-instance-wide', 'cp-west']);
        expect(ids(certProfilesOf(certs, ca('ca-instance')))).toEqual(['cp-instance-wide', 'cp-instance-ca']);
    });
});

/**
 * `CertProfileScope.Admits(profileSpaceId, profileCaId, caId, caSpaceId)` on the server, case by
 * case: (no space and no CA) or (same space and (no CA or this CA)).
 */
describe('whether a CA may issue under a certificate profile', () => {
    const east1: RequestCa = { id: 'ca-east1', name: 'East One', spaceId: EAST };
    const instance: RequestCa = { id: 'ca-instance', name: 'Instance Root', spaceId: null };
    const profile = (spaceId: string | null | undefined, certificateAuthorityId: string | null | undefined): ScopedCertProfile =>
        ({ id: 'p', name: 'p', spaceId, certificateAuthorityId });

    it.each([
        ['instance-wide, a space CA', profile(null, null), east1, true],
        ['instance-wide, an instance CA', profile(null, null), instance, true],
        ['instance-wide with the fields absent', profile(undefined, undefined), east1, true],
        ['its space, bound to no CA', profile(EAST, null), east1, true],
        ['its space, bound to it', profile(EAST, 'ca-east1'), east1, true],
        ['its space, bound to a sibling CA', profile(EAST, 'ca-east2'), east1, false],
        ['another space', profile(WEST, null), east1, false],
        ['another space, an instance CA', profile(WEST, null), instance, false],
        ['bound to it under another space', profile(WEST, 'ca-east1'), east1, false],
        ['no space, bound to the instance CA', profile(null, 'ca-instance'), instance, true],
        ['no space, bound to another instance CA', profile(null, 'ca-other'), instance, false],
        ['no space, bound to an instance CA, asked of a space CA', profile(null, 'ca-instance'), east1, false],
        ['no space, bound to this space CA', profile(null, 'ca-east1'), east1, false],
    ])('%s', (_name, p, issuing, expected) => {
        expect(caAdmitsCertProfile(p, issuing)).toBe(expected);
    });
});

describe('choosing a CA', () => {
    it('empties the request and certificate profile and puts the CA\'s default signing profile in, whatever was held', () => {
        expect(selectionsForCa('ca-east1', signing)).toEqual({
            caId: 'ca-east1', requestProfileId: '', signingProfileId: 'sp-east1-b', certProfileId: '',
        });
        // From East One to West: nothing of East One is carried over.
        const next = selectionsForCa('ca-west', signing);
        expect(next).toEqual({ caId: 'ca-west', requestProfileId: '', signingProfileId: 'sp-west', certProfileId: '' });
        expect(ids(signingProfilesOf(signing, next.caId))).toContain(next.signingProfileId);
    });

    it('back to none empties all three', () => {
        expect(selectionsForCa('', signing)).toEqual({ caId: '', requestProfileId: '', signingProfileId: '', certProfileId: '' });
    });
});
