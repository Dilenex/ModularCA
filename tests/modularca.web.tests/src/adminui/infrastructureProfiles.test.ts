import { describe, expect, it } from 'vitest';
import {
    DEFAULT_CHOICE, certProfileInUse, certProfileUseText, changedRoles, choicesFor, otherDefaultNames, roleConstraintGroups, roleLabel,
    savedChoices, sharedConstraintGroup,
    toRequest, type InfrastructureCandidate, type InfrastructureRole,
} from '@adminui/pages/infrastructureProfiles';

/** The profile pickers of a CA's own certificates, and the in-use mark on a certificate profile. */

const role = (key: string, defaultProfileName: string, chosenProfileId: string | null = null): InfrastructureRole =>
    ({ key, name: key, defaultProfileName, chosenProfileId, profileId: chosenProfileId ?? 'default', profileName: defaultProfileName, problem: null });

const tsa = role('tsa', 'TSA Certificate Profile');
const ocsp = role('ocspResponder', 'OCSP Responder Certificate Profile', 'p-ocsp');
const cmp = role('cmpSigner', 'CMP Signer Certificate Profile');

const candidates: InfrastructureCandidate[] = [
    { id: 'd-tsa', name: 'TSA Certificate Profile', suits: ['tsa', 'cmpSigner'] },
    { id: 'p-tsa', name: 'Long-lived TSA', suits: ['tsa', 'cmpSigner'] },
    { id: 'p-ocsp', name: 'Short OCSP', suits: [] },
    { id: 'p-tls', name: 'TLS Server', suits: ['cmpSigner'] },
];

describe('a role picker', () => {
    it('offers the profiles that suit the role, without the default profile itself', () => {
        expect(choicesFor(tsa, candidates).map((c) => c.id)).toEqual(['p-tsa']);
        expect(choicesFor(cmp, candidates).map((c) => c.id)).toEqual(['d-tsa', 'p-tsa', 'p-tls']);
    });

    it('keeps the profile the CA names even when it no longer suits', () => {
        expect(choicesFor(ocsp, candidates).map((c) => c.id)).toEqual(['p-ocsp']);
    });

    it('keeps the default profile when the CA names it by id', () => {
        expect(choicesFor(role('tsa', 'TSA Certificate Profile', 'd-tsa'), candidates).map((c) => c.id)).toEqual(['d-tsa', 'p-tsa']);
    });

    it('is labelled by what the certificate does', () => {
        expect([ocsp, tsa, cmp].map(roleLabel)).toEqual(['OCSP responder', 'TSA signer', 'CMP signer']);
        expect(roleLabel({ ...tsa, key: 'other', name: 'Other' })).toBe('Other');
    });
});

describe('the choices', () => {
    const roles = [ocsp, tsa, cmp];

    it('start as saved, the default as an empty choice', () => {
        expect(savedChoices(roles)).toEqual({ ocspResponder: 'p-ocsp', tsa: DEFAULT_CHOICE, cmpSigner: DEFAULT_CHOICE });
    });

    it('name the roles that differ from what is saved', () => {
        const choices = savedChoices(roles);
        expect(changedRoles(roles, choices)).toEqual([]);
        expect(changedRoles(roles, { ...choices, tsa: 'p-tsa', ocspResponder: DEFAULT_CHOICE }).map((r) => r.key)).toEqual(['ocspResponder', 'tsa']);
        expect(changedRoles(roles, {})).toEqual([ocsp]);
    });

    it('are sent whole, the default as null', () => {
        expect(toRequest({ ocspResponder: 'p-ocsp', tsa: DEFAULT_CHOICE })).toEqual({
            ocspResponderCertProfileId: 'p-ocsp', tsaCertProfileId: null, cmpSignerCertProfileId: null,
        });
    });
});

describe('a certificate profile in use', () => {
    it('is one found by name or named by a CA', () => {
        expect(certProfileInUse({})).toBe(false);
        expect(certProfileInUse({ systemPurpose: null, infrastructureUses: [] })).toBe(false);
        expect(certProfileInUse({ systemPurpose: 'the console TLS certificate is issued from it' })).toBe(true);
        expect(certProfileInUse({ infrastructureUses: ['Issuing CA: TSA'] })).toBe(true);
    });

    it('says why in one line', () => {
        expect(certProfileUseText({})).toBe('');
        expect(certProfileUseText({ systemPurpose: 'x', infrastructureUses: ['Issuing CA: TSA', 'Root: OCSP Responder'] }))
            .toBe('Found by name: x. Named by Issuing CA: TSA; Root: OCSP Responder.');
    });
});

describe('the panel beside the pickers', () => {
    const facts = (id: string, name: string, eku: string): InfrastructureCandidate => ({
        id, name, suits: [], keyUsages: ['digitalSignature'], extendedKeyUsages: [{ value: eku, name: eku }], validityPeriodMin: 'P1D', validityPeriodMax: 'P10Y',
    });
    const answer = {
        roles: [
            { ...ocsp, defaultProfileId: 'd-ocsp', chosenProfileId: 'p-short', problem: 'the saved one has a problem' },
            { ...tsa, defaultProfileId: 'd-tsa' },
            { ...cmp, defaultProfileId: null, problem: 'It is created the first time this certificate is issued.' },
        ],
        candidates: [
            facts('d-ocsp', 'OCSP Responder Certificate Profile', '1.3.6.1.5.5.7.3.9'),
            facts('p-short', 'Short OCSP', '1.3.6.1.5.5.7.3.9'),
            facts('d-tsa', 'TSA Certificate Profile', '1.3.6.1.5.5.7.3.8'),
        ],
        subjectKey: 'ECDSA P-256',
        lifetimeYears: 10,
        caNotAfter: '2051-09-12T16:31:00Z',
    };

    it('shows the profile each picker holds, the default when it holds none', () => {
        const groups = roleConstraintGroups(answer, savedChoices(answer.roles));
        expect(groups.map((g) => [g.title, g.from])).toEqual([
            ['OCSP responder', 'Short OCSP'], ['TSA signer', 'TSA Certificate Profile'], ['CMP signer', undefined],
        ]);
        expect(groups[0].lines.at(-1)).toEqual({ label: 'Problem', value: 'the saved one has a problem', tone: 'warn' });
        expect(groups[2].lines).toEqual([{ label: 'Profile', value: 'It is created the first time this certificate is issued.', tone: 'warn' }]);
    });

    it('follows an unsaved choice, without the saved profile\'s problem', () => {
        const groups = roleConstraintGroups(answer, { ...savedChoices(answer.roles), ocspResponder: DEFAULT_CHOICE });
        expect(groups[0].from).toBe('OCSP Responder Certificate Profile');
        expect(groups[0].lines.map((l) => l.label)).toEqual(['Key usage', 'Extended key usage', 'Profile validity']);
    });

    it('says what all three get whatever their profile', () => {
        const group = sharedConstraintGroup(answer, (iso) => iso.slice(0, 10));
        expect(group.lines).toEqual([
            { label: 'Key', value: "ECDSA P-256, following the CA's key" },
            { label: 'Lifetime', value: "10 years, or less where the profile's longest validity is shorter; never past the CA's expiry on 2051-09-12" },
        ]);
        expect(sharedConstraintGroup({ roles: [], candidates: [] }, String).lines[0].value).toBe("Follows the CA's key");
    });

    it('keeps the other certificates\' default profiles out of a picker', () => {
        const roles = [ocsp, tsa, cmp];
        expect(otherDefaultNames(cmp, roles)).toEqual(['OCSP Responder Certificate Profile', 'TSA Certificate Profile']);
        expect(choicesFor(cmp, candidates, otherDefaultNames(cmp, roles)).map((c) => c.id)).toEqual(['p-tsa', 'p-tls']);
    });
});
