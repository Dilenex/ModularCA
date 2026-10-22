import { describe, expect, it } from 'vitest';
import type { ProfilePairConstraints, ServerKeyOption } from '@shared/generated';
import {
    certificateGroup, extendedKeyUsageWords, infrastructureGroup, issuerGroup, keyUsageWords, keysGroup, namesGroup,
    type RequestProfileRules,
} from '@adminui/pages/profileConstraints';

/** The panel beside the profile pickers: what the chosen profiles impose, in words. */

const value = (group: { lines: { label: string; value: string }[] }, label: string) =>
    group.lines.filter((l) => l.label === label).map((l) => l.value);

const profile = (over: Partial<RequestProfileRules> = {}): RequestProfileRules => ({
    name: 'Web Server (ACME)',
    subjectDnRules: [
        { field: 'CN', requirement: 'Required', regex: '^[a-z.]+$' },
        { field: 'O', requirement: 'Forbidden' },
        { field: 'OU', requirement: 'forbidden' },
        { field: 'C', requirement: 'Optional', fixedValue: 'US' },
        { field: 'L', requirement: 'Required', defaultValue: 'Reno' },
    ],
    sanRules: { allowedTypes: ['DNS', 'IP'], required: true, rules: { dns: { regex: null, maxCount: 100 }, IP: { regex: '^10\\.', maxCount: 10 } } },
    requireApproval: false,
    ...over,
});

const constraints = (over: Partial<ProfilePairConstraints> = {}): ProfilePairConstraints => ({
    issuingCaName: 'Staging CA R1',
    nameConstraintsPermitted: [],
    nameConstraintsExcluded: [],
    keyUsages: ['digitalSignature', 'Key Encipherment'],
    extendedKeyUsages: [{ value: '1.3.6.1.5.5.7.3.1', name: 'serverAuth' }],
    validityPeriodMin: 'P1D',
    validityPeriodMax: 'P397D',
    allowWildcard: false,
    ...over,
});

describe('the names a request profile allows', () => {
    it('lists what is required, forbidden, set and filled in, with patterns and SAN rules', () => {
        const group = namesGroup(profile());
        expect(group.title).toBe('Names');
        expect(group.from).toBe('Web Server (ACME)');
        expect(value(group, 'Required')).toEqual(['CN, L']);
        expect(value(group, 'Not allowed')).toEqual(['O, OU']);
        expect(value(group, 'Set by the profile')).toEqual(['C = US']);
        expect(value(group, 'Filled in if left out')).toEqual(['L = Reno']);
        expect(value(group, 'Must match')).toEqual(['CN: ^[a-z.]+$', 'IP: ^10\\.']);
        expect(value(group, 'SANs')).toEqual(['DNS (up to 100), IP (up to 10); at least one']);
        expect(value(group, 'Approval')).toEqual(['Not required by this profile']);
    });

    it('says so when the profile allows no SAN, has no subject rule, or needs approval', () => {
        const group = namesGroup(profile({
            subjectDnRules: [],
            sanRules: { allowedTypes: [], required: false, rules: {} },
            requireApproval: true,
            requiredApprovalCount: 2,
        }));
        expect(value(group, 'Subject')).toEqual(['No rule']);
        expect(value(group, 'SANs')).toEqual(['None allowed']);
        expect(value(group, 'Approval')).toEqual(['Required, 2 approvals']);
        expect(value(namesGroup(profile({ requireApproval: true })), 'Approval')).toEqual(['Required']);
    });
});

describe('the issuing CA and the certificate', () => {
    it('names the CA and its name constraints', () => {
        const group = issuerGroup('Staging CA R1 Signing Profile', constraints({ nameConstraintsPermitted: ['DNS:.corp.example'], nameConstraintsExcluded: ['DNS:.lab.corp.example'] }));
        expect(group.from).toBe('Staging CA R1 Signing Profile');
        expect(value(group, 'Issued by')).toEqual(['Staging CA R1']);
        expect(value(group, 'Names limited to')).toEqual(['DNS:.corp.example']);
        expect(value(group, 'Names excluded')).toEqual(['DNS:.lab.corp.example']);

        const unbound = issuerGroup('Loose', constraints({ issuingCaName: null }));
        expect(unbound.lines).toEqual([{ label: 'Issued by', value: 'No CA: this signing profile names none', tone: 'warn' }]);
    });

    it('puts usages, validity and wildcards in words', () => {
        const group = certificateGroup('TLS Server', constraints());
        expect(value(group, 'Key usage')).toEqual(['Digital Signature, Key Encipherment']);
        expect(value(group, 'Extended key usage')).toEqual(['Server Auth']);
        expect(value(group, 'Validity')).toEqual(['1 day to 397 days']);
        expect(value(group, 'Wildcard names')).toEqual(['Not allowed']);
    });

    it('warns about a profile that lists no key usage', () => {
        const group = certificateGroup('Main Certificate Profile', constraints({ keyUsages: [], extendedKeyUsages: [], validityPeriodMin: null, validityPeriodMax: null, allowWildcard: true }));
        expect(group.lines[0]).toEqual({ label: 'Key usage', value: 'None: the profile lists no key usage', tone: 'warn' });
        expect(value(group, 'Extended key usage')).toEqual(['None']);
        expect(value(group, 'Validity')).toEqual(['No limit in the profile']);
        expect(value(group, 'Wildcard names')).toEqual(['Allowed']);
    });

    it('labels a usage it knows and keeps the catalog name of one it does not', () => {
        expect(keyUsageWords('keyCertSign')).toBe('Key Cert Sign');
        expect(keyUsageWords('CRL Sign')).toBe('CRL Sign');
        expect(keyUsageWords('somethingElse')).toBe('somethingElse');
        expect(extendedKeyUsageWords({ value: 'codeSigning', name: 'codeSigning' })).toBe('Code Signing');
        expect(extendedKeyUsageWords({ value: '1.2.3.4', name: 'Custom Usage' })).toBe('Custom Usage');
    });
});

describe('the keys a pair accepts', () => {
    const option = (algorithm: string, keySize: string | null): ServerKeyOption => ({ algorithm, keySize, signatureAlgorithm: 'x' });

    it('are listed an algorithm to a line, sizes together', () => {
        const group = keysGroup([option('RSA', '3072'), option('RSA', '4096'), option('ECDSA', 'P-384'), option('Ed25519', null), option('ML-DSA-65', null)], 9);
        expect(group.lines).toEqual([
            { label: 'Accepted', value: 'RSA 3072, 4096' },
            { label: '', value: 'ECDSA P-384' },
            { label: '', value: 'Ed25519, ML-DSA-65' },
            { label: 'Not accepted', value: '9 other keys' },
        ]);
        expect(keysGroup([option('Ed25519', null)], 1).lines.at(-1)).toEqual({ label: 'Not accepted', value: '1 other key' });
        expect(keysGroup([option('Ed25519', null)], 0).lines).toEqual([{ label: 'Accepted', value: 'Ed25519' }]);
    });

    it('say so when nothing is accepted', () => {
        expect(keysGroup([], 14).lines).toEqual([
            { label: 'Accepted', value: 'None: these two profiles accept no key the CA can generate', tone: 'warn' },
        ]);
    });
});

describe("one of a CA's own certificates", () => {
    it('shows what its profile gives it, and the problem of that profile', () => {
        const facts = { name: 'TSA Certificate Profile', keyUsages: ['digitalSignature'], extendedKeyUsages: [{ value: '1.3.6.1.5.5.7.3.8', name: 'timeStamping' }], validityPeriodMin: 'P1D', validityPeriodMax: 'P10Y' };
        const group = infrastructureGroup('TSA signer', facts, null);
        expect(group.title).toBe('TSA signer');
        expect(group.from).toBe('TSA Certificate Profile');
        expect(group.lines).toEqual([
            { label: 'Key usage', value: 'Digital Signature' },
            { label: 'Extended key usage', value: 'Time Stamping' },
            { label: 'Profile validity', value: '1 day to 10 years' },
        ]);
        expect(infrastructureGroup('TSA signer', facts, 'does not list time stamping').lines.at(-1))
            .toEqual({ label: 'Problem', value: 'does not list time stamping', tone: 'warn' });
    });

    it('says the profile is missing when there is none', () => {
        expect(infrastructureGroup('CMP signer', undefined, 'It is created the first time this certificate is issued.').lines)
            .toEqual([{ label: 'Profile', value: 'It is created the first time this certificate is issued.', tone: 'warn' }]);
        expect(infrastructureGroup('CMP signer', undefined, null).lines[0].value).toBe('Not found');
    });
});
