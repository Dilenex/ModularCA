import { describe, expect, it } from 'vitest';
import cases from './name-constraint-cases.json';
import {
    INFRA_SAN_TYPES, NAME_CONSTRAINT_TYPES, SAN_TYPES, hasNonDnsConstraint, nameConstraintEntryError, nameConstraintListFromStored,
    nameConstraintRowsFromStored, nameConstraintRowsInvalid, nameConstraintRowsToJson, nameConstraintRowsToList,
    validateNcEmail, validateNcIp, validateSanDns, validateSanIp, validateSanUpn, validateSanUri,
} from '@shared/generalNames';

/**
 * Name-constraint checks must accept and refuse exactly what the server's NameConstraintRules
 * does; the cases are shared with tests/ModularCA.Tests (NameConstraintRulesTests) through
 * name-constraint-cases.json, so a rule changed on one side fails the other suite.
 */
describe('name constraints: parity with NameConstraintRules', () => {
    it.each(cases.accept)('accepts %s', (entry) => {
        expect(nameConstraintEntryError(entry)).toBeNull();
    });

    it.each(cases.reject)('refuses %s', (entry) => {
        expect(nameConstraintEntryError(entry)).not.toBeNull();
    });
});

describe('name constraints: the forms in question', () => {
    it('takes IP ranges as address/prefix or address/netmask, and refuses a bare address', () => {
        expect(validateNcIp('10.0.0.0/8')).toBeNull();
        expect(validateNcIp('10.0.0.0/255.0.0.0')).toBeNull();
        expect(validateNcIp('10.0.0.0')).toMatch(/single address/);
        expect(validateNcIp('10.0.0.1/8')).toMatch(/10\.0\.0\.0\/8/);
    });

    it('refuses @example.com and names the two forms that work', () => {
        const message = validateNcEmail('@example.com');
        expect(message).toContain('example.com');
        expect(message).toContain('.example.com');
    });

    it('lists the five types in the server spelling', () => {
        expect(NAME_CONSTRAINT_TYPES.map((t) => t.value)).toEqual(['DNS', 'IP', 'EMAIL', 'URI', 'DN']);
    });
});

describe('name constraints: stored values', () => {
    it('reads a JSON string, an array, or nothing', () => {
        expect(nameConstraintListFromStored('["DNS:a.example"]')).toEqual(['DNS:a.example']);
        expect(nameConstraintListFromStored(['DNS:a.example'])).toEqual(['DNS:a.example']);
        expect(nameConstraintListFromStored(null)).toEqual([]);
        expect(nameConstraintListFromStored('  ')).toEqual([]);
    });

    it('keeps text that is not a JSON array as one entry, so it is shown and flagged', () => {
        const rows = nameConstraintRowsFromStored('DNS:a.example, DNS:b.example');
        expect(rows).toHaveLength(1);
        expect(nameConstraintRowsInvalid(rows)).toBe(true);
    });

    it('writes rows back as the JSON array, or null when empty', () => {
        const rows = nameConstraintRowsFromStored('["dns:a.example","Email:example.com"]');
        expect(nameConstraintRowsToJson(rows)).toBe('["DNS:a.example","EMAIL:example.com"]');
        expect(nameConstraintRowsToList(rows)).toEqual(['DNS:a.example', 'EMAIL:example.com']);
        expect(nameConstraintRowsToJson([{ type: 'DNS', value: '' }])).toBeNull();
    });

    it('notices constraints other than DNS', () => {
        expect(hasNonDnsConstraint([{ type: 'DNS', value: 'a.example' }])).toBe(false);
        expect(hasNonDnsConstraint([{ type: 'IP', value: '10.0.0.0/8' }])).toBe(true);
        expect(hasNonDnsConstraint([{ type: 'IP', value: '' }])).toBe(false);
    });
});

describe('SAN types', () => {
    it('offers DNS, IP, Email, URI and UPN for issuance, and only DNS and IP for Web TLS', () => {
        expect(SAN_TYPES.map((t) => t.value)).toEqual(['DNS', 'IP', 'Email', 'URI', 'UPN']);
        expect(INFRA_SAN_TYPES.map((t) => t.value)).toEqual(['DNS', 'IP']);
    });

    it('checks DNS names and wildcards as the issuance check does', () => {
        expect(validateSanDns('host.example.com')).toBeNull();
        expect(validateSanDns('localhost')).toBeNull();
        expect(validateSanDns('*.example.com')).toBeNull();
        expect(validateSanDns('*.example.com', { allowWildcard: false })).not.toBeNull();
        expect(validateSanDns('*.com')).not.toBeNull();
        expect(validateSanDns('a.*.example.com')).not.toBeNull();
        expect(validateSanDns('exa mple.com')).not.toBeNull();
        expect(validateSanDns('10.0.0.1')).not.toBeNull();
    });

    it('checks addresses, URIs and UPNs', () => {
        expect(validateSanIp('10.0.0.1')).toBeNull();
        expect(validateSanIp('2001:db8::1')).toBeNull();
        expect(validateSanIp('10.0.0.0/8')).not.toBeNull();
        expect(validateSanUri('https://example.com/x')).toBeNull();
        expect(validateSanUri('urn:uuid:6e8bc430-9c3a-11d9-9669-0800200c9a66')).toBeNull();
        expect(validateSanUri('example.com')).not.toBeNull();
        expect(validateSanUpn('alice@corp.example')).toBeNull();
        expect(validateSanUpn('"Alice" <alice@corp.example>')).not.toBeNull();
        expect(validateSanUpn('a@b@c')).not.toBeNull();
    });
});
