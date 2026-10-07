import { describe, expect, it } from 'vitest';
import splitCases from './enrollment-restriction-cases.json';
import {
    parseRestrictionPatterns, restrictionFromRows, restrictionRowsFromText, validateRestrictionDn, validateRestrictionDomain,
} from '@adminui/components/enrollmentRestriction';

/**
 * Enrollment-token restrictions (L15). The server split a restriction on every space, so
 * `O=Acme Corp` became `O=Acme` and `Corp`, each enough on its own to admit a CSR. The console now
 * edits typed rows and the server keeps a DN value whole; these pin that the two read a stored
 * restriction identically (shared with EnrollmentNameRestrictionTests) and that the rows
 * serialise to text the server reads back as the same patterns.
 */
describe('parsing: parity with EnrollmentNameRestriction.ParsePatterns', () => {
    it.each(splitCases.cases.map((c) => [c.input, c.patterns] as const))('%j', (input, patterns) => {
        expect(parseRestrictionPatterns(input)).toEqual(patterns);
    });

    it('keeps O=Acme Corp as one pattern instead of O=Acme plus a Corp DNS suffix', () => {
        expect(parseRestrictionPatterns('O=Acme Corp')).toEqual(['O=Acme Corp']);
        expect(restrictionRowsFromText('O=Acme Corp')).toEqual([{ type: 'DN', value: 'O=Acme Corp' }]);
    });
});

describe('rows', () => {
    it('serialise to text the server reads back as the same patterns', () => {
        const rows = [
            { type: 'DNS', value: 'example.com' },
            { type: 'DN', value: 'O=Acme Corp' },
            { type: 'DN', value: 'O=Acme, Inc.' },
            { type: 'DNS', value: '' },
        ];
        const text = restrictionFromRows(rows);
        expect(text).toBe('example.com; O=Acme Corp; O=Acme\\, Inc.');
        expect(parseRestrictionPatterns(text)).toEqual(['example.com', 'O=Acme Corp', 'O=Acme\\, Inc.']);
    });

    it('serialise to an empty string when there are none', () => {
        expect(restrictionFromRows([])).toBe('');
    });
});

describe('validation', () => {
    it('takes a domain per row, without wildcards or separators', () => {
        expect(validateRestrictionDomain('example.com')).toBeNull();
        expect(validateRestrictionDomain('.example.com')).toBeNull();
        expect(validateRestrictionDomain('*.example.com')).toMatch(/wildcard/);
        expect(validateRestrictionDomain('a.com b.com')).not.toBeNull();
        expect(validateRestrictionDomain('O=Acme')).not.toBeNull();
    });

    it('takes one attribute=value per row', () => {
        expect(validateRestrictionDn('O=Acme Corp')).toBeNull();
        expect(validateRestrictionDn('2.5.4.10=Acme')).toBeNull();
        expect(validateRestrictionDn('Acme')).not.toBeNull();
        expect(validateRestrictionDn('O=')).not.toBeNull();
        expect(validateRestrictionDn('O=Acme; x')).not.toBeNull();
        expect(validateRestrictionDn('O=Acme OU=Eng')).toMatch(/One attribute per row/);
    });
});
