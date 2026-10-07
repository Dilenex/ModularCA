import { describe, expect, it } from 'vitest';
import cases from './sunset-rule-cases.json';
import { hasRowErrors } from '@shared/components/rowTable';
import {
    SUNSET_ALGORITHM_SUGGESTIONS, SUNSET_COLUMNS, sunsetAlgorithmWarning, sunsetRowsFromList, sunsetRowsToList, sunsetRuleError,
} from '@adminui/pages/sunsetRules';

/**
 * Algorithm Sunset Rules as rows. The grammar must match ConfigInputRules.AlgorithmSunsetRuleError
 * (the cases are shared with ConfigInputRulesTests), and the rows must say the same thing.
 */
describe('sunset rules: parity with ConfigInputRules', () => {
    it.each(cases.accept)('accepts %j', (rule) => expect(sunsetRuleError(rule)).toBeNull());
    it.each(cases.reject)('refuses %j', (rule) => expect(sunsetRuleError(rule)).not.toBeNull());

    it('judges a rule as rows the same way as the whole string', () => {
        for (const rule of [...cases.accept, ...cases.reject]) {
            if (!rule.trim()) continue;
            const rows = sunsetRowsFromList([rule]);
            expect(hasRowErrors(rows, SUNSET_COLUMNS), rule).toBe(sunsetRuleError(rule) !== null);
        }
    });
});

describe('sunset rules: rows', () => {
    it('splits at the last colon, as the server does, and writes ALG:date back', () => {
        const rules = ['RSA-2048:2030-01-01', 'ECDSA-P-256 : 2035-06-30'];
        const rows = sunsetRowsFromList(rules);
        expect(rows).toEqual([{ algorithm: 'RSA-2048', date: '2030-01-01' }, { algorithm: 'ECDSA-P-256', date: '2035-06-30' }]);
        expect(sunsetRowsToList(rows)).toEqual(['RSA-2048:2030-01-01', 'ECDSA-P-256:2035-06-30']);
    });

    it('keeps a rule with no date as a row missing its date', () => {
        const rows = sunsetRowsFromList(['RSA-2048']);
        expect(rows).toEqual([{ algorithm: 'RSA-2048', date: '' }]);
        expect(hasRowErrors(rows, SUNSET_COLUMNS)).toBe(true);
    });

    it('drops blank rows on save', () => {
        expect(sunsetRowsToList([{ algorithm: '', date: '' }, { algorithm: 'RSA', date: '2030-01-01' }])).toEqual(['RSA:2030-01-01']);
    });

    it('warns, without blocking, on an algorithm the server never names', () => {
        expect(sunsetAlgorithmWarning('SHA-256')).toMatch(/not a name/);
        expect(sunsetAlgorithmWarning('rsa-8192')).toBeNull();
        expect(sunsetAlgorithmWarning('ML-DSA-87')).toBeNull();
        expect(sunsetAlgorithmWarning('1.2.840.113549.1.1.4')).toBeNull();
        expect(SUNSET_ALGORITHM_SUGGESTIONS.every((s) => sunsetAlgorithmWarning(s) === null && sunsetRuleError(`${s}:2030-01-01`) === null)).toBe(true);
        expect(hasRowErrors(sunsetRowsFromList(['SHA-256:2035-01-01']), SUNSET_COLUMNS)).toBe(false);
    });
});
