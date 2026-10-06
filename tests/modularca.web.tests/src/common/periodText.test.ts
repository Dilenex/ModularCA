import { describe, expect, it } from 'vitest';
import { periodRangeText, periodText } from '@shared/periodText';

describe('ISO periods in words', () => {
    it('names each unit, singular and plural', () => {
        expect(periodText('P10M')).toBe('10 months');
        expect(periodText('P1Y')).toBe('1 year');
        expect(periodText('P90D')).toBe('90 days');
        expect(periodText('P2W')).toBe('2 weeks');
        expect(periodText('P1Y6M')).toBe('1 year 6 months');
        expect(periodText('PT12H')).toBe('12 hours');
        expect(periodText('P1DT30M')).toBe('1 day 30 minutes');
    });

    it('tells months from minutes by the T', () => {
        expect(periodText('P5M')).toBe('5 months');
        expect(periodText('PT5M')).toBe('5 minutes');
    });

    it('returns anything else unchanged', () => {
        expect(periodText('13 months')).toBe('13 months');
        expect(periodText('P')).toBe('P');
        expect(periodText('P0D')).toBe('P0D');
        expect(periodText('')).toBe('');
        expect(periodText(null)).toBe('');
    });

    it('describes a window by the bounds that are set', () => {
        expect(periodRangeText('P10M', 'P13M')).toBe('10 months to 13 months');
        expect(periodRangeText('P1Y', 'P1Y')).toBe('1 year');
        expect(periodRangeText(null, 'P90D')).toBe('up to 90 days');
        expect(periodRangeText('P1D', '')).toBe('at least 1 day');
        expect(periodRangeText(undefined, undefined)).toBe('');
    });
});
