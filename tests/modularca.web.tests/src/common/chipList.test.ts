import { describe, expect, it } from 'vitest';
import {
    addEntries, findProblems, hasSeparator, invalidItems, listFromValue, listToCsv, normalizeNumeric, removeAt, sortNumeric, splitEntries,
} from '@shared/components/chipList';
import { validateEmail, validatePositiveInteger } from '@shared/validators';

describe('splitEntries', () => {
    it('splits on commas and line breaks, trimming and dropping blanks', () => {
        expect(splitEntries(' a, b\n\nc\r\nd,, ')).toEqual(['a', 'b', 'c', 'd']);
    });

    it('leaves commas alone when they do not separate (regexes)', () => {
        expect(splitEntries('^a{0,3}$\n^b$', false)).toEqual(['^a{0,3}$', '^b$']);
        expect(hasSeparator('a{0,3}', false)).toBe(false);
        expect(hasSeparator('a,b')).toBe(true);
    });
});

describe('addEntries', () => {
    it('appends new entries and reports duplicates, including within one paste', () => {
        const r = addEntries(['a'], ['b', 'a', 'b']);
        expect(r.value).toEqual(['a', 'b']);
        expect(r.added).toEqual(['b']);
        expect(r.duplicates).toEqual(['a', 'b']);
    });

    it('dedupes case-insensitively only when asked', () => {
        expect(addEntries(['Ops@Example.com'], ['ops@example.com']).value).toHaveLength(2);
        expect(addEntries(['Ops@Example.com'], ['ops@example.com'], { caseInsensitive: true }).duplicates).toEqual(['ops@example.com']);
    });

    it('stores a suggestion in its own spelling and refuses free entries when not allowed', () => {
        const suggestions = [{ value: 'SHA1withRSA' }];
        expect(addEntries([], ['sha1withrsa'], { suggestions }).value).toEqual(['SHA1withRSA']);
        expect(addEntries([], ['custom'], { suggestions }).value).toEqual(['custom']);
        const r = addEntries([], ['custom'], { suggestions, allowFree: false });
        expect(r.value).toEqual([]);
        expect(r.refused).toEqual(['custom']);
    });

    it('normalises and sorts numeric lists, keeping non-numbers last to be flagged', () => {
        expect(addEntries(['30'], ['007', '90', 'x', '30'], { numeric: true, sort: 'desc' }).value).toEqual(['90', '30', '7', 'x']);
        expect(sortNumeric(['10', '2', '1'])).toEqual(['1', '2', '10']);
        expect(normalizeNumeric('0042')).toBe('42');
        expect(normalizeNumeric('4x')).toBe('4x');
    });
});

describe('removeAt and validation', () => {
    it('removes by index', () => {
        expect(removeAt(['a', 'b', 'c'], 1)).toEqual(['a', 'c']);
    });

    it('finds invalid entries with their positions and messages', () => {
        const items = ['ops@example.com', 'nope', 'x@y'];
        expect(invalidItems(items, validateEmail)).toEqual(['nope', 'x@y']);
        expect(findProblems(items, validateEmail).map((p) => p.index)).toEqual([1, 2]);
        expect(invalidItems(['0', '5'], (v) => validatePositiveInteger(v))).toEqual(['0']);
        expect(invalidItems(items)).toEqual([]);
    });
});

describe('list shapes from the API', () => {
    it('reads arrays and comma strings, and writes comma strings', () => {
        expect(listFromValue(['a', ' b ', ''])).toEqual(['a', 'b']);
        expect(listFromValue('a@x.com, b@x.com,')).toEqual(['a@x.com', 'b@x.com']);
        expect(listFromValue([90, 30])).toEqual(['90', '30']);
        expect(listFromValue(null)).toEqual([]);
        expect(listToCsv(['a', 'b'])).toBe('a, b');
    });
});
