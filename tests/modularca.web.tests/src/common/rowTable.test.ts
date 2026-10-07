import { describe, expect, it } from 'vitest';
import {
    type KeyValueRow, type RowTableColumn, addTableRow, filledRows, findRowProblems, hasRowErrors, isBlankRow,
    keyValueRowsFromObject, keyValueRowsToObject, removeTableRow, updateTableRow,
} from '@shared/components/rowTable';

/** The logic behind RowTableEditor and KeyValueTable. */

interface Row extends Record<string, string | boolean> {
    name: string;
    kind: string;
    on: boolean;
    until: string;
}

const COLUMNS: RowTableColumn<Row>[] = [
    { key: 'name', label: 'Name', kind: 'text', required: true, validate: (v) => (/^[a-z]+$/.test(v) ? null : 'Lower-case letters only.'), warn: (v) => (v === 'test' ? 'Looks like a placeholder.' : null) },
    { key: 'kind', label: 'Kind', kind: 'select', options: [{ value: 'a', label: 'A' }] },
    { key: 'on', label: 'On', kind: 'checkbox' },
    { key: 'until', label: 'Until', kind: 'date' },
];
const row = (name: string, kind = '', on = false, until = ''): Row => ({ name, kind, on, until });

describe('row table: editing', () => {
    it('adds, updates and removes rows without touching the others', () => {
        const rows = [row('a'), row('b')];
        expect(addTableRow(rows, row('c')).map((r) => r.name)).toEqual(['a', 'b', 'c']);
        expect(updateTableRow(rows, 1, { name: 'x', on: true })).toEqual([row('a'), row('x', '', true)]);
        expect(removeTableRow(rows, 0)).toEqual([row('b')]);
        expect(rows).toEqual([row('a'), row('b')]);
    });

    it('treats a row with only checkboxes set as blank, and drops blank rows', () => {
        expect(isBlankRow(row('', '', true), COLUMNS)).toBe(true);
        expect(isBlankRow(row('', 'a'), COLUMNS)).toBe(false);
        expect(filledRows([row(''), row('a'), row(' ', '', true)], COLUMNS)).toEqual([row('a')]);
    });
});

describe('row table: problems', () => {
    it('reports per-cell errors and warnings, and never a blank row', () => {
        const problems = findRowProblems([row('Bad'), row(''), row('test')], COLUMNS);
        expect(problems).toEqual([
            { index: 0, column: 'name', message: 'Lower-case letters only.', tone: 'error' },
            { index: 2, column: 'name', message: 'Looks like a placeholder.', tone: 'warning' },
        ]);
        expect(hasRowErrors([row('test')], COLUMNS)).toBe(false);
        expect(hasRowErrors([row('Bad')], COLUMNS)).toBe(true);
    });

    it('requires a required cell once the row holds anything', () => {
        expect(findRowProblems([row('', 'a')], COLUMNS)).toEqual([{ index: 0, column: 'name', message: 'Enter name.', tone: 'error' }]);
    });

    it('flags each later duplicate of the key column, naming the first', () => {
        const problems = findRowProblems([row('a'), row('b'), row('a'), row('a')], COLUMNS, { duplicateKey: { column: 'name' } });
        expect(problems.map((p) => [p.index, p.message])).toEqual([[2, 'Duplicate of row 1.'], [3, 'Duplicate of row 1.']]);
    });

    it('compares duplicates through the normaliser and uses the custom message', () => {
        const problems = findRowProblems([row('ab'), row('ab', 'a')], COLUMNS, {
            duplicateKey: { column: 'name', normalize: (v) => v.toUpperCase(), message: (v, first) => `${v} again (row ${first + 1})` },
        });
        expect(problems).toEqual([{ index: 1, column: 'name', message: 'ab again (row 1)', tone: 'error' }]);
    });

    it('adds the caller row check as a row problem unless it names a column', () => {
        const problems = findRowProblems([row('a', '', true), row('b')], COLUMNS, {
            validateRow: (r) => (r.on && !r.until ? { message: 'Set a date when On is ticked.' } : null),
        });
        expect(problems).toEqual([{ index: 0, column: undefined, message: 'Set a date when On is ticked.', tone: 'error' }]);
    });
});

describe('key/value rows', () => {
    it('reads an object in key order and reports non-string values', () => {
        expect(keyValueRowsFromObject({ b: 'x', a: 'y', c: 3 })).toEqual({ rows: [{ key: 'b', value: 'x' }, { key: 'a', value: 'y' }], skipped: ['c'] });
        expect(keyValueRowsFromObject(null)).toEqual({ rows: [], skipped: [] });
        expect(keyValueRowsFromObject(['a'])).toEqual({ rows: [], skipped: [] });
    });

    it('writes trimmed entries, skipping blank rows', () => {
        const rows: KeyValueRow[] = [{ key: ' k ', value: ' v ' }, { key: '', value: '' }];
        expect(keyValueRowsToObject(rows)).toEqual({ k: 'v' });
    });
});
