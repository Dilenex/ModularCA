import { describe, expect, it } from 'vitest';
import { sortRows } from '@shared/tableSort';

/**
 * Client-side sorting for tables that hold all their rows: numeric-aware, stable, empties
 * last in either direction, and a no-op for a column that has nothing to sort by.
 */
type Row = { name: string; n: number | null; when?: string };
const rows: Row[] = [
    { name: 'cert-10', n: 2, when: '2026-03-01' },
    { name: 'cert-2', n: null, when: '2026-01-01' },
    { name: 'cert-1', n: 1 },
    { name: 'Cert-3', n: 1, when: '2026-02-01' },
];
const columns = [
    { key: 'name', exportValue: (r: Row) => r.name },
    { key: 'n', sortValue: (r: Row) => r.n },
    { key: 'when', sortValue: (r: Row) => (r.when ? new Date(r.when) : null) },
    { key: 'actions' },
];

describe('sortRows', () => {
    it('is the input order without a sort or for an unsortable column', () => {
        expect(sortRows(rows, columns, null)).toBe(rows);
        expect(sortRows(rows, columns, { key: 'actions', dir: 'asc' })).toBe(rows);
        expect(sortRows(rows, columns, { key: 'missing', dir: 'asc' })).toBe(rows);
    });

    it('sorts strings numerically and case-insensitively', () => {
        expect(sortRows(rows, columns, { key: 'name', dir: 'asc' }).map(r => r.name)).toEqual(['cert-1', 'cert-2', 'Cert-3', 'cert-10']);
        expect(sortRows(rows, columns, { key: 'name', dir: 'desc' }).map(r => r.name)).toEqual(['cert-10', 'Cert-3', 'cert-2', 'cert-1']);
    });

    it('keeps empties last in both directions and is stable for ties', () => {
        expect(sortRows(rows, columns, { key: 'n', dir: 'asc' }).map(r => r.name)).toEqual(['cert-1', 'Cert-3', 'cert-10', 'cert-2']);
        expect(sortRows(rows, columns, { key: 'n', dir: 'desc' }).map(r => r.name)).toEqual(['cert-10', 'cert-1', 'Cert-3', 'cert-2']);
    });

    it('sorts dates by time', () => {
        expect(sortRows(rows, columns, { key: 'when', dir: 'desc' }).map(r => r.name)).toEqual(['cert-10', 'Cert-3', 'cert-2', 'cert-1']);
    });
});
