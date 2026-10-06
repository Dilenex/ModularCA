import { describe, expect, it } from 'vitest';
import { findRows } from '@shared/tableFind';

interface Ca { name: string; type: string; space: string | null; children: number }

const rows: Ca[] = [
    { name: 'Staging CA R1', type: 'Root', space: 'Staging', children: 0 },
    { name: 'Staging CA R2', type: 'Root', space: 'Staging', children: 2 },
    { name: 'MSAE CA 1', type: 'Sub', space: 'MSAE Test', children: 0 },
    { name: 'System Signing CA', type: 'Root', space: null, children: 0 },
];
const columns = [
    { exportValue: (r: Ca) => r.type },
    { exportValue: (r: Ca) => r.name },
    { exportValue: (r: Ca) => r.space },
    { exportValue: (r: Ca) => r.children },
    {},
];
const names = (found: Ca[]) => found.map((r) => r.name);

describe('table quick-find', () => {
    it('returns the rows as given when nothing is typed', () => {
        expect(findRows(rows, columns, '')).toBe(rows);
        expect(findRows(rows, columns, '   ')).toBe(rows);
    });

    it('ignores case', () => {
        expect(names(findRows(rows, columns, 'msae'))).toEqual(['MSAE CA 1']);
    });

    it('needs every word, in any column', () => {
        expect(names(findRows(rows, columns, 'root staging'))).toEqual(['Staging CA R1', 'Staging CA R2']);
        expect(names(findRows(rows, columns, 'sub staging'))).toEqual([]);
    });

    it('does not match across two columns as if they were one word', () => {
        expect(findRows(rows, columns, 'rootstaging')).toEqual([]);
    });

    it('reads numbers and skips empty values and columns without text', () => {
        expect(names(findRows(rows, columns, '2'))).toEqual(['Staging CA R2']);
        expect(names(findRows(rows, columns, 'signing'))).toEqual(['System Signing CA']);
    });
});
