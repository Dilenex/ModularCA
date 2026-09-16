import type { SortSpec } from './tableQuery';

/**
 * Client-side sorting for tables whose rows are all in hand. Pure, so the test project
 * covers it; DataTable calls it when no `onSortChange` is supplied.
 */
export interface SortableColumn<Row> {
    key: string;
    /** Value to sort by. Falls back to `exportValue`, then to nothing (the column is unsortable). */
    sortValue?: (row: Row) => string | number | boolean | Date | null | undefined;
    exportValue?: (row: Row) => string | number | null | undefined;
}

function compare(a: unknown, b: unknown): number {
    const an = a == null || a === '';
    const bn = b == null || b === '';
    if (an && bn) return 0;
    if (an) return 1;   // empty values sort last in either direction
    if (bn) return -1;
    if (a instanceof Date || b instanceof Date) return new Date(a as any).getTime() - new Date(b as any).getTime();
    if (typeof a === 'number' && typeof b === 'number') return a - b;
    if (typeof a === 'boolean' && typeof b === 'boolean') return Number(a) - Number(b);
    return String(a).localeCompare(String(b), undefined, { numeric: true, sensitivity: 'base' });
}

/** A stable sort of `rows` by the column named in `sort`; the input order when there is no sort or no such column. */
export function sortRows<Row>(rows: Row[], columns: SortableColumn<Row>[], sort: SortSpec | null | undefined): Row[] {
    if (!sort) return rows;
    const col = columns.find(c => c.key === sort.key);
    const accessor = col?.sortValue ?? col?.exportValue;
    if (!accessor) return rows;
    const sign = sort.dir === 'desc' ? -1 : 1;
    return rows
        .map((row, i) => ({ row, i, v: accessor(row) }))
        .sort((x, y) => {
            const c = compare(x.v, y.v);
            // Empty values stay last regardless of direction; everything else flips with it.
            const xn = x.v == null || x.v === '', yn = y.v == null || y.v === '';
            if (xn !== yn) return c;
            return (c * sign) || (x.i - y.i);
        })
        .map(x => x.row);
}
