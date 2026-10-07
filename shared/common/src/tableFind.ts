/** The slice of a table column that quick-find reads: the same text the CSV export writes. */
export interface FindableColumn<Row> {
    exportValue?: (row: Row) => string | number | null | undefined;
}

/**
 * The rows in which every word typed appears in some column's text, ignoring case. Words may be
 * in different columns ("root staging"). Nothing typed returns the rows as given.
 */
export function findRows<Row>(rows: Row[], columns: FindableColumn<Row>[], typed: string): Row[] {
    const words = typed.toLowerCase().split(/\s+/).filter(Boolean);
    if (words.length === 0) return rows;
    return rows.filter((row) => {
        const text = columns.map((c) => String(c.exportValue?.(row) ?? '')).join('\n').toLowerCase();
        return words.every((w) => text.includes(w));
    });
}
