/**
 * The logic behind RowTableEditor: rows of named cells (text, select, checkbox, date), each
 * column with its own check, plus optional duplicate detection on one column and a check across a
 * whole row. No React here, so it is covered by tests/modularca.web.tests.
 *
 * A row whose text, select and date cells are all blank is never an error: it is a row just added
 * or about to be removed, and callers drop it when they serialise (`filledRows`).
 */

/** One row: cell values keyed by column. Checkbox cells are booleans, every other cell a string. */
export type TableRow = Record<string, string | boolean>;

export type RowTableColumnKind = 'text' | 'select' | 'checkbox' | 'date';

/** A check on one cell: an error message, or null when the value is acceptable. */
export type CellCheck<R extends TableRow> = (value: string, row: R, index: number, rows: readonly R[]) => string | null;

export interface RowTableOption {
    value: string;
    label: string;
    disabled?: boolean;
}

export interface RowTableColumn<R extends TableRow> {
    key: Extract<keyof R, string>;
    label: string;
    kind: RowTableColumnKind;
    /** A filled row with this cell blank is an error. */
    required?: boolean;
    /** Checks a non-blank cell (text, select, date). Not called for checkboxes. */
    validate?: CellCheck<R>;
    /** Like validate, but the message is a warning: shown, and does not block. */
    warn?: CellCheck<R>;
    /** Text and date: placeholder. Select: label of the empty choice. */
    placeholder?: string;
    /** Select: the choices. A stored value not among them is kept and shown as "(not offered)". */
    options?: readonly RowTableOption[];
    /** Text: values offered as you type (a datalist), each optionally labelled. */
    suggestions?: readonly RowTableOption[];
    /** Text: monospace. */
    mono?: boolean;
    /** Text: maximum length the field accepts as typed. */
    maxLength?: number;
    /** Date: earliest and latest dates, YYYY-MM-DD. */
    min?: string;
    max?: string;
    /** CSS width for the column on wide screens, e.g. '12rem'. */
    width?: string;
    /** A line under the column header (wide) or the field label (narrow). */
    hint?: string;
}

export interface DuplicateKeyOption<R extends TableRow> {
    /** The column whose values must be distinct. */
    column: Extract<keyof R, string>;
    /** Compares values after this; default: trimmed. */
    normalize?: (value: string) => string;
    /** The message for a later duplicate; default names the first row. */
    message?: (value: string, firstIndex: number) => string;
}

export interface RowTableChecks<R extends TableRow> {
    duplicateKey?: DuplicateKeyOption<R>;
    /** A check across a filled row, e.g. one cell only makes sense with another. */
    validateRow?: (row: R, index: number, rows: readonly R[]) => RowProblemInput | null;
}

export interface RowProblemInput {
    message: string;
    tone?: 'error' | 'warning';
    /** The cell it belongs to; left out, it is a row problem. */
    column?: string;
}

/** A problem found in a row. */
export interface RowProblem {
    index: number;
    /** The column, or undefined for a problem with the row as a whole. */
    column?: string;
    message: string;
    tone: 'error' | 'warning';
}

/** The string form of a cell, '' for a missing value. */
export const cellText = (row: TableRow, key: string): string => {
    const v = row[key];
    return typeof v === 'string' ? v : '';
};

/** Whether every text, select and date cell of a row is blank (checkboxes are ignored). */
export const isBlankRow = <R extends TableRow>(row: R, columns: readonly RowTableColumn<R>[]): boolean =>
    columns.every((c) => c.kind === 'checkbox' || !cellText(row, c.key).trim());

/** The rows that are not blank, in order. */
export const filledRows = <R extends TableRow>(rows: readonly R[], columns: readonly RowTableColumn<R>[]): R[] =>
    rows.filter((r) => !isBlankRow(r, columns));

/** Appends a row. */
export const addTableRow = <R extends TableRow>(rows: readonly R[], row: R): R[] => [...rows, row];

/** Removes the row at `index`. */
export const removeTableRow = <R extends TableRow>(rows: readonly R[], index: number): R[] =>
    rows.filter((_, i) => i !== index);

/** Replaces cells of the row at `index`. */
export const updateTableRow = <R extends TableRow>(rows: readonly R[], index: number, patch: Partial<R>): R[] =>
    rows.map((r, i) => (i === index ? { ...r, ...patch } : r));

const defaultNormalize = (v: string) => v.trim();

/**
 * Every problem in the rows: per cell (required, validate, warn), duplicates of the key column
 * (each later occurrence is flagged, naming the first), and the caller's row check. Blank rows
 * are skipped.
 */
export const findRowProblems = <R extends TableRow>(
    rows: readonly R[], columns: readonly RowTableColumn<R>[], checks: RowTableChecks<R> = {},
): RowProblem[] => {
    const problems: RowProblem[] = [];
    const seen = new Map<string, number>();
    rows.forEach((row, index) => {
        if (isBlankRow(row, columns)) return;
        for (const c of columns) {
            if (c.kind === 'checkbox') continue;
            const value = cellText(row, c.key).trim();
            if (!value) {
                if (c.required) problems.push({ index, column: c.key, message: `Enter ${c.label.toLowerCase()}.`, tone: 'error' });
                continue;
            }
            const error = c.validate?.(value, row, index, rows) ?? null;
            if (error) { problems.push({ index, column: c.key, message: error, tone: 'error' }); continue; }
            const warning = c.warn?.(value, row, index, rows) ?? null;
            if (warning) problems.push({ index, column: c.key, message: warning, tone: 'warning' });
        }
        const dup = checks.duplicateKey;
        if (dup) {
            const raw = cellText(row, dup.column);
            const key = (dup.normalize ?? defaultNormalize)(raw);
            if (key) {
                const first = seen.get(key);
                if (first === undefined) seen.set(key, index);
                else problems.push({
                    index, column: dup.column, tone: 'error',
                    message: dup.message ? dup.message(raw.trim(), first) : `Duplicate of row ${first + 1}.`,
                });
            }
        }
        const rowProblem = checks.validateRow?.(row, index, rows) ?? null;
        if (rowProblem) problems.push({ index, column: rowProblem.column, message: rowProblem.message, tone: rowProblem.tone ?? 'error' });
    });
    return problems;
};

/** Whether any row has an error (warnings do not count). */
export const hasRowErrors = <R extends TableRow>(
    rows: readonly R[], columns: readonly RowTableColumn<R>[], checks: RowTableChecks<R> = {},
): boolean => findRowProblems(rows, columns, checks).some((p) => p.tone === 'error');

/* ── Key/value rows ─────────────────────────────────────────────────────────── */

/** A row of a key/value table. */
export interface KeyValueRow extends TableRow {
    key: string;
    value: string;
}

/**
 * Rows from a stored object of strings, in its key order. Entries whose value is not a string are
 * returned separately so the caller can report them.
 */
export const keyValueRowsFromObject = (obj: unknown): { rows: KeyValueRow[]; skipped: string[] } => {
    const rows: KeyValueRow[] = [];
    const skipped: string[] = [];
    if (obj && typeof obj === 'object' && !Array.isArray(obj)) {
        for (const [key, value] of Object.entries(obj as Record<string, unknown>)) {
            if (typeof value === 'string') rows.push({ key, value });
            else skipped.push(key);
        }
    }
    return { rows, skipped };
};

/** The object to store: one entry per filled row, keys and values trimmed; a later duplicate key wins. */
export const keyValueRowsToObject = (rows: readonly KeyValueRow[]): Record<string, string> => {
    const out: Record<string, string> = {};
    for (const r of rows) {
        const key = r.key.trim();
        const value = r.value.trim();
        if (!key && !value) continue;
        out[key] = value;
    }
    return out;
};
