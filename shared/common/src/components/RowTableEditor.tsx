import React from 'react';
import {
    type KeyValueRow, type RowProblem, type RowProblemInput, type RowTableChecks, type RowTableColumn, type TableRow,
    addTableRow, cellText, findRowProblems, removeTableRow, updateTableRow,
} from './rowTable';

export type { KeyValueRow, RowProblem, RowProblemInput, RowTableChecks, RowTableColumn, RowTableOption, TableRow } from './rowTable';

export interface RowTableEditorProps<R extends TableRow> {
    value: R[];
    onChange: (next: R[]) => void;
    columns: readonly RowTableColumn<R>[];
    /** A new, blank row for the add button. */
    newRow: () => R;
    /** Duplicate-key detection and a whole-row check; see `findRowProblems`. */
    checks?: RowTableChecks<R>;
    /** The caller's own problems for a row (e.g. a stored value the server no longer knows). */
    rowProblems?: (row: R, index: number) => RowProblemInput[] | undefined;
    /** Names the table for assistive technology, e.g. "Certificate policies". */
    caption: string;
    /** Names one row in the remove button, e.g. its key; default "row N". */
    rowLabel?: (row: R, index: number) => string;
    addLabel?: string;
    /** Shown when there are no rows. */
    emptyText?: React.ReactNode;
    /** Extra buttons next to the add button. */
    actions?: React.ReactNode;
    disabled?: boolean;
    id?: string;
    'aria-describedby'?: string;
}

const FIELD = 'w-full px-2.5 py-1.5 bg-raised border rounded text-sm text-ink placeholder-ink-faint focus:outline-none focus:border-accent focus:ring-1 focus:ring-accent disabled:bg-sunken disabled:text-ink-faint disabled:cursor-not-allowed';
const TONE_BORDER = { error: 'border-crit', warning: 'border-warn/40' } as const;
const TONE_TEXT = { error: 'text-crit', warning: 'text-warn' } as const;

/**
 * An editable table: one row per entry, typed columns (text, select, checkbox, date), add and
 * remove. Each cell is checked by its column, a chosen column can be required to hold distinct
 * values, and a row check can relate cells. Problems show under the cell they belong to, or under
 * the row; invalid rows stay, marked, and callers block Save with `hasRowErrors` from `rowTable.ts`.
 *
 * On wide screens it is a table with column headers; on narrow ones each row becomes a group of
 * labelled fields. A blank row is never an error, so a row just added does not shout.
 */
export function RowTableEditor<R extends TableRow>({
    value, onChange, columns, newRow, checks, rowProblems, caption, rowLabel,
    addLabel = '+ Add row', emptyText, actions, disabled, id, 'aria-describedby': describedBy,
}: RowTableEditorProps<R>): React.ReactElement {
    const autoId = React.useId();
    const baseId = id ?? autoId;
    const problems: RowProblem[] = [
        ...findRowProblems(value, columns, checks),
        ...value.flatMap((row, index) => (rowProblems?.(row, index) ?? []).map((p) => ({ index, column: p.column, message: p.message, tone: p.tone ?? 'error' as const }))),
    ];

    const firstInputs = React.useRef<(HTMLElement | null)[]>([]);
    const focusIndex = React.useRef<number | null>(null);
    React.useEffect(() => {
        if (focusIndex.current !== null) {
            firstInputs.current[focusIndex.current]?.focus();
            focusIndex.current = null;
        }
    });

    const add = () => {
        focusIndex.current = value.length;
        onChange(addTableRow(value, newRow()));
    };
    const set = (index: number, key: string, v: string | boolean) => onChange(updateTableRow(value, index, { [key]: v } as Partial<R>));

    const cellId = (index: number, key: string) => `${baseId}-r${index}-${key}`;

    return (
        <div id={baseId} role="group" aria-label={caption} aria-describedby={describedBy} className="space-y-2">
            {value.length === 0 && emptyText && <p className="text-xs text-ink-muted">{emptyText}</p>}
            {value.length > 0 && (
                <table role="table" aria-label={caption} className="block md:table w-full border-collapse text-sm">
                    <thead role="rowgroup" className="hidden md:table-header-group">
                        <tr role="row">
                            {columns.map((c) => (
                                <th key={c.key} role="columnheader" scope="col" style={c.width ? { width: c.width } : undefined}
                                    className="text-left align-bottom pr-2 pb-1 label-caps">
                                    {c.label}
                                    {c.hint && <span className="block normal-case tracking-normal font-normal text-[11px] text-ink-muted">{c.hint}</span>}
                                </th>
                            ))}
                            <th role="columnheader" scope="col" className="w-10 pb-1"><span className="sr-only">Remove</span></th>
                        </tr>
                    </thead>
                    <tbody role="rowgroup" className="block md:table-row-group space-y-2 md:space-y-0">
                        {value.map((row, index) => {
                            const rowLevel = problems.filter((p) => p.index === index && !p.column);
                            const label = rowLabel?.(row, index) || `row ${index + 1}`;
                            const rowMessageId = `${baseId}-r${index}-messages`;
                            return (
                                <React.Fragment key={index}>
                                    <tr role="row" className={`block md:table-row rounded border md:border-0 p-2 md:p-0 ${rowLevel.some((p) => p.tone === 'error') ? 'border-crit' : 'border-line'}`}>
                                        {columns.map((c, ci) => {
                                            const cellProblem = problems.find((p) => p.index === index && p.column === c.key && p.tone === 'error')
                                                ?? problems.find((p) => p.index === index && p.column === c.key);
                                            const fieldId = cellId(index, c.key);
                                            const messageId = `${fieldId}-message`;
                                            const describe = [cellProblem ? messageId : null, rowLevel.length ? rowMessageId : null].filter(Boolean).join(' ') || undefined;
                                            const border = cellProblem ? TONE_BORDER[cellProblem.tone] : 'border-line-strong';
                                            const ariaLabel = `${c.label}, ${label}`;
                                            const refFirst = ci === 0 ? (el: HTMLElement | null) => { firstInputs.current[index] = el; } : undefined;
                                            const text = cellText(row, c.key);
                                            let control: React.ReactNode;
                                            if (c.kind === 'checkbox') {
                                                control = (
                                                    <input ref={refFirst} id={fieldId} type="checkbox" checked={row[c.key] === true} disabled={disabled}
                                                        onChange={(e) => set(index, c.key, e.target.checked)} aria-label={ariaLabel} aria-describedby={describe}
                                                        className="h-4 w-4 rounded border-line-strong accent-accent disabled:cursor-not-allowed" />
                                                );
                                            } else if (c.kind === 'select') {
                                                const opts = c.options ?? [];
                                                const offered = !text || opts.some((o) => o.value === text);
                                                control = (
                                                    <select ref={refFirst} id={fieldId} value={text} disabled={disabled}
                                                        onChange={(e) => set(index, c.key, e.target.value)} aria-label={ariaLabel}
                                                        aria-invalid={cellProblem?.tone === 'error' || undefined} aria-describedby={describe}
                                                        className={`${FIELD} ${border}`}>
                                                        <option value="">{c.placeholder ?? 'Choose…'}</option>
                                                        {!offered && <option value={text}>{text} (not offered)</option>}
                                                        {opts.map((o) => <option key={o.value} value={o.value} disabled={o.disabled}>{o.label}</option>)}
                                                    </select>
                                                );
                                            } else {
                                                const listId = c.kind === 'text' && c.suggestions?.length ? `${baseId}-${c.key}-suggestions` : undefined;
                                                control = (
                                                    <input ref={refFirst} id={fieldId} type={c.kind === 'date' ? 'date' : 'text'} value={text} disabled={disabled}
                                                        onChange={(e) => set(index, c.key, e.target.value)} placeholder={c.placeholder}
                                                        min={c.kind === 'date' ? c.min : undefined} max={c.kind === 'date' ? c.max : undefined}
                                                        maxLength={c.kind === 'text' ? c.maxLength : undefined} list={listId}
                                                        aria-label={ariaLabel} aria-invalid={cellProblem?.tone === 'error' || undefined} aria-describedby={describe}
                                                        autoComplete="off" spellCheck={false} data-1p-ignore data-lpignore="true" data-bwignore data-form-type="other"
                                                        className={`${FIELD} ${c.mono ? 'font-mono' : ''} ${border}`} />
                                                );
                                            }
                                            return (
                                                <td key={c.key} role="cell" className="block md:table-cell md:align-top md:pr-2 md:py-1 pb-2 last:pb-0">
                                                    <label htmlFor={fieldId} className="block md:sr-only text-xs text-ink-muted mb-0.5">{c.label}</label>
                                                    {control}
                                                    {cellProblem && <p id={messageId} className={`mt-0.5 text-xs ${TONE_TEXT[cellProblem.tone]}`}>{cellProblem.message}</p>}
                                                </td>
                                            );
                                        })}
                                        <td role="cell" className="block md:table-cell md:align-top md:py-1 text-right">
                                            {!disabled && (
                                                <button type="button" onClick={() => onChange(removeTableRow(value, index))}
                                                    aria-label={`Remove ${label}`} title="Remove"
                                                    className="px-2 py-1.5 text-sm text-crit hover:bg-crit-soft rounded transition-colors focus:outline-none focus-visible:ring-2 focus-visible:ring-accent">
                                                    <span aria-hidden="true">&#10005;</span><span className="md:hidden ml-1 text-xs">Remove</span>
                                                </button>
                                            )}
                                        </td>
                                    </tr>
                                    {rowLevel.length > 0 && (
                                        <tr role="row" className="block md:table-row">
                                            <td role="cell" colSpan={columns.length + 1} className="block md:table-cell pb-1">
                                                <ul id={rowMessageId} className="space-y-0.5 text-xs">
                                                    {rowLevel.map((p, i) => <li key={i} className={TONE_TEXT[p.tone]}>{p.message}</li>)}
                                                </ul>
                                            </td>
                                        </tr>
                                    )}
                                </React.Fragment>
                            );
                        })}
                    </tbody>
                </table>
            )}
            {columns.filter((c) => c.kind === 'text' && c.suggestions?.length).map((c) => (
                <datalist key={c.key} id={`${baseId}-${c.key}-suggestions`}>
                    {c.suggestions!.map((s) => <option key={s.value} value={s.value}>{s.label}</option>)}
                </datalist>
            ))}
            {!disabled && (
                <div className="flex flex-wrap items-center gap-2">
                    <button type="button" onClick={add}
                        className="px-3 py-1.5 text-xs text-accent-ink border border-accent/40 rounded hover:bg-accent-soft transition-colors focus:outline-none focus-visible:ring-2 focus-visible:ring-accent">
                        {addLabel}
                    </button>
                    {actions}
                </div>
            )}
        </div>
    );
}

export interface KeyValueTableProps {
    value: KeyValueRow[];
    onChange: (next: KeyValueRow[]) => void;
    /** The key column: a text field. Its values must be distinct (compared through `normalizeKey`). */
    keyColumn: Omit<RowTableColumn<KeyValueRow>, 'key' | 'kind'>;
    /** The value column: a select when `options` is given, otherwise a text field. */
    valueColumn: Omit<RowTableColumn<KeyValueRow>, 'key' | 'kind'>;
    /** How keys compare for duplicates; default trimmed, case-sensitive. */
    normalizeKey?: (key: string) => string;
    duplicateMessage?: (key: string, firstIndex: number) => string;
    rowProblems?: RowTableEditorProps<KeyValueRow>['rowProblems'];
    caption: string;
    addLabel?: string;
    emptyText?: React.ReactNode;
    disabled?: boolean;
    id?: string;
    'aria-describedby'?: string;
}

/**
 * RowTableEditor for a map: a key text column whose values must be distinct and a value column
 * (a select when options are given). Callers convert with `keyValueRowsFromObject` and
 * `keyValueRowsToObject` from `rowTable.ts`.
 */
export const KeyValueTable: React.FC<KeyValueTableProps> = ({
    value, onChange, keyColumn, valueColumn, normalizeKey, duplicateMessage, rowProblems, caption, addLabel, emptyText, disabled, id,
    'aria-describedby': describedBy,
}) => {
    const columns: RowTableColumn<KeyValueRow>[] = [
        { ...keyColumn, key: 'key', kind: 'text', required: true },
        { ...valueColumn, key: 'value', kind: valueColumn.options ? 'select' : 'text', required: true },
    ];
    return (
        <RowTableEditor<KeyValueRow>
            value={value} onChange={onChange} columns={columns} newRow={() => ({ key: '', value: '' })}
            checks={{ duplicateKey: { column: 'key', normalize: normalizeKey, message: duplicateMessage } }}
            rowProblems={rowProblems} caption={caption} rowLabel={(r, i) => r.key.trim() || `row ${i + 1}`}
            addLabel={addLabel} emptyText={emptyText} disabled={disabled} id={id} aria-describedby={describedBy}
        />
    );
};

export default RowTableEditor;
