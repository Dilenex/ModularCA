import React from 'react';
import {
    type TypedEntry, type TypedEntryCheckOptions, type TypedEntryType,
    addEntryRow, findEntryType, findTypedEntryProblems, insertPastedEntries, parseTypedEntry, pastedTypedValue,
    removeEntryRow, splitPastedEntries, typedEntryError, updateEntryRow,
} from './typedEntryList';

export type { TypedEntry, TypedEntryType } from './typedEntryList';

/** A status the caller supplies for a row, such as the server's verdict after a check. */
export interface TypedEntryRowStatus {
    status?: 'valid' | 'warning' | 'error';
    message?: string;
}

export interface TypedEntryListEditorProps {
    value: TypedEntry[];
    onChange: (next: TypedEntry[]) => void;
    /** Every type a row may be read as, each with its label, validator, placeholder and example. */
    types: readonly TypedEntryType[];
    /** Types offered in the select (canonical values). Default: all. A row already holding another type keeps it. */
    offeredTypes?: readonly string[];
    /** Type of a new row. Default: the first offered. */
    defaultType?: string;
    /** Passed to validation, e.g. `allowedTypes` to flag a known type not accepted here. */
    check?: TypedEntryCheckOptions;
    /** False skips the per-type validators (when the caller validates elsewhere). Default true. */
    validate?: boolean;
    /** The caller's own status for a row; its message shows when the row has no local error. */
    rowStatus?: (entry: TypedEntry, index: number) => TypedEntryRowStatus | undefined;
    /** Label of the add button. */
    addLabel?: string;
    /** Shown when there are no rows. */
    emptyText?: string;
    /** Extra buttons next to the add button. */
    actions?: React.ReactNode;
    /** Called when a type select or value field loses focus. */
    onBlur?: () => void;
    disabled?: boolean;
    id?: string;
    /** Names the list for assistive technology, e.g. "Permitted names". */
    'aria-label'?: string;
    'aria-describedby'?: string;
}

const STATUS_ICON: Record<NonNullable<TypedEntryRowStatus['status']>, { glyph: string; cls: string; title: string }> = {
    valid: { glyph: '✓', cls: 'text-ok', title: 'Valid' },
    warning: { glyph: '⚠', cls: 'text-warn', title: 'Warning' },
    error: { glyph: '✗', cls: 'text-crit', title: 'Error' },
};

const BORDER: Record<NonNullable<TypedEntryRowStatus['status']>, string> = {
    valid: 'border-ok/40',
    warning: 'border-warn/40',
    error: 'border-crit',
};

const MESSAGE_TONE: Record<NonNullable<TypedEntryRowStatus['status']>, string> = {
    valid: 'text-ok',
    warning: 'text-warn',
    error: 'text-crit',
};

const FIELD = 'w-full px-3 py-2 bg-raised border rounded text-sm text-ink placeholder-ink-faint focus:outline-none focus:border-accent focus:ring-1 focus:ring-accent disabled:bg-sunken disabled:text-ink-faint disabled:cursor-not-allowed';

/**
 * Rows of a type select and a value field, edited as a list of `TYPE:value` entries: Subject
 * Alternative Names, name-constraint subtrees, enrollment restrictions. Each row is checked by
 * its type's validator, and an invalid row stays in the list, marked, with the reason under it.
 *
 * Pasting several lines (or a JSON array of strings) into a value field adds one row per entry;
 * a line that starts with a known `TYPE:` takes that type, any other takes the row's. Pasting a
 * single `DNS:example.com` into an empty field sets the type as well.
 *
 * The value is the rows themselves, so a value is never re-parsed while it is typed; callers
 * convert at their boundary with `entriesFromList` and `entriesToList` from `typedEntryList.ts`,
 * and block Save with `hasTypedEntryProblems`.
 */
export const TypedEntryListEditor: React.FC<TypedEntryListEditorProps> = ({
    value, onChange, types, offeredTypes, defaultType, check, validate = true, rowStatus,
    addLabel = '+ Add entry', emptyText, actions, onBlur, disabled, id,
    'aria-label': ariaLabel, 'aria-describedby': describedBy,
}) => {
    const autoId = React.useId();
    const baseId = id ?? autoId;
    const offered = types.filter((t) => !offeredTypes || offeredTypes.includes(t.value));
    const newRowType = defaultType ?? offered[0]?.value ?? types[0]?.value ?? '';
    const problems = validate ? findTypedEntryProblems(value, types, check) : [];
    const problemAt = new Map(problems.map((p) => [p.index, p.message]));

    const inputs = React.useRef<(HTMLInputElement | null)[]>([]);
    const focusIndex = React.useRef<number | null>(null);
    React.useEffect(() => {
        if (focusIndex.current !== null) {
            inputs.current[focusIndex.current]?.focus();
            focusIndex.current = null;
        }
    });

    const add = () => {
        focusIndex.current = value.length;
        onChange(addEntryRow(value, newRowType));
    };

    const onPaste = (index: number) => (e: React.ClipboardEvent<HTMLInputElement>) => {
        const text = e.clipboardData.getData('text');
        const entries = splitPastedEntries(text);
        if (entries) {
            e.preventDefault();
            onChange(insertPastedEntries(value, index, entries, types));
            return;
        }
        if (!value[index]?.value.trim()) {
            const typed = pastedTypedValue(text, types);
            if (typed) {
                e.preventDefault();
                onChange(updateEntryRow(value, index, typed));
            }
        }
    };

    return (
        <div id={baseId} role="group" aria-label={ariaLabel} aria-describedby={describedBy} className="space-y-2">
            {value.length === 0 && emptyText && <p className="text-xs text-ink-muted">{emptyText}</p>}
            {value.map((row, index) => {
                const known = findEntryType(types, row.type);
                const external = rowStatus?.(row, index);
                const localError = problemAt.get(index) ?? null;
                const status = localError ? 'error' : external?.status;
                const message = localError ?? external?.message ?? null;
                const messageId = `${baseId}-row-${index}-message`;
                const rowOffersOwnType = row.type && !offered.some((t) => t.value === (known?.value ?? row.type));
                return (
                    <div key={index} className="grid grid-cols-[7rem_minmax(0,1fr)_auto] items-center gap-x-2 gap-y-1">
                        <select
                            value={known?.value ?? row.type}
                            onChange={(e) => onChange(updateEntryRow(value, index, { type: e.target.value }))}
                            onBlur={onBlur}
                            disabled={disabled}
                            aria-label={`Type of entry ${index + 1}`}
                            className="w-full px-2 py-2 bg-raised border border-line-strong rounded text-sm text-ink focus:outline-none focus:border-accent disabled:bg-sunken disabled:text-ink-faint disabled:cursor-not-allowed"
                        >
                            {!row.type && <option value="">Type…</option>}
                            {rowOffersOwnType && <option value={known?.value ?? row.type}>{known?.label ?? row.type}</option>}
                            {offered.map((t) => <option key={t.value} value={t.value}>{t.label}</option>)}
                        </select>
                        <input
                            ref={(el) => { inputs.current[index] = el; }}
                            type="text"
                            value={row.value}
                            onChange={(e) => onChange(updateEntryRow(value, index, { value: e.target.value }))}
                            onPaste={onPaste(index)}
                            onBlur={onBlur}
                            disabled={disabled}
                            placeholder={known?.placeholder ?? (known ? `${known.label} value` : 'Value')}
                            aria-label={`Value of entry ${index + 1}${known ? ` (${known.label})` : ''}`}
                            aria-invalid={status === 'error' || undefined}
                            aria-describedby={message ? messageId : undefined}
                            autoComplete="off" spellCheck={false} data-1p-ignore data-lpignore="true" data-bwignore data-form-type="other"
                            className={`${FIELD} font-mono ${status ? BORDER[status] : 'border-line-strong'}`}
                        />
                        <div className="flex items-center gap-1">
                            {status && (
                                <span className={`text-sm w-4 text-center ${STATUS_ICON[status].cls}`} title={STATUS_ICON[status].title} aria-hidden="true">
                                    {STATUS_ICON[status].glyph}
                                </span>
                            )}
                            {!disabled && (
                                <button
                                    type="button"
                                    onClick={() => onChange(removeEntryRow(value, index))}
                                    aria-label={`Remove entry ${index + 1}${row.value.trim() ? ` ${row.value.trim()}` : ''}`}
                                    title="Remove"
                                    className="px-2 py-2 text-sm text-crit hover:bg-crit-soft rounded transition-colors focus:outline-none focus-visible:ring-2 focus-visible:ring-accent"
                                >
                                    <span aria-hidden="true">&#10005;</span>
                                </button>
                            )}
                        </div>
                        {message && (
                            <p id={messageId} className={`col-start-2 col-span-2 text-xs ${MESSAGE_TONE[status ?? 'error']}`}>{message}</p>
                        )}
                    </div>
                );
            })}
            {!disabled && (
                <div className="flex flex-wrap items-center gap-2">
                    <button
                        type="button"
                        onClick={add}
                        className="px-3 py-1.5 text-xs text-accent-ink border border-accent/40 rounded hover:bg-accent-soft transition-colors focus:outline-none focus-visible:ring-2 focus-visible:ring-accent"
                    >
                        {addLabel}
                    </button>
                    {actions}
                </div>
            )}
        </div>
    );
};

export interface TypedEntryListViewProps {
    /** Stored `TYPE:value` strings, or rows. */
    entries: readonly (string | TypedEntry)[];
    types: readonly TypedEntryType[];
    /** Shown when the list is empty. Default "None". */
    emptyText?: string;
    check?: TypedEntryCheckOptions;
    /** Label for the list, for assistive technology. */
    'aria-label'?: string;
}

/**
 * A read-only rendering of a `TYPE:value` list: the type's label and the value, one per line,
 * with any entry the types would refuse marked and its reason given. Used where a list is
 * reviewed rather than edited, such as a ceremony an approver is deciding on.
 */
export const TypedEntryListView: React.FC<TypedEntryListViewProps> = ({ entries, types, emptyText = 'None', check, 'aria-label': ariaLabel }) => {
    const rows = entries.map((e) => (typeof e === 'string' ? parseTypedEntry(e, types) : e));
    if (rows.length === 0) return <p className="text-xs text-ink-muted">{emptyText}</p>;
    return (
        <ul className="space-y-1" aria-label={ariaLabel}>
            {rows.map((row, i) => {
                const known = findEntryType(types, row.type);
                const problem = row.value.trim() ? typedEntryError(row, types, check) : 'This entry has no value.';
                return (
                    <li key={i} className="text-xs">
                        <div className="flex items-baseline gap-2">
                            <span className="inline-block min-w-[3.5rem] px-1.5 py-0.5 rounded border border-line-strong bg-sunken text-ink-muted font-semibold text-center">
                                {known?.label ?? (row.type || '?')}
                            </span>
                            <span className={`font-mono break-all ${problem ? 'text-crit' : 'text-ink'}`}>{row.value}</span>
                        </div>
                        {problem && <p className="mt-0.5 text-crit">{problem}</p>}
                    </li>
                );
            })}
        </ul>
    );
};

export default TypedEntryListEditor;
