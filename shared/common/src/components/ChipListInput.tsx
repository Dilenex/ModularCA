import React from 'react';
import { addEntries, findProblems, hasSeparator, removeAt, splitEntries, type ChipSuggestion } from './chipList';

export type { ChipSuggestion } from './chipList';

export interface ChipListInputProps {
    value: string[];
    onChange: (next: string[]) => void;
    /** Checks one entry. An entry that fails stays in the list, marked invalid, with its message shown under the field. */
    validate?: (item: string) => string | null;
    /** Called with the invalid entries whenever that set changes, so a page can block Save. */
    onInvalidChange?: (invalid: string[]) => void;
    /** Treat entries differing only in case as duplicates. */
    caseInsensitive?: boolean;
    /** Values offered in a picker and as quick-add buttons. */
    suggestions?: ChipSuggestion[];
    /** With suggestions: false refuses anything not suggested. Default true. */
    allowFree?: boolean;
    /** Whole numbers: normalised and kept sorted (see `sort`). */
    numeric?: boolean;
    sort?: 'asc' | 'desc';
    /** False when a value may itself contain a comma (regexes): only Enter, Tab, blur and newlines separate. Default true. */
    commaSeparates?: boolean;
    /** Render entries in the monospace face (addresses, paths, patterns). */
    mono?: boolean;
    /** Force the invalid styling, e.g. when the list is required and empty. */
    invalid?: boolean;
    placeholder?: string;
    id?: string;
    'aria-describedby'?: string;
    'aria-label'?: string;
    disabled?: boolean;
}

/**
 * A list of short values edited as chips: type and press Enter, Tab or comma (or leave the field)
 * to add one; paste a comma- or newline-separated list to add several; Backspace in the empty
 * field removes the last chip. Replaces the comma-text inputs that split and re-joined their value
 * on every keystroke, which ate a separator as soon as it was typed.
 *
 * Invalid entries are kept, marked, and listed with their reason rather than refused, so pasted
 * input is never lost. Pages block Save on them through `onInvalidChange` or `invalidItems()`.
 */
export const ChipListInput: React.FC<ChipListInputProps> = ({
    value, onChange, validate, onInvalidChange, caseInsensitive, suggestions, allowFree = true,
    numeric, sort, commaSeparates = true, mono, invalid, placeholder, id, disabled,
    'aria-describedby': describedBy, 'aria-label': ariaLabel,
}) => {
    const autoId = React.useId();
    const inputId = id ?? `${autoId}-input`;
    const problemsId = `${inputId}-problems`;
    const noticeId = `${inputId}-notice`;
    const listId = `${inputId}-suggestions`;
    const inputRef = React.useRef<HTMLInputElement>(null);
    const [draft, setDraft] = React.useState('');
    const [notice, setNotice] = React.useState<string | null>(null);

    const opts = { caseInsensitive, numeric, sort, allowFree, suggestions };
    const problems = findProblems(value, validate);
    const problemIndexes = new Set(problems.map((p) => p.index));

    const invalidKey = JSON.stringify(problems.map((p) => p.item));
    const reportInvalid = React.useRef(onInvalidChange);
    reportInvalid.current = onInvalidChange;
    React.useEffect(() => { reportInvalid.current?.(JSON.parse(invalidKey)); }, [invalidKey]);

    const commit = (entries: string[]) => {
        if (entries.length === 0) return;
        const r = addEntries(value, entries, opts);
        const notes: string[] = [];
        if (r.duplicates.length) notes.push(`Already in the list: ${r.duplicates.join(', ')}.`);
        if (r.refused.length) notes.push(`Not one of the offered values: ${r.refused.join(', ')}.`);
        setNotice(notes.length ? notes.join(' ') : null);
        if (r.added.length) onChange(r.value);
    };

    const commitDraft = () => {
        if (!draft.trim()) { setDraft(''); return; }
        commit(splitEntries(draft, commaSeparates));
        setDraft('');
    };

    const onKeyDown = (e: React.KeyboardEvent<HTMLInputElement>) => {
        if (e.key === 'Enter' || (e.key === ',' && commaSeparates)) {
            e.preventDefault();
            commitDraft();
        } else if (e.key === 'Tab') {
            // Commit, then let focus move on as usual.
            if (draft.trim()) commitDraft();
        } else if (e.key === 'Backspace' && draft === '' && value.length > 0) {
            e.preventDefault();
            onChange(removeAt(value, value.length - 1));
            setNotice(null);
        } else if (e.key === 'Escape' && draft) {
            setDraft('');
        }
    };

    const onPaste = (e: React.ClipboardEvent<HTMLInputElement>) => {
        const text = e.clipboardData.getData('text');
        if (!hasSeparator(text, commaSeparates)) return;
        e.preventDefault();
        commit(splitEntries(draft + text, commaSeparates));
        setDraft('');
    };

    const onInputChange = (e: React.ChangeEvent<HTMLInputElement>) => {
        const next = e.target.value;
        setNotice(null);
        // Picking from the datalist replaces the text in one step; take the pick at once.
        const native = e.nativeEvent as InputEvent;
        const picked = suggestions?.some((s) => s.value === next) && (!native.inputType || native.inputType === 'insertReplacementText');
        if (picked) { commit([next]); setDraft(''); return; }
        if (hasSeparator(next, commaSeparates)) { commit(splitEntries(next, commaSeparates)); setDraft(''); return; }
        setDraft(next);
    };

    const remove = (index: number) => {
        onChange(removeAt(value, index));
        setNotice(null);
        inputRef.current?.focus();
    };

    const hasProblems = problems.length > 0 || !!invalid;
    const describedByAll = [describedBy, problems.length ? problemsId : null, notice ? noticeId : null].filter(Boolean).join(' ') || undefined;
    const valueKeys = new Set(value.map((v) => (caseInsensitive ? v.toLowerCase() : v)));
    const unused = (suggestions ?? []).filter((s) => !valueKeys.has(caseInsensitive ? s.value.toLowerCase() : s.value));

    return (
        <div>
            <div
                onClick={(e) => { if (e.target === e.currentTarget) inputRef.current?.focus(); }}
                className={`flex flex-wrap items-center gap-1.5 w-full min-h-[38px] px-2 py-1.5 bg-raised border rounded text-sm focus-within:border-accent focus-within:ring-1 focus-within:ring-accent ${hasProblems ? 'border-crit' : 'border-line-strong'} ${disabled ? 'bg-sunken cursor-not-allowed' : 'cursor-text'}`}
            >
                {value.length > 0 && (
                    <ul className="contents" aria-label="Entries">
                        {value.map((item, index) => {
                            const bad = problemIndexes.has(index);
                            return (
                                <li key={`${item}-${index}`}
                                    className={`inline-flex items-center gap-1 max-w-full pl-2 pr-1 py-0.5 rounded border text-xs ${mono ? 'font-mono' : ''} ${bad ? 'bg-crit-soft text-crit border-crit/40' : 'bg-sunken text-ink border-line-strong'}`}>
                                    <span className="truncate" title={item}>{item}</span>
                                    {bad && <span className="sr-only"> (invalid)</span>}
                                    {!disabled && (
                                        <button type="button" onClick={() => remove(index)} aria-label={`Remove ${item}`}
                                            className="inline-flex items-center justify-center w-4 h-4 rounded leading-none text-ink-muted hover:text-ink hover:bg-hover focus:outline-none focus-visible:ring-2 focus-visible:ring-accent">
                                            <span aria-hidden="true">×</span>
                                        </button>
                                    )}
                                </li>
                            );
                        })}
                    </ul>
                )}
                <input
                    ref={inputRef}
                    id={inputId}
                    type="text"
                    inputMode={numeric ? 'numeric' : undefined}
                    value={draft}
                    onChange={onInputChange}
                    onKeyDown={onKeyDown}
                    onPaste={onPaste}
                    onBlur={commitDraft}
                    disabled={disabled}
                    placeholder={value.length === 0 ? placeholder : undefined}
                    list={suggestions?.length ? listId : undefined}
                    aria-label={ariaLabel}
                    aria-describedby={describedByAll}
                    aria-invalid={hasProblems || undefined}
                    autoComplete="off" spellCheck={false} data-1p-ignore data-lpignore="true" data-bwignore data-form-type="other"
                    className={`flex-1 min-w-[8rem] bg-transparent text-ink placeholder-ink-faint outline-none border-0 p-0.5 disabled:cursor-not-allowed ${mono ? 'font-mono' : ''}`}
                />
                {suggestions?.length ? (
                    <datalist id={listId}>
                        {unused.map((s) => <option key={s.value} value={s.value}>{s.label && s.label !== s.value ? s.label : undefined}</option>)}
                    </datalist>
                ) : null}
            </div>
            {!disabled && unused.length > 0 && (
                <div className="mt-1.5 flex flex-wrap items-center gap-1">
                    <span className="text-xs text-ink-muted mr-1">Add:</span>
                    {unused.map((s) => (
                        <button key={s.value} type="button" onClick={() => commit([s.value])} title={s.label}
                            className="px-1.5 py-0.5 rounded border border-line text-xs text-ink-muted bg-ground hover:text-ink hover:border-ink-faint focus:outline-none focus-visible:ring-2 focus-visible:ring-accent">
                            + {s.value}
                        </button>
                    ))}
                </div>
            )}
            {problems.length > 0 && (
                <ul id={problemsId} className="mt-1 space-y-0.5 text-xs text-crit">
                    {problems.map((p) => <li key={`${p.item}-${p.index}`}>{p.message}</li>)}
                </ul>
            )}
            {notice && <p id={noticeId} role="status" className="mt-1 text-xs text-warn">{notice}</p>}
        </div>
    );
};

export default ChipListInput;
