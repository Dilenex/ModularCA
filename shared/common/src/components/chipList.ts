/**
 * The logic behind ChipListInput: splitting typed or pasted text into entries, de-duplicating,
 * sorting numeric lists and finding invalid entries. No React here, so it is covered by
 * tests/modularca.web.tests.
 */

/** One suggested value; `label` is shown in the picker when it differs from the value. */
export interface ChipSuggestion {
    value: string;
    label?: string;
}

export interface ChipListOptions {
    /** Treat `Foo` and `foo` as the same entry. */
    caseInsensitive?: boolean;
    /** Entries are whole numbers: normalised (`007` → `7`) and kept sorted. */
    numeric?: boolean;
    /** Sort direction in numeric mode. Default ascending. */
    sort?: 'asc' | 'desc';
    /** With suggestions: false refuses anything not suggested. Default true. */
    allowFree?: boolean;
    suggestions?: ChipSuggestion[];
}

/** Result of adding entries: the new list, plus what was skipped and why. */
export interface ChipAddResult {
    value: string[];
    added: string[];
    /** Already in the list (or repeated within the same paste). */
    duplicates: string[];
    /** Not among the suggestions while `allowFree` is false. */
    refused: string[];
}

/** An entry that failed `validate`, with its position and message. */
export interface ChipProblem {
    item: string;
    index: number;
    message: string;
}

/**
 * Splits typed or pasted text into trimmed, non-empty entries: on line breaks, and on commas
 * unless `commaSeparates` is false (for values that may contain one, such as regexes).
 */
export const splitEntries = (text: string, commaSeparates = true): string[] =>
    text.split(commaSeparates ? /[,\r\n]+/ : /[\r\n]+/).map((s) => s.trim()).filter(Boolean);

/** Whether text contains a separator that should turn it into entries. */
export const hasSeparator = (text: string, commaSeparates = true): boolean =>
    (commaSeparates ? /[,\r\n]/ : /[\r\n]/).test(text);

/** Reads a list held as an array or as a comma-separated string (the shapes the API uses). */
export const listFromValue = (value: unknown): string[] => {
    if (Array.isArray(value)) return value.map((v) => String(v).trim()).filter(Boolean);
    if (typeof value === 'string') return splitEntries(value);
    return [];
};

/** Joins a list for a server field that stores a comma-separated string. */
export const listToCsv = (items: string[]): string => items.join(', ');

const keyOf = (item: string, caseInsensitive?: boolean) => (caseInsensitive ? item.toLowerCase() : item);

/** `007` → `7`; anything that is not all digits is left as typed so it can be flagged. */
export const normalizeNumeric = (item: string): string =>
    /^\d+$/.test(item) ? String(Number(item)) : item;

/** Numeric order, with entries that are not numbers kept after the numbers in their typed order. */
export const sortNumeric = (items: string[], dir: 'asc' | 'desc' = 'asc'): string[] => {
    const nums = items.filter((i) => /^\d+$/.test(i)).sort((a, b) => (dir === 'asc' ? Number(a) - Number(b) : Number(b) - Number(a)));
    return [...nums, ...items.filter((i) => !/^\d+$/.test(i))];
};

/**
 * Adds entries to a list. Duplicates (against the list and within `incoming`) are skipped, and
 * with `allowFree: false` so are entries that are not suggested; a suggestion typed in another
 * case is stored with the suggestion's spelling.
 */
export const addEntries = (current: string[], incoming: string[], opts: ChipListOptions = {}): ChipAddResult => {
    const value = [...current];
    const seen = new Set(current.map((c) => keyOf(c, opts.caseInsensitive)));
    const result: ChipAddResult = { value, added: [], duplicates: [], refused: [] };
    const suggestions = opts.suggestions ?? [];

    for (const raw of incoming) {
        let item = raw.trim();
        if (!item) continue;
        if (opts.numeric) item = normalizeNumeric(item);
        const suggested = suggestions.find((s) => s.value.toLowerCase() === item.toLowerCase());
        if (suggested) item = suggested.value;
        else if (suggestions.length > 0 && opts.allowFree === false) { result.refused.push(item); continue; }

        const key = keyOf(item, opts.caseInsensitive);
        if (seen.has(key)) { result.duplicates.push(item); continue; }
        seen.add(key);
        value.push(item);
        result.added.push(item);
    }
    if (opts.numeric) result.value = sortNumeric(value, opts.sort);
    return result;
};

/** Removes the entry at `index`. */
export const removeAt = (current: string[], index: number): string[] => current.filter((_, i) => i !== index);

/** Every entry `validate` rejects, in list order. */
export const findProblems = (items: string[], validate?: (item: string) => string | null): ChipProblem[] => {
    if (!validate) return [];
    const out: ChipProblem[] = [];
    items.forEach((item, index) => {
        const message = validate(item);
        if (message) out.push({ item, index, message });
    });
    return out;
};

/** The entries `validate` rejects; what a page checks to block Save. */
export const invalidItems = (items: string[], validate?: (item: string) => string | null): string[] =>
    findProblems(items, validate).map((p) => p.item);
