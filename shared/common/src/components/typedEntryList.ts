/**
 * The logic behind TypedEntryListEditor: rows of a type plus a value, serialised as `TYPE:value`
 * (SANs, name constraints, enrollment restrictions). No React here, so it is covered by
 * tests/modularca.web.tests.
 *
 * Types are matched case-insensitively on input, and written back in the caller's canonical
 * spelling, so `email:a@b.com` read by a caller whose type is `Email` comes back as `Email:a@b.com`.
 */
import type { Validator } from '../validators';

/** One type a row can take. */
export interface TypedEntryType {
    /** The canonical spelling, written before the colon. */
    value: string;
    /** Shown in the type select. */
    label: string;
    /** Other spellings accepted when reading (compared case-insensitively), e.g. `RFC822`. */
    aliases?: string[];
    /** Checks one trimmed value of this type. */
    validate?: Validator;
    /** Placeholder for the value field. */
    placeholder?: string;
    /** A valid example value, shown in hints and the read-only view's legend. */
    example?: string;
}

/** One row. `type` is a canonical type value, the prefix as typed when unknown, or '' when none. */
export interface TypedEntry {
    type: string;
    value: string;
}

/** An entry that failed validation, with its row index. */
export interface TypedEntryProblem {
    index: number;
    entry: TypedEntry;
    message: string;
}

/** The type a spelling names (its canonical value or an alias, any case), or undefined. */
export const findEntryType = (types: readonly TypedEntryType[], spelling: string): TypedEntryType | undefined => {
    const s = spelling.trim().toLowerCase();
    if (!s) return undefined;
    return types.find((t) => t.value.toLowerCase() === s || (t.aliases ?? []).some((a) => a.toLowerCase() === s));
};

/**
 * Reads one `TYPE:value` string. A known prefix (any case) becomes the canonical type. With no
 * known prefix, `defaultType` claims the whole text when given (so a pasted `2001:db8::1` stays
 * an address); otherwise the prefix is kept as typed, or the type is '' when there is no colon.
 */
export const parseTypedEntry = (text: string, types: readonly TypedEntryType[], defaultType?: string): TypedEntry => {
    const raw = text.trim();
    const colon = raw.indexOf(':');
    if (colon > 0) {
        const known = findEntryType(types, raw.slice(0, colon));
        if (known) return { type: known.value, value: raw.slice(colon + 1).trim() };
    }
    if (defaultType !== undefined) return { type: defaultType, value: raw };
    if (colon > 0) return { type: raw.slice(0, colon).trim(), value: raw.slice(colon + 1).trim() };
    return { type: '', value: raw };
};

/** `TYPE:value`, value trimmed. */
export const formatTypedEntry = (e: TypedEntry): string => `${e.type}:${e.value.trim()}`;

/** Rows from a stored list. Null or undefined is an empty list. */
export const entriesFromList = (list: readonly string[] | null | undefined, types: readonly TypedEntryType[]): TypedEntry[] =>
    (list ?? []).filter((s) => typeof s === 'string' && s.trim()).map((s) => parseTypedEntry(s, types));

/** The list to store: one `TYPE:value` per row that has a value; blank rows are dropped. */
export const entriesToList = (rows: readonly TypedEntry[]): string[] =>
    rows.filter((r) => r.value.trim()).map(formatTypedEntry);

/** A stored list rewritten in the canonical spellings, for comparing two lists. */
export const canonicalList = (list: readonly string[] | null | undefined, types: readonly TypedEntryType[]): string[] =>
    entriesToList(entriesFromList(list, types));

/** Whether two stored lists hold the same entries in the same order, ignoring type case and spacing. */
export const sameEntryLists = (a: readonly string[] | null | undefined, b: readonly string[] | null | undefined, types: readonly TypedEntryType[]): boolean => {
    const ca = canonicalList(a, types);
    const cb = canonicalList(b, types);
    return ca.length === cb.length && ca.every((v, i) => v === cb[i]);
};

export interface TypedEntryCheckOptions {
    /** Canonical types a row may hold. A known type outside this list is flagged. Default: all. */
    allowedTypes?: readonly string[];
    /** Message for a known type that is not allowed here. */
    notAllowedMessage?: (type: TypedEntryType) => string;
}

const typeNames = (types: readonly TypedEntryType[], allowed?: readonly string[]) =>
    types.filter((t) => !allowed || allowed.includes(t.value)).map((t) => t.value).join(', ');

/**
 * Why a row is invalid, or null. A row with a blank value is never an error: it is dropped when
 * the list is stored.
 */
export const typedEntryError = (e: TypedEntry, types: readonly TypedEntryType[], opts: TypedEntryCheckOptions = {}): string | null => {
    const value = e.value.trim();
    if (!value) return null;
    if (!e.type) return `"${value}" has no type; choose one of ${typeNames(types, opts.allowedTypes)}.`;
    const type = findEntryType(types, e.type);
    if (!type) return `"${e.type}" is not a supported type here; use one of ${typeNames(types, opts.allowedTypes)}.`;
    if (opts.allowedTypes && !opts.allowedTypes.includes(type.value)) {
        return opts.notAllowedMessage?.(type) ?? `${type.label} entries are not accepted here.`;
    }
    return type.validate?.(value) ?? null;
};

/** Every invalid row, in order. */
export const findTypedEntryProblems = (rows: readonly TypedEntry[], types: readonly TypedEntryType[], opts: TypedEntryCheckOptions = {}): TypedEntryProblem[] => {
    const out: TypedEntryProblem[] = [];
    rows.forEach((entry, index) => {
        const message = typedEntryError(entry, types, opts);
        if (message) out.push({ index, entry, message });
    });
    return out;
};

/** True when any row is invalid; what a page checks to block Save. */
export const hasTypedEntryProblems = (rows: readonly TypedEntry[], types: readonly TypedEntryType[], opts: TypedEntryCheckOptions = {}): boolean =>
    findTypedEntryProblems(rows, types, opts).length > 0;

/**
 * The entries in pasted text, or null when the paste is a single plain value the field should
 * take as typed. Splits a JSON array of strings, or text with line breaks (one entry per line).
 * Commas never split: a DN or a URI may contain one.
 */
export const splitPastedEntries = (text: string): string[] | null => {
    const t = text.trim();
    if (t.startsWith('[')) {
        try {
            const parsed = JSON.parse(t);
            if (Array.isArray(parsed) && parsed.every((x) => typeof x === 'string')) {
                return parsed.map((s: string) => s.trim()).filter(Boolean);
            }
        } catch { /* not JSON: fall through */ }
    }
    if (!/[\r\n]/.test(t)) return null;
    return t.split(/\r?\n|\r/).map((s) => s.trim()).filter(Boolean);
};

/** Adds an empty row of `type`. */
export const addEntryRow = (rows: readonly TypedEntry[], type: string): TypedEntry[] => [...rows, { type, value: '' }];

/** Removes the row at `index`. */
export const removeEntryRow = (rows: readonly TypedEntry[], index: number): TypedEntry[] => rows.filter((_, i) => i !== index);

/** Replaces fields of the row at `index`. */
export const updateEntryRow = (rows: readonly TypedEntry[], index: number, patch: Partial<TypedEntry>): TypedEntry[] =>
    rows.map((r, i) => (i === index ? { ...r, ...patch } : r));

/**
 * Puts pasted entries at row `index`: each is read with that row's type as the default, the first
 * replaces the row when its value is blank, and the rest follow it.
 */
export const insertPastedEntries = (
    rows: readonly TypedEntry[], index: number, pasted: readonly string[], types: readonly TypedEntryType[],
): TypedEntry[] => {
    if (pasted.length === 0) return [...rows];
    const current = rows[index];
    const parsed = pasted.map((p) => parseTypedEntry(p, types, current?.type || undefined));
    if (!current) return [...rows, ...parsed];
    const replace = !current.value.trim();
    return [...rows.slice(0, replace ? index : index + 1), ...parsed, ...rows.slice(index + 1)];
};

/**
 * A single pasted `TYPE:value` with a known prefix, read into a row, or null. Lets a value field
 * take `DNS:example.com` pasted whole and set its type select to match.
 */
export const pastedTypedValue = (text: string, types: readonly TypedEntryType[]): TypedEntry | null => {
    const t = text.trim();
    const colon = t.indexOf(':');
    if (colon <= 0) return null;
    const type = findEntryType(types, t.slice(0, colon));
    return type ? { type: type.value, value: t.slice(colon + 1).trim() } : null;
};
