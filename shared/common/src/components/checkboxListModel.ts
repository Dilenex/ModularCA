/*
 * Pure helpers behind CheckboxList. No React here, so tests/modularca.web.tests can cover them.
 */

export interface CheckboxOption {
    value: string;
    label: string;
    /** One line under the label saying what the option does. */
    description?: string;
    /** Small monospace text after the label, such as an OID. */
    detail?: string;
    disabled?: boolean;
    /** Tooltip and screen-reader text for a disabled option. */
    disabledReason?: string;
    /** Marks the option as part of a conflict the field reports below. */
    tone?: 'warn';
    /** A short status pill after the label, such as "Enabled". */
    badge?: { label: string; tone: 'ok' | 'warn' | 'muted' };
}

export interface CheckboxGroup {
    id: string;
    label: string;
    options: readonly CheckboxOption[];
}

/** A ceiling list: empty means every value is allowed. */
export type CeilingMode = 'any' | 'only';

/**
 * Ticks or unticks one value. A new value is appended and the rest keep their order, so a list
 * that is opened and saved without edits comes back byte-for-byte.
 */
export const toggleValue = (values: readonly string[], value: string, on: boolean): string[] => {
    if (on) return values.includes(value) ? [...values] : [...values, value];
    return values.filter((v) => v !== value);
};

/** Whether a group's enabled options are all, some or none ticked. */
export const groupState = (values: readonly string[], options: readonly CheckboxOption[]): 'all' | 'some' | 'none' => {
    const enabled = options.filter((o) => !o.disabled);
    const ticked = enabled.filter((o) => values.includes(o.value)).length;
    if (ticked === 0) return 'none';
    return ticked === enabled.length ? 'all' : 'some';
};

/** Ticks or unticks every enabled option of a group. */
export const setGroup = (values: readonly string[], options: readonly CheckboxOption[], on: boolean): string[] => {
    const enabled = options.filter((o) => !o.disabled).map((o) => o.value);
    if (on) return [...values, ...enabled.filter((v) => !values.includes(v))];
    return values.filter((v) => !enabled.includes(v));
};

/** Stored values that no option offers. They are shown and kept, never silently dropped. */
export const unknownValues = (values: readonly string[], options: readonly CheckboxOption[]): string[] => {
    const offered = new Set(options.map((o) => o.value));
    return values.filter((v, i) => !offered.has(v) && values.indexOf(v) === i);
};

export const flattenGroups = (groups: readonly CheckboxGroup[]): CheckboxOption[] => groups.flatMap((g) => g.options);

/** A ceiling shows "Only these" as soon as it holds a value, or once the operator chose it. */
export const ceilingModeOf = (values: readonly string[], onlyChosen: boolean): CeilingMode =>
    values.length > 0 || onlyChosen ? 'only' : 'any';

/** "Only these" with nothing ticked saves as an empty list, which the server reads as unrestricted. */
export const ceilingEmptyOnly = (mode: CeilingMode, values: readonly string[]): boolean =>
    mode === 'only' && values.length === 0;

/** The mode a stored ceiling list loads in: empty is Any. */
export const ceilingModeFromList = (values: readonly string[]): CeilingMode => (values.length > 0 ? 'only' : 'any');

/** The list a ceiling saves: Any saves empty, whatever is still ticked underneath. */
export const ceilingListOut = (mode: CeilingMode, values: readonly string[]): string[] => (mode === 'any' ? [] : [...values]);
