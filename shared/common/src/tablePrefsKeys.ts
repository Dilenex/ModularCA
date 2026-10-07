/** A table's stored layout: column widths and hidden columns, keyed by column key. */
export interface TableLayoutPrefs {
    widths: Record<string, number>;
    hidden: string[];
}

/**
 * The layout with renamed column keys (old key to new key) carried over, so a stored width or a
 * hidden flag survives a column rename. A key already stored under its new name wins.
 */
export function renameColumnKeys<T extends TableLayoutPrefs>(prefs: T, renamed?: Record<string, string>): T {
    if (!renamed) return prefs;
    const entries = Object.entries(renamed).filter(([from]) => from in prefs.widths || prefs.hidden.includes(from));
    if (entries.length === 0) return prefs;
    const widths = { ...prefs.widths };
    let hidden = [...prefs.hidden];
    for (const [from, to] of entries) {
        if (from in widths) {
            if (!(to in widths)) widths[to] = widths[from];
            delete widths[from];
        }
        if (hidden.includes(from)) {
            hidden = hidden.filter((k) => k !== from);
            if (!hidden.includes(to)) hidden.push(to);
        }
    }
    return { ...prefs, widths, hidden };
}
