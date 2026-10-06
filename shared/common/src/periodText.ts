const UNITS: Array<[index: number, one: string, many: string]> = [
    [1, 'year', 'years'], [2, 'month', 'months'], [3, 'week', 'weeks'], [4, 'day', 'days'],
    [5, 'hour', 'hours'], [6, 'minute', 'minutes'], [7, 'second', 'seconds'],
];
const PERIOD = /^P(?:(\d+)Y)?(?:(\d+)M)?(?:(\d+)W)?(?:(\d+)D)?(?:T(?:(\d+)H)?(?:(\d+)M)?(?:(\d+)S)?)?$/;

/**
 * An ISO 8601 period in words: "P10M" reads "10 months", "P1Y6M" reads "1 year 6 months".
 * Text that is not such a period is returned as it is, so nothing is hidden.
 */
export function periodText(iso: string | null | undefined): string {
    if (!iso) return '';
    const m = PERIOD.exec(iso.trim());
    if (!m) return iso;
    const parts = UNITS
        .map(([i, one, many]) => ({ n: m[i] ? parseInt(m[i], 10) : 0, one, many }))
        .filter((p) => p.n > 0)
        .map((p) => `${p.n} ${p.n === 1 ? p.one : p.many}`);
    return parts.length > 0 ? parts.join(' ') : iso;
}

/** A profile's validity window: "10 months to 13 months", or the one bound that is set. */
export function periodRangeText(min: string | null | undefined, max: string | null | undefined): string {
    const from = periodText(min), to = periodText(max);
    if (from && to) return from === to ? from : `${from} to ${to}`;
    if (to) return `up to ${to}`;
    if (from) return `at least ${from}`;
    return '';
}
