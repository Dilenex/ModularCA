/**
 * DNS hostname helpers shared by every ModularCA front end.
 *
 * These live here rather than in each SPA because the same logic previously existed in three
 * places — the admin request form, the user request form, and the reissue modal — with nothing
 * keeping them in step. That shape is the most common defect in this codebase: a fix lands in one
 * copy and the siblings quietly keep the old behaviour.
 */

/**
 * True when a string is shaped like a DNS hostname that could legitimately appear in a
 * `dNSName` SAN.
 *
 * Deliberately a *shape* test, not a validity or existence test. Its job is to decide whether
 * offering "use this Common Name as a DNS SAN" would make sense — a CN is not always a hostname
 * (client and user certificates carry `CN=John Smith`), and offering to copy a personal name into
 * a DNS SAN produces a certificate that fails SAN validation with a message pointing nowhere near
 * the cause.
 *
 * Accepts a single leading `*.` wildcard label, since those are legitimate for TLS. Rejects
 * anything without a dot, so single-label intranet names do not trigger the offer — those are
 * usually a CN that was never meant to be a hostname.
 *
 * Length limits follow RFC 1035: 253 characters total, 63 per label.
 */
export function looksLikeHostname(value: string): boolean {
    const v = value.trim().toLowerCase();
    if (!v || v.length > 253 || v.includes(' ')) return false;

    const host = v.startsWith('*.') ? v.slice(2) : v;
    if (!host.includes('.')) return false;

    return host
        .split('.')
        .every(label =>
            label.length > 0 &&
            label.length <= 63 &&
            /^[a-z0-9]([a-z0-9-]*[a-z0-9])?$/.test(label));
}

/**
 * Case-insensitive comparison of two DNS names. DNS is case-insensitive, so `Example.COM` and
 * `example.com` are the same name and must not be offered as separate SANs.
 */
export function sameHostname(a: string, b: string): boolean {
    return a.trim().toLowerCase() === b.trim().toLowerCase();
}
