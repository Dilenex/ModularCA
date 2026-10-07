/**
 * Single-value validators shared by every ModularCA front end. Pure functions, no React, so
 * tests/modularca.web.tests can cover them.
 *
 * Each `validate*` function returns an error message for the operator, or null when the value is
 * acceptable. They take one already-trimmed entry, which is what ChipListInput hands its
 * `validate` prop. The server stays authoritative; these give feedback before Save.
 */

/** A check over one entry: an error message, or null when the entry is acceptable. */
export type Validator = (value: string) => string | null;

/**
 * Loose IPv4/IPv6 address-or-CIDR shape, kept for callers that only need a quick shape test.
 * `validateIpOrCidr` is the real check.
 */
export const CIDR_REGEX = /^(\d{1,3}\.){3}\d{1,3}(\/\d{1,2})?$|^[0-9a-fA-F:]+(\/\d{1,3})?$/;

/** A bare `name@domain.tld` mailbox. Display-name forms (`Ops <ops@example.com>`) do not match. */
export const EMAIL_REGEX = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

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

/* ── IP addresses ──────────────────────────────────────────────────────────── */

/** A parsed address: family and network-order bytes (4 or 16). */
export interface ParsedIp {
    family: 4 | 6;
    bytes: number[];
}

/** Parses a strict dotted-quad IPv4 address: four decimal octets, no leading zeros. */
export function parseIpv4(value: string): number[] | null {
    const parts = value.split('.');
    if (parts.length !== 4) return null;
    const out: number[] = [];
    for (const p of parts) {
        if (!/^(0|[1-9]\d{0,2})$/.test(p)) return null;
        const n = Number(p);
        if (n > 255) return null;
        out.push(n);
    }
    return out;
}

/** Parses an IPv6 address (with `::` compression and an optional trailing dotted quad). No zone ids. */
export function parseIpv6(value: string): number[] | null {
    if (!value.includes(':') || value.includes('%')) return null;
    const halves = value.split('::');
    if (halves.length > 2) return null;

    const groups = (part: string): number[] | null => {
        if (part === '') return [];
        const out: number[] = [];
        const pieces = part.split(':');
        for (let i = 0; i < pieces.length; i++) {
            const piece = pieces[i];
            if (i === pieces.length - 1 && piece.includes('.')) {
                const v4 = parseIpv4(piece);
                if (!v4) return null;
                out.push((v4[0] << 8) | v4[1], (v4[2] << 8) | v4[3]);
            } else {
                if (!/^[0-9a-fA-F]{1,4}$/.test(piece)) return null;
                out.push(parseInt(piece, 16));
            }
        }
        return out;
    };

    const head = groups(halves[0]);
    if (!head) return null;
    // An embedded dotted quad is only valid at the very end.
    if (halves.length === 2 && halves[0].includes('.')) return null;

    let words: number[];
    if (halves.length === 2) {
        const tail = groups(halves[1]);
        if (!tail) return null;
        const missing = 8 - head.length - tail.length;
        if (missing < 1) return null;
        words = [...head, ...new Array(missing).fill(0), ...tail];
    } else {
        words = head;
    }
    if (words.length !== 8) return null;
    return words.flatMap(w => [w >> 8, w & 0xff]);
}

/** Parses an IPv4 or IPv6 address. */
export function parseIp(value: string): ParsedIp | null {
    const v4 = parseIpv4(value);
    if (v4) return { family: 4, bytes: v4 };
    const v6 = parseIpv6(value);
    if (v6) return { family: 6, bytes: v6 };
    return null;
}

/** Formats address bytes back to text; IPv6 uses `::` for the longest run of zero groups. */
export function formatIp(ip: ParsedIp): string {
    if (ip.family === 4) return ip.bytes.join('.');
    const words: number[] = [];
    for (let i = 0; i < 16; i += 2) words.push((ip.bytes[i] << 8) | ip.bytes[i + 1]);
    let bestStart = -1, bestLen = 0;
    for (let i = 0; i < 8;) {
        if (words[i] !== 0) { i++; continue; }
        let j = i;
        while (j < 8 && words[j] === 0) j++;
        if (j - i > bestLen && j - i > 1) { bestStart = i; bestLen = j - i; }
        i = j;
    }
    const hex = words.map(w => w.toString(16));
    if (bestStart < 0) return hex.join(':');
    return `${hex.slice(0, bestStart).join(':')}::${hex.slice(bestStart + bestLen).join(':')}`;
}

/** The address with every bit after `prefix` cleared. */
function networkOf(ip: ParsedIp, prefix: number): ParsedIp {
    const bytes = ip.bytes.map((b, i) => {
        const keep = Math.max(0, Math.min(8, prefix - i * 8));
        return keep === 0 ? 0 : b & (0xff << (8 - keep)) & 0xff;
    });
    return { family: ip.family, bytes };
}

/**
 * An IPv4 or IPv6 address, or a CIDR range (`10.0.0.0/8`, `2001:db8::/32`).
 *
 * With `requireNetworkAddress`, a range whose address has bits set past the prefix
 * (`10.0.0.1/8`) is refused and the intended network is suggested. OpenSSH rejects such ranges
 * in `source-address`; the whitelist matcher accepts them, so it is off by default.
 */
export function validateIpOrCidr(value: string, opts: { requireNetworkAddress?: boolean } = {}): string | null {
    const v = value.trim();
    if (!v) return 'Enter an address or CIDR range.';
    if (v === '*' || v.includes('*')) return 'Wildcards are not supported; use a CIDR range such as 0.0.0.0/0.';
    const parts = v.split('/');
    if (parts.length > 2) return `"${v}" has more than one "/".`;
    const ip = parseIp(parts[0]);
    if (!ip) return `"${parts[0]}" is not an IPv4 or IPv6 address.`;
    if (parts.length === 1) return null;

    const max = ip.family === 4 ? 32 : 128;
    if (!/^\d{1,3}$/.test(parts[1]) || Number(parts[1]) > max) {
        return `The prefix length after "/" must be a number from 0 to ${max} for IPv${ip.family}.`;
    }
    const prefix = Number(parts[1]);
    if (opts.requireNetworkAddress) {
        const net = networkOf(ip, prefix);
        if (net.bytes.some((b, i) => b !== ip.bytes[i])) {
            return `"${v}" has bits set after the /${prefix} prefix; use ${formatIp(net)}/${prefix}.`;
        }
    }
    return null;
}

/* ── Other single-value checks ─────────────────────────────────────────────── */

/** A bare email address, `name@example.com`. */
export function validateEmail(value: string): string | null {
    const v = value.trim();
    if (!v) return 'Enter an email address.';
    if (v.length > 254 || !EMAIL_REGEX.test(v)) return `"${v}" is not an email address; use the form name@example.com.`;
    return null;
}

/** Hosts for which plain-http origins are accepted, matching the server's CORS startup check. */
const LOCAL_HOSTS = new Set(['localhost', '127.0.0.1', '[::1]']);

/**
 * A browser origin: `https://host` with an optional port, and nothing after it.
 *
 * Browsers send the Origin header without a path or trailing slash, and the server compares
 * origins as strings, so `https://app.example.com/` would never match. Plain http is accepted
 * only for localhost, 127.0.0.1 and [::1] (unless `allowHttpLocalhost` is false), as the server
 * enforces at startup.
 */
export function validateOrigin(value: string, opts: { allowHttpLocalhost?: boolean } = {}): string | null {
    const allowHttpLocalhost = opts.allowHttpLocalhost ?? true;
    const v = value.trim();
    if (!v) return 'Enter an origin such as https://app.example.com.';
    if (v.includes('*')) return 'Wildcards are not allowed; list each origin.';
    const m = /^([a-zA-Z][a-zA-Z0-9+.-]*):\/\/([^/?#]*)(.*)$/.exec(v);
    if (!m) return `"${v}" is not an origin; use https://host or https://host:port.`;
    const [, scheme, authority, rest] = m;
    if (rest === '/') return `Remove the trailing "/": browsers send the origin as ${scheme}://${authority}.`;
    if (rest) return 'An origin has no path, query or fragment; use https://host or https://host:port.';
    if (authority.includes('@')) return 'An origin cannot carry a user name or password.';

    let url: URL;
    try { url = new URL(v); } catch { return `"${v}" is not a valid URL.`; }
    if (!url.hostname) return 'The origin has no host.';

    const s = scheme.toLowerCase();
    if (s === 'https') return null;
    if (s === 'http') {
        if (allowHttpLocalhost && LOCAL_HOSTS.has(url.hostname.toLowerCase())) return null;
        return allowHttpLocalhost
            ? 'Use https://; plain http is accepted only for localhost, 127.0.0.1 and [::1].'
            : 'Use https://.';
    }
    return `"${scheme}" is not a web scheme; use https://.`;
}

/**
 * A URL path prefix such as `/api/v1/health`. Matched as a plain prefix, so wildcards and query
 * strings would never match anything.
 */
export function validatePathPrefix(value: string): string | null {
    const v = value.trim();
    if (!v) return 'Enter a path prefix such as /health.';
    if (!v.startsWith('/')) return `"${v}" must start with "/", e.g. /${v.replace(/^\/*/, '')}.`;
    if (/\s/.test(v)) return 'A path prefix cannot contain spaces.';
    if (v.includes('*')) return 'Wildcards are not supported; a prefix already covers every path under it.';
    if (/[?#]/.test(v)) return 'A path prefix has no query string or fragment.';
    if (v.includes('://')) return 'Enter only the path, without scheme or host.';
    return null;
}

/** An absolute file path on Linux (`/etc/...`) or Windows (`C:\...`, `\\server\share\...`). */
export function validateAbsoluteFilePath(value: string): string | null {
    const v = value.trim();
    if (!v) return 'Enter a file path.';
    if (/[\u0000-\u001f]/.test(v)) return 'The path contains a control character.';
    if (v.startsWith('/') || /^[A-Za-z]:[\\/]/.test(v) || /^\\\\[^\\]+\\[^\\]+/.test(v)) return null;
    return `"${v}" is not an absolute path; use e.g. /etc/modularca/ca.pem or C:\\ModularCA\\ca.pem.`;
}

/**
 * A dotted-decimal object identifier such as `1.3.6.1.4.1.311.20.2.2`: at least two arcs, the
 * first 0, 1 or 2, and under arcs 0 and 1 a second arc of at most 39 (X.660).
 */
export function validateOid(value: string): string | null {
    const v = value.trim();
    if (!v) return 'Enter an OID.';
    if (!/^\d+(\.\d+)+$/.test(v)) return `"${v}" is not a dotted OID such as 1.3.6.1.4.1.311.20.2.2.`;
    const arcs = v.split('.');
    if (arcs.some(a => a.length > 1 && a.startsWith('0'))) return 'OID arcs cannot have leading zeros.';
    if (!['0', '1', '2'].includes(arcs[0])) return 'An OID starts with 0, 1 or 2.';
    if (arcs[0] !== '2' && Number(arcs[1]) > 39) return `Under arc ${arcs[0]} the second arc is at most 39.`;
    return null;
}

/**
 * A regular expression that compiles. This runs the browser's engine; the server compiles the
 * pattern again with .NET, whose syntax differs in places (inline options, named groups), so
 * passing here is a first check rather than a guarantee.
 */
export function validateRegex(value: string): string | null {
    if (!value.trim()) return 'Enter a pattern.';
    try {
        new RegExp(value);
        return null;
    } catch (e) {
        const reason = e instanceof Error ? e.message.replace(/^Invalid regular expression: /, '') : 'it does not compile';
        return `Not a valid regular expression (${reason}). The server uses .NET regex, which may differ from this check.`;
    }
}

/** A whole number from 1 to `max` (default the largest 32-bit int, the server's `int`). */
export function validatePositiveInteger(value: string, max = 2147483647): string | null {
    const v = value.trim();
    if (!/^\d+$/.test(v)) return `"${v}" is not a whole number.`;
    const n = Number(v);
    if (n < 1) return 'Enter a number greater than 0.';
    if (n > max) return `Enter a number no greater than ${max}.`;
    return null;
}
