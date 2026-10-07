/**
 * The subject and SAN restrictions on an enrollment token, edited as typed rows instead of free
 * text. Pure logic, so tests/modularca.web.tests can cover it.
 *
 * The server (`EnrollmentNameRestriction`) reads a restriction as a list of patterns, any one of
 * which is enough:
 * - a DNS domain (`example.com`) matches that name and its subdomains, in the CN or a DNS SAN;
 * - a DN attribute (`O=Acme Corp`) matches a subject that carries exactly that value.
 * A SAN restriction takes domains only: no SAN can satisfy a DN pattern.
 *
 * `parseRestrictionPatterns` mirrors the server's `ParsePatterns`; the shared cases are in
 * tests/modularca.web.tests/src/adminui/enrollment-restriction-cases.json.
 */
import type { TypedEntry, TypedEntryType } from '@shared/components/typedEntryList';
import type { Validator } from '@shared/validators';
import { DN_KEYWORDS } from '@shared/generalNames';

const ATTRIBUTE_ALTERNATION = [...DN_KEYWORDS].sort((a, b) => b.length - a.length).join('|');

/** Whitespace after which a known `attribute=` starts another DN pattern (the server's `NextDnPattern`). */
const NEXT_DN_PATTERN = new RegExp(`\\s+(?=(?:${ATTRIBUTE_ALTERNATION}|(?:OID\\.)?\\d+(?:\\.\\d+)+)\\s*=)`, 'i');

const ATTRIBUTE_NAME = /^(?:[A-Za-z][A-Za-z0-9-]*|(?:OID\.)?\d+(?:\.\d+)+)$/i;
const DNS_LABEL = /^[A-Za-z0-9_]([A-Za-z0-9_-]*[A-Za-z0-9_])?$/;

/** Splits on `separator` where it is not backslash-escaped; pieces trimmed, empty ones dropped. */
const splitUnescaped = (text: string, separator: string): string[] => {
    const out: string[] = [];
    let start = 0;
    for (let i = 0; i < text.length; i++) {
        if (text[i] === '\\') { i++; continue; }
        if (text[i] !== separator) continue;
        const piece = text.slice(start, i).trim();
        if (piece) out.push(piece);
        start = i + 1;
    }
    const last = text.slice(start).trim();
    if (last) out.push(last);
    return out;
};

/**
 * The patterns the server reads from a stored restriction: split on line breaks and `;`, then on
 * unescaped commas; a piece with `=` is one DN pattern (spaces kept) unless whitespace is followed
 * by another known `attribute=`; any other piece is DNS names split on whitespace.
 */
export const parseRestrictionPatterns = (restriction: string | null | undefined): string[] => {
    if (!restriction || !restriction.trim()) return [];
    const out: string[] = [];
    for (const segment of restriction.split(/[;\r\n]/).map((s) => s.trim()).filter(Boolean)) {
        for (const piece of splitUnescaped(segment, ',')) {
            for (const part of piece.split(NEXT_DN_PATTERN)) {
                if (part.includes('=')) out.push(part.trim());
                else out.push(...part.split(/[ \t]+/).map((s) => s.trim()).filter(Boolean));
            }
        }
    }
    return out.filter(Boolean);
};

/** A domain pattern, as the server's `RestrictionError` accepts it. */
export const validateRestrictionDomain: Validator = (raw) => {
    const v = raw.trim();
    if (!v) return 'Enter a domain such as example.com.';
    if (/[\s,;=]/.test(v)) return 'One domain per row, with no spaces, commas or "=".';
    if (v.includes('*')) return 'Leave out the wildcard: a domain already covers its subdomains.';
    let host = v.replace(/\.$/, '');
    if (host.startsWith('.')) host = host.slice(1);
    if (!host || host.length > 253) return `"${v}" is not a DNS name.`;
    for (const label of host.split('.')) {
        if (!label || label.length > 63 || !DNS_LABEL.test(label)) return `"${v}" is not a DNS name.`;
    }
    return null;
};

/** A DN attribute pattern, `attribute=value`, written as one row. */
export const validateRestrictionDn: Validator = (raw) => {
    const v = raw.trim();
    const eq = v.indexOf('=');
    if (eq < 0) return 'Write the attribute and value, such as O=Acme Corp.';
    if (!ATTRIBUTE_NAME.test(v.slice(0, eq).trim())) return `"${v.slice(0, eq).trim() || '(none)'}" is not an attribute name such as O, OU or C.`;
    const value = v.slice(eq + 1).trim();
    if (!value) return 'Enter the value after "=".';
    if (/[;\r\n]/.test(value)) return 'The value cannot contain ";" or a line break.';
    if (NEXT_DN_PATTERN.test(v)) return 'One attribute per row: this value contains another "attribute=".';
    return null;
};

/** Rows for the subject restriction: a domain matched against the CN, or a DN attribute. */
export const SUBJECT_RESTRICTION_TYPES: readonly TypedEntryType[] = [
    { value: 'DNS', label: 'DNS domain', validate: validateRestrictionDomain, placeholder: 'example.com', example: 'example.com' },
    { value: 'DN', label: 'DN attribute', validate: validateRestrictionDn, placeholder: 'O=Acme Corp', example: 'O=Acme Corp' },
];

/** Rows for the SAN restriction: domains only. */
export const SAN_RESTRICTION_TYPES: readonly TypedEntryType[] = [SUBJECT_RESTRICTION_TYPES[0]];

/** Rows from a stored restriction, as the server reads it. */
export const restrictionRowsFromText = (restriction: string | null | undefined): TypedEntry[] =>
    parseRestrictionPatterns(restriction).map((p) => ({ type: p.includes('=') ? 'DN' : 'DNS', value: p }));

/**
 * The restriction text to send: one pattern per row, joined with "; ", which the server splits on.
 * A comma in a DN value is escaped so it does not separate patterns. Empty rows are dropped.
 */
export const restrictionFromRows = (rows: readonly TypedEntry[]): string =>
    rows
        .filter((r) => r.value.trim())
        .map((r) => (r.type === 'DN' ? r.value.trim().replace(/(?<!\\),/g, '\\,') : r.value.trim()))
        .join('; ');
