/**
 * Type sets and per-type checks for the general names the console edits as `TYPE:value` rows:
 * name-constraint subtrees (RFC 5280 §4.2.1.10) and Subject Alternative Names. Pure functions, so
 * tests/modularca.web.tests can cover them.
 *
 * The name-constraint checks mirror `NameConstraintRules` on the server, which refuses the same
 * entries at save; tests/modularca.web.tests/src/common/name-constraint-cases.json holds the
 * cases both test suites run. The SAN checks follow the issuance switch in
 * `CertificateBuilderService`, which stays authoritative.
 */
import { type ParsedIp, type Validator, formatIp, parseIp, parseIpv4, validateEmail } from './validators';
import {
    type TypedEntry, type TypedEntryType, entriesFromList, entriesToList, hasTypedEntryProblems, parseTypedEntry, typedEntryError,
} from './components/typedEntryList';

/* ── Shared pieces ─────────────────────────────────────────────────────────── */

const CONTROL = /[\u0000-\u001f\u007f]/;
const DNS_LABEL = /^[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?$/;
const DOTTED_QUAD = /^\d+(\.\d+){3}$/;

/**
 * A host name or, with `allowLeadingDot`, a `.domain`: LDH labels of 1 to 63 characters, 253 in
 * all, no trailing dot, no wildcard. `kind` names the field in messages.
 */
const domainError = (value: string, kind: string, allowLeadingDot: boolean): string | null => {
    let host = value;
    if (host.startsWith('.')) {
        if (!allowLeadingDot) return `"${value}" cannot start with a dot here.`;
        host = host.slice(1);
    }
    if (!host) return `"${value}" names no domain.`;
    if (host.includes('*')) return `Wildcards are not used in name constraints; write .example.com to cover every subdomain of example.com.`;
    if (host.endsWith('.')) return `Remove the trailing dot from "${value}".`;
    if (host.length > 253) return `"${value}" is longer than 253 characters.`;
    if (DOTTED_QUAD.test(host)) return `"${value}" is an address, not a ${kind}; use an IP entry with a prefix, e.g. IP:10.0.0.0/8.`;
    for (const label of host.split('.')) {
        if (!label) return `"${value}" has an empty label (two dots in a row).`;
        if (label.length > 63) return `The label "${label}" is longer than 63 characters.`;
        if (!DNS_LABEL.test(label)) {
            return `"${label}" is not a valid DNS label: letters, digits and hyphens only, not starting or ending with a hyphen (use the xn-- form for international names).`;
        }
    }
    return null;
};

/* ── Name constraints ──────────────────────────────────────────────────────── */

/**
 * DNS subtree: `example.com` (the host and every subdomain) or `.example.com` (subdomains only,
 * the convention OpenSSL and this server's issuance check follow).
 */
export const validateNcDns: Validator = (v) => domainError(v.trim(), 'DNS name', true);

/** Bytes of a prefix-length mask. */
const maskBytes = (len: number, prefix: number): number[] =>
    Array.from({ length: len }, (_, i) => {
        const bits = Math.max(0, Math.min(8, prefix - i * 8));
        return bits === 0 ? 0 : (0xff << (8 - bits)) & 0xff;
    });

/** The prefix length of a contiguous mask, or null when the mask has a gap. */
const prefixOfMask = (bytes: number[]): number | null => {
    let prefix = 0;
    let ended = false;
    for (const b of bytes) {
        for (let bit = 7; bit >= 0; bit--) {
            const set = (b >> bit) & 1;
            if (set && ended) return null;
            if (set) prefix++;
            else ended = true;
        }
    }
    return prefix;
};

/**
 * IP subtree: a range written `address/prefix` (`10.0.0.0/8`, `2001:db8::/32`) or
 * `address/netmask` (`10.0.0.0/255.0.0.0`); the server encodes both the same way. The netmask
 * must be contiguous and the address must be the network address. A bare address is refused:
 * RFC 5280 encodes an IP constraint as address plus mask, and a bare address produced a 4-byte
 * value relying parties reject.
 */
export const validateNcIp: Validator = (raw) => {
    const v = raw.trim();
    const parts = v.split('/');
    if (parts.length === 1) return `"${v}" is a single address; IP constraints are ranges, so add a prefix length, e.g. ${v}/${v.includes(':') ? 128 : 32}.`;
    if (parts.length > 2) return `"${v}" has more than one "/".`;
    if (parts[0].includes('%')) return 'An IPv6 zone (%…) is not allowed.';
    const ip = parseIp(parts[0]);
    if (!ip) return `"${parts[0]}" is not an IPv4 or IPv6 address.`;
    const len = ip.bytes.length;
    const max = len * 8;
    let prefix: number;
    if (/^(0|[1-9]\d{0,2})$/.test(parts[1])) {
        prefix = Number(parts[1]);
        if (prefix > max) return `The prefix length must be 0 to ${max} for IPv${ip.family}.`;
    } else {
        const mask = ip.family === 4 ? parseIpv4(parts[1]) : parseIp(parts[1])?.family === 6 ? parseIp(parts[1])!.bytes : null;
        if (!mask) return `After "/" give a prefix length (e.g. /8) or an IPv${ip.family} netmask (e.g. ${ip.family === 4 ? '255.0.0.0' : 'ffff:ffff::'}).`;
        const p = prefixOfMask(mask);
        if (p === null) return `"${parts[1]}" is not a contiguous netmask.`;
        prefix = p;
    }
    const mask = maskBytes(len, prefix);
    const net: ParsedIp = { family: ip.family, bytes: ip.bytes.map((b, i) => b & mask[i]) };
    if (net.bytes.some((b, i) => b !== ip.bytes[i])) {
        return `"${v}" has bits set after the /${prefix} prefix; use ${formatIp(net)}/${prefix}.`;
    }
    return null;
};

const MAILBOX_LOCAL = /^[^\s@<>()[\],;:"\\]+$/;

/**
 * Email (rfc822Name) subtree, in the three forms RFC 5280 §4.2.1.10 defines: a mailbox
 * (`admin@example.com`), every mailbox at a host (`example.com`), or every mailbox in a domain's
 * subdomains (`.example.com`). `@example.com` is none of these: OpenSSL reads it as the host,
 * while Go refuses to parse a certificate carrying it.
 */
export const validateNcEmail: Validator = (raw) => {
    const v = raw.trim();
    const at = v.indexOf('@');
    if (at < 0) return domainError(v, 'mail domain', true);
    if (at === 0) {
        const host = v.slice(1);
        return `"${v}" is not a valid email constraint; write ${host || 'example.com'} for every mailbox at that host, or .${host || 'example.com'} for its subdomains.`;
    }
    if (v.indexOf('@', at + 1) >= 0) return `"${v}" has more than one "@".`;
    if (!MAILBOX_LOCAL.test(v.slice(0, at))) return `"${v}" is not a bare mailbox; use the form admin@example.com.`;
    return domainError(v.slice(at + 1), 'mail domain', false);
};

/**
 * URI subtree: the host part only, `example.com` or `.example.com`. RFC 5280 constrains the host
 * of a URI, so `https://example.com` would never match anything.
 */
export const validateNcUri: Validator = (raw) => {
    const v = raw.trim();
    if (/[/:?#@[\]]/.test(v)) return `Give only the host (example.com) or a domain (.example.com), not a URL; a URI constraint names the host.`;
    return domainError(v, 'host name', true);
};

/** Attribute keywords the server's DN parser (BouncyCastle `X509Name.DefaultLookup`) knows, lower case. */
export const DN_KEYWORDS: ReadonlySet<string> = new Set([
    'businesscategory', 'c', 'cn', 'countryofcitizenship', 'countryofresidence', 'dateofbirth', 'dc', 'description',
    'dn', 'dnq', 'dnqualifier', 'e', 'emailaddress', 'gender', 'generation', 'givenname', 'initials',
    'jurisdictioncountry', 'jurisdictionlocality', 'jurisdictionstate', 'l', 'name', 'nameatbirth', 'o',
    'organizationidentifier', 'ou', 'placeofbirth', 'postaladdress', 'postalcode', 'pseudonym', 'role', 's',
    'serialnumber', 'sn', 'st', 'street', 'surname', 't', 'telephonenumber', 'uid', 'uniqueidentifier',
    'unstructuredaddress', 'unstructuredname',
]);

const dnKeyError = (key: string): string | null => {
    const k = key.trim();
    if (!k) return 'A DN component has no attribute name before "=".';
    if (DN_KEYWORDS.has(k.toLowerCase()) || /^(oid\.)?\d+(\.\d+)+$/i.test(k)) return null;
    return `"${k}" is not a DN attribute the server knows; use CN, O, OU, C, L, ST, DC and the like, or a dotted OID.`;
};

const dnMaxLength = (field: string): number => {
    const f = field.trim().toUpperCase();
    return f === 'CN' ? 64 : 128;
};

/** The server's per-value rule (`DnComponentSanitizer.Sanitize`). */
const dnValueError = (field: string, value: string): string | null => {
    const t = value.trim();
    if (!t) return `The ${field.trim() || 'DN'} value is empty.`;
    if (t.length > dnMaxLength(field)) return `The ${field.trim()} value is longer than ${dnMaxLength(field)} characters.`;
    if (CONTROL.test(t)) return `The ${field.trim()} value contains a control character.`;
    if (/[\u202a-\u202e\u2066-\u2069]/.test(t)) return `The ${field.trim()} value contains a bidirectional override character.`;
    if (/[\ud800-\udbff](?![\udc00-\udfff])|(?<![\ud800-\udbff])[\udc00-\udfff]/.test(t)) return `The ${field.trim()} value contains an unpaired surrogate.`;
    return null;
};

/**
 * DN (directoryName) subtree, RFC 4514 style: `O=Acme,C=US`, every RDN `attribute=value`. The
 * server splits on every comma before parsing, so a comma inside a value (escaped or quoted) is
 * refused there and here.
 */
export const validateNcDn: Validator = (raw) => {
    const v = raw.trim();
    for (const part of v.split(',')) {
        const eq = part.indexOf('=');
        if (eq <= 0) return `DN component "${part.trim()}" is missing a "=" (a comma inside a value is not supported).`;
        const field = part.slice(0, eq);
        const keyErr = dnKeyError(field);
        if (keyErr) return keyErr;
        const rest = part.slice(eq + 1);
        const valErr = dnValueError(field, rest);
        if (valErr) return valErr;
        // A multi-valued RDN (CN=a+O=b): every further piece must itself be attribute=value.
        const pieces = rest.split(/(?<!\\)\+/);
        for (const piece of pieces.slice(1)) {
            const peq = piece.indexOf('=');
            if (peq <= 0) return `"${part.trim()}" has a "+" not followed by attribute=value; escape it as \\+.`;
            const pk = dnKeyError(piece.slice(0, peq));
            if (pk) return pk;
        }
    }
    return null;
};

/** The five name-constraint types, as `ParseSubtrees` spells them. */
export const NAME_CONSTRAINT_TYPES: readonly TypedEntryType[] = [
    { value: 'DNS', label: 'DNS', validate: validateNcDns, placeholder: 'example.com or .example.com', example: '.example.com' },
    { value: 'IP', label: 'IP', validate: validateNcIp, placeholder: '10.0.0.0/8', example: '10.0.0.0/8' },
    { value: 'EMAIL', label: 'Email', validate: validateNcEmail, placeholder: 'example.com, .example.com or admin@example.com', example: 'example.com' },
    { value: 'URI', label: 'URI', validate: validateNcUri, placeholder: 'host.example.com or .example.com', example: '.example.com' },
    { value: 'DN', label: 'DN', validate: validateNcDn, placeholder: 'O=Example,C=US', example: 'O=Example,C=US' },
];

/** The help text both name-constraint editors show. */
export const NAME_CONSTRAINTS_HINT =
    'Each entry is a type and a value: DNS example.com (the host and its subdomains) or .example.com (subdomains only); '
    + 'IP 10.0.0.0/8 or 10.0.0.0/255.0.0.0; Email admin@example.com, example.com or .example.com; '
    + 'URI host.example.com or .example.com (the host, not a URL); DN O=Example,C=US. Wildcards are not supported. Leave both lists empty for no constraint.';

/** Constraints are written into CA certificates only; said next to both editors. */
export const NAME_CONSTRAINTS_CA_ONLY =
    'Name constraints are written only into CA certificates. A leaf certificate issued through this profile never carries them.';

/** Why a stored constraint list holds non-DNS entries this server will not issue under. */
export const NAME_CONSTRAINTS_NON_DNS_WARNING =
    'ModularCA enforces only DNS constraints when it issues. A CA run on this server whose certificate carries IP, Email, URI or DN constraints refuses to issue anything until they are removed.';

/**
 * Reads a stored name-constraint field into a list: a JSON array (as a string or already parsed),
 * or null/blank for none. Text that is not a JSON array of strings is returned as one entry, so
 * the editor shows it (flagged) rather than losing it.
 */
export const nameConstraintListFromStored = (stored: unknown): string[] => {
    if (Array.isArray(stored)) return stored.filter((s): s is string => typeof s === 'string');
    if (typeof stored !== 'string' || !stored.trim()) return [];
    try {
        const parsed = JSON.parse(stored);
        if (Array.isArray(parsed) && parsed.every((x) => typeof x === 'string')) return parsed;
    } catch { /* fall through */ }
    return [stored.trim()];
};

/** Editor rows from a stored name-constraint field (JSON string, array, or null). */
export const nameConstraintRowsFromStored = (stored: unknown): TypedEntry[] =>
    entriesFromList(nameConstraintListFromStored(stored), NAME_CONSTRAINT_TYPES);

/** The list to send for a `List<string>` body; rows without a value are dropped. */
export const nameConstraintRowsToList = (rows: readonly TypedEntry[]): string[] => entriesToList(rows);

/** The JSON-array string a signing profile stores, or null when there are no entries. */
export const nameConstraintRowsToJson = (rows: readonly TypedEntry[]): string | null => {
    const list = entriesToList(rows);
    return list.length > 0 ? JSON.stringify(list) : null;
};

/** True when any row would be refused by the server. */
export const nameConstraintRowsInvalid = (rows: readonly TypedEntry[]): boolean => hasTypedEntryProblems(rows, NAME_CONSTRAINT_TYPES);

/** True when any row with a value is not DNS: the CA carrying it will not issue (see the warning). */
export const hasNonDnsConstraint = (rows: readonly TypedEntry[]): boolean =>
    rows.some((r) => r.value.trim() && ['IP', 'EMAIL', 'URI', 'DN'].includes(r.type.toUpperCase()));

/**
 * Why one stored `TYPE:value` entry would be refused by the server's `NameConstraintRules`, or
 * null. Unlike an editor row, a stored entry with no value is an error.
 */
export const nameConstraintEntryError = (entry: string): string | null => {
    const parsed = parseTypedEntry(entry, NAME_CONSTRAINT_TYPES);
    if (!parsed.value.trim()) return `"${entry.trim()}" has no value.`;
    return typedEntryError(parsed, NAME_CONSTRAINT_TYPES);
};

/* ── Subject Alternative Names ─────────────────────────────────────────────── */

/**
 * A DNS SAN as `DnComponentSanitizer.ValidateDnsName` accepts it: a host name, or with
 * `allowWildcard` a `*.` leftmost label over at least two more labels.
 */
export const validateSanDns = (raw: string, opts: { allowWildcard?: boolean } = {}): string | null => {
    const v = raw.trim();
    if (!v) return 'Enter a DNS name.';
    if (v.length > 253) return `"${v}" is longer than 253 characters.`;
    if (CONTROL.test(v)) return `"${v}" contains a control character.`;
    let host = v;
    if (v.includes('*')) {
        if (opts.allowWildcard === false) return 'Wildcards are not allowed here.';
        const labels = v.split('.');
        if (labels[0] !== '*') return 'A wildcard must be the whole leftmost label, as in *.example.com.';
        if (labels.slice(1).some((l) => l.includes('*'))) return 'Only the leftmost label may be a wildcard.';
        if (labels.length < 3) return 'A wildcard needs at least two labels under it, as in *.example.com.';
        host = labels.slice(1).join('.');
    }
    if (DOTTED_QUAD.test(host)) return `"${v}" is an address; use an IP entry.`;
    const bare = host.endsWith('.') ? host.slice(0, -1) : host;
    for (const label of bare.split('.')) {
        if (!label) return `"${v}" has an empty label.`;
        if (label.length > 63) return `The label "${label}" is longer than 63 characters.`;
        if (label.startsWith('-') || !/^[\p{L}\p{N}_-]+$/u.test(label)) return `"${v}" is not a valid DNS name.`;
    }
    return null;
};

/** An IP SAN: one IPv4 or IPv6 address, no range. */
export const validateSanIp: Validator = (raw) => {
    const v = raw.trim();
    if (!v) return 'Enter an address.';
    if (v.includes('/')) return 'A SAN holds one address, not a range.';
    return parseIp(v) ? null : `"${v}" is not an IPv4 or IPv6 address.`;
};

/** A URI SAN: an absolute URI with a scheme, such as https://example.com/path or urn:uuid:…. */
export const validateSanUri: Validator = (raw) => {
    const v = raw.trim();
    if (!v) return 'Enter a URI.';
    if (/\s/.test(v)) return 'A URI cannot contain spaces.';
    if (!/^[A-Za-z][A-Za-z0-9+.-]*:/.test(v)) return `"${v}" is not an absolute URI; include the scheme, e.g. https://example.com.`;
    try { new URL(v); } catch { return `"${v}" is not a valid URI.`; }
    return null;
};

/** A UPN SAN, as `DnComponentSanitizer.ValidateUpn` accepts it: `user@suffix`, one `@`, no whitespace. */
export const validateSanUpn: Validator = (raw) => {
    const v = raw;
    if (!v.trim()) return 'Enter a UPN such as user@corp.example.';
    if (v.length > 1024) return 'A UPN is at most 1024 characters.';
    if (CONTROL.test(v)) return 'A UPN cannot contain control characters.';
    if (/\s/.test(v)) return 'A UPN cannot contain whitespace.';
    const bad = [...'"<>,;\\()[]'].find((c) => v.includes(c));
    if (bad) return `A UPN cannot contain "${bad}".`;
    const at = v.indexOf('@');
    if (at < 1 || at !== v.lastIndexOf('@') || at === v.length - 1) return 'A UPN has the form user@suffix, with exactly one "@".';
    const suffix = v.slice(at + 1);
    if (suffix.startsWith('.') || suffix.endsWith('.') || suffix.includes('..')) return `The suffix "${suffix}" is malformed.`;
    return null;
};

const SAN_DNS: TypedEntryType = { value: 'DNS', label: 'DNS', validate: (v) => validateSanDns(v), placeholder: 'host.example.com', example: 'host.example.com' };
const SAN_IP: TypedEntryType = { value: 'IP', label: 'IP', validate: validateSanIp, placeholder: '10.0.0.5', example: '10.0.0.5' };

/**
 * Every SAN type issuance accepts (`CertificateBuilderService`), in the spellings stored SAN lists
 * use. `EMAIL` and `RFC822` read as Email.
 */
export const SAN_TYPES: readonly TypedEntryType[] = [
    SAN_DNS,
    SAN_IP,
    { value: 'Email', label: 'Email', aliases: ['RFC822'], validate: validateEmail, placeholder: 'user@example.com', example: 'user@example.com' },
    { value: 'URI', label: 'URI', validate: validateSanUri, placeholder: 'https://example.com', example: 'https://example.com' },
    { value: 'UPN', label: 'UPN', validate: validateSanUpn, placeholder: 'user@corp.example', example: 'user@corp.example' },
];

/**
 * The SAN types a server-generated infrastructure certificate (Web TLS, at setup and on reissue)
 * can carry: `CsrService` builds only DNS and IP names into that CSR.
 */
export const INFRA_SAN_TYPES: readonly TypedEntryType[] = [SAN_DNS, SAN_IP];
