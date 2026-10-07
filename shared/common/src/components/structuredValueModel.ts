/**
 * The pure half of `StructuredValue`: turns a parsed JSON value into a tree of display nodes.
 * Every leaf is plain text; the component renders text nodes only, never markup, because audit
 * details carry attacker-influenced strings (usernames, CSR subjects, request paths).
 */

export interface ValueEntry {
    /** The key as stored. */
    key: string;
    /** The key as shown: identifier keys humanized, anything else verbatim. */
    label: string;
    node: ValueNode;
}

export interface TableColumn {
    key: string;
    label: string;
}

export type ValueNode =
    /** null, undefined or an empty string. */
    | { kind: 'empty'; text: string }
    | { kind: 'text'; text: string; mono: boolean; multiline: boolean; title?: string }
    | { kind: 'object'; summary: string; entries: ValueEntry[]; more: number }
    | { kind: 'list'; summary: string; items: ValueNode[]; more: number }
    /** An array of objects with the same primitive fields. */
    | { kind: 'table'; summary: string; columns: TableColumn[]; rows: ValueNode[][]; more: number }
    /** A container past the depth limit: its compact JSON, clipped. */
    | { kind: 'truncated'; summary: string; raw: string };

export interface StructuredValueOptions {
    /** Container levels shown below the root; deeper ones become `truncated`. Default 4. */
    maxDepth?: number;
    /** Entries or items shown per container; the rest are counted in `more`. Default 50. */
    maxItems?: number;
    /** Formats a recognised ISO timestamp. Defaults to a local en-US date and time. */
    formatDate?: (d: Date) => string;
}

export const DEFAULT_MAX_DEPTH = 4;
export const DEFAULT_MAX_ITEMS = 50;
const MAX_TABLE_COLUMNS = 8;
const MAX_TRUNCATED_RAW = 400;

const GUID = /^[{(]?[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}[)}]?$/i;
const HEX_PLAIN = /^(?:0x)?[0-9a-f]{16,}$/i;
const HEX_COLON = /^[0-9a-f]{2}(?:[:\- ][0-9a-f]{2}){7,}$/i;
const ISO_DATE = /^\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}(?::\d{2}(?:\.\d{1,9})?)?(?:Z|[+-]\d{2}:?\d{2})?$/i;
const MONO_KEY = /^(?:id|ids|serial|serialnumber|thumbprint|hash|fingerprint|oid|ip|ipaddress)$|(?:Id|Ids|ID|IDs|Serial|SerialNumber|Thumbprint|Hash|Fingerprint|Oid|OID|Ip|IP|IpAddress)$|_(?:id|ip|serial|hash)$/;
const IDENTIFIER = /^[A-Za-z][A-Za-z0-9_]*$/;

const ACRONYMS: Record<string, string> = {
    id: 'ID', ids: 'IDs', ip: 'IP', ca: 'CA', csr: 'CSR', san: 'SAN', sans: 'SANs', dn: 'DN', oid: 'OID',
    url: 'URL', uri: 'URI', mfa: 'MFA', acme: 'ACME', est: 'EST', scep: 'SCEP', cmp: 'CMP', crl: 'CRL',
    ocsp: 'OCSP', dns: 'DNS', upn: 'UPN', ssh: 'SSH', tls: 'TLS', ttl: 'TTL', utc: 'UTC', json: 'JSON',
    eku: 'EKU', ekus: 'EKUs', api: 'API', cps: 'CPS', ldap: 'LDAP', http: 'HTTP', https: 'HTTPS', msae: 'MSAE',
};

const defaultFormatDate = (d: Date): string =>
    d.toLocaleString('en-US', { year: 'numeric', month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit', second: '2-digit' });

/** `certSerialNumber` → "Cert serial number", `caId` → "CA ID". A key that is not an identifier is returned as is. */
export function humanizeKey(key: string): string {
    if (!IDENTIFIER.test(key)) return key;
    const words = key
        .replace(/_+/g, ' ')
        .replace(/([a-z0-9])([A-Z])/g, '$1 $2')
        .replace(/([A-Z]+)([A-Z][a-z])/g, '$1 $2')
        .trim()
        .split(/\s+/);
    return words.map((w, i) => {
        const lower = w.toLowerCase();
        if (ACRONYMS[lower]) return ACRONYMS[lower];
        return i === 0 ? lower.charAt(0).toUpperCase() + lower.slice(1) : lower;
    }).join(' ');
}

/** Parses JSON text. A JSON string that itself holds an object or array (double encoding) is unwrapped once. */
export function parseJsonText(text: string): { ok: true; value: unknown } | { ok: false } {
    let value: unknown;
    try { value = JSON.parse(text); } catch { return { ok: false }; }
    if (typeof value === 'string') {
        const inner = value.trim();
        if (inner.startsWith('{') || inner.startsWith('[')) {
            try { value = JSON.parse(inner); } catch { /* an ordinary string */ }
        }
    }
    return { ok: true, value };
}

/** The parsed object or array when `v` is a string holding one; undefined for anything else. */
export function parseJsonContainer(v: unknown): object | undefined {
    if (typeof v !== 'string') return undefined;
    const t = v.trim();
    if (!(t.startsWith('{') && t.endsWith('}')) && !(t.startsWith('[') && t.endsWith(']'))) return undefined;
    const parsed = parseJsonText(t);
    return parsed.ok && parsed.value !== null && typeof parsed.value === 'object' ? parsed.value : undefined;
}

const isPlainObject = (v: unknown): v is Record<string, unknown> =>
    v !== null && typeof v === 'object' && !Array.isArray(v);

const isPrimitive = (v: unknown): boolean => v === null || v === undefined || typeof v !== 'object';

const plural = (n: number, one: string, many: string) => `${n} ${n === 1 ? one : many}`;

/** "3 fields" or "1 item"; what a collapsed container says about itself. */
export function containerSummary(v: object): string {
    return Array.isArray(v) ? plural(v.length, 'item', 'items') : plural(Object.keys(v).length, 'field', 'fields');
}

/** Formats a primitive. Booleans read Yes/No, null "—", ISO timestamps as dates (raw in `title`). */
export function formatPrimitive(value: unknown, key?: string, options: StructuredValueOptions = {}): ValueNode {
    if (value === null || value === undefined) return { kind: 'empty', text: '—' };
    if (typeof value === 'boolean') return { kind: 'text', text: value ? 'Yes' : 'No', mono: false, multiline: false };
    if (typeof value === 'number') return { kind: 'text', text: String(value), mono: false, multiline: false };
    if (typeof value !== 'string') return { kind: 'text', text: String(value), mono: false, multiline: false };
    if (value === '') return { kind: 'empty', text: '(empty)' };
    const trimmed = value.trim();
    if (ISO_DATE.test(trimmed)) {
        const d = new Date(trimmed);
        if (!Number.isNaN(d.getTime())) {
            return { kind: 'text', text: (options.formatDate ?? defaultFormatDate)(d), mono: false, multiline: false, title: value };
        }
    }
    const mono = GUID.test(trimmed) || HEX_PLAIN.test(trimmed) || HEX_COLON.test(trimmed) || (key !== undefined && MONO_KEY.test(key));
    return { kind: 'text', text: value, mono, multiline: value.includes('\n') };
}

/** The columns when every item is an object of primitives over at most eight keys in all; else null. */
export function uniformColumns(items: unknown[]): string[] | null {
    if (items.length === 0) return null;
    const keys: string[] = [];
    for (const item of items) {
        if (!isPlainObject(item)) return null;
        for (const [k, v] of Object.entries(item)) {
            if (!isPrimitive(v)) return null;
            if (!keys.includes(k)) keys.push(k);
        }
    }
    return keys.length > 0 && keys.length <= MAX_TABLE_COLUMNS ? keys : null;
}

function clip(text: string, max: number): string {
    return text.length > max ? `${text.slice(0, max)}…` : text;
}

type ResolvedOptions = StructuredValueOptions & { maxDepth: number; maxItems: number };

function build(value: unknown, depth: number, key: string | undefined, o: ResolvedOptions): ValueNode {
    if (isPrimitive(value)) return formatPrimitive(value, key, o);
    const container = value as object;
    const summary = containerSummary(container);
    if (depth > o.maxDepth) {
        let raw: string;
        try { raw = JSON.stringify(container) ?? ''; } catch { raw = ''; }
        return { kind: 'truncated', summary, raw: clip(raw, MAX_TRUNCATED_RAW) };
    }
    if (Array.isArray(container)) {
        const shown = container.slice(0, o.maxItems);
        const more = container.length - shown.length;
        const columns = uniformColumns(shown);
        if (columns) {
            return {
                kind: 'table', summary, more,
                columns: columns.map((k) => ({ key: k, label: humanizeKey(k) })),
                rows: shown.map((row) => columns.map((k) => formatPrimitive((row as Record<string, unknown>)[k], k, o))),
            };
        }
        return { kind: 'list', summary, more, items: shown.map((item) => build(item, depth + 1, key, o)) };
    }
    const all = Object.entries(container as Record<string, unknown>);
    const shown = all.slice(0, o.maxItems);
    return {
        kind: 'object', summary, more: all.length - shown.length,
        entries: shown.map(([k, v]) => ({ key: k, label: humanizeKey(k), node: build(v, depth + 1, k, o) })),
    };
}

/** The display tree for a parsed JSON value. The root container is depth 0. */
export function buildValueTree(value: unknown, options: StructuredValueOptions = {}): ValueNode {
    const o: ResolvedOptions = {
        ...options,
        maxDepth: Math.max(0, options.maxDepth ?? DEFAULT_MAX_DEPTH),
        maxItems: Math.max(1, options.maxItems ?? DEFAULT_MAX_ITEMS),
    };
    return build(value, 0, undefined, o);
}

/** True for the node kinds that hold other nodes. */
export const isContainerNode = (n: ValueNode): n is Extract<ValueNode, { kind: 'object' | 'list' | 'table' }> =>
    n.kind === 'object' || n.kind === 'list' || n.kind === 'table';
