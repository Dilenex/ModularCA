/**
 * The LDAP Group to Role Mappings setting as key/value rows: an LDAP group DN mapped to one local
 * group name. Pure, so tests/modularca.web.tests covers it.
 *
 * Stored as a JSON object string (`{ "<group DN>": "<local group name>" }`), so one DN maps to one
 * group. Server rules mirrored here (LdapGroupSyncService):
 * - sync compares a user's group DNs with the keys exactly, ignoring case;
 * - group names compare ignoring case;
 * - a new or changed mapping to a system or privilege-controlled group is refused at save
 *   (IsRefusedMappingTarget); one stored unchanged passes, and sync skips it;
 * - sync never grants an instance group (one with no space);
 * - a target still naming a space group by its pre-0.4.0 `org-` name resolves to the renamed
 *   `space-` group, and a super's save rewrites it.
 * Cases shared with ModularCA.Tests: tests/modularca.web.tests/src/adminui/ldap-mapping-cases.json.
 */
import type { KeyValueRow, RowProblemInput, RowTableOption } from '@shared/components/rowTable';
import { keyValueRowsFromObject, keyValueRowsToObject } from '@shared/components/rowTable';

/** A group as GET /api/v1/admin/groups returns it, the fields that matter here. */
export interface MappingGroup {
    name: string;
    displayName?: string | null;
    spaceId?: string | null;
    isSystemGroup?: boolean;
    isSystemTierSuper?: boolean;
    isControlled?: boolean;
}

/** Mirrors LdapGroupSyncService.IsRefusedMappingTarget. */
export const isRefusedMappingTarget = (g: Pick<MappingGroup, 'isSystemGroup' | 'isSystemTierSuper' | 'isControlled'>): boolean =>
    !!g.isSystemGroup || !!g.isSystemTierSuper || !!g.isControlled;

/** The groups worth offering: ones sync can grant (in a space, not system or controlled), by name. */
export const mappingTargetOptions = (groups: readonly MappingGroup[]): RowTableOption[] =>
    groups
        .filter((g) => g.spaceId && !isRefusedMappingTarget(g))
        .slice()
        .sort((a, b) => a.name.localeCompare(b.name))
        .map((g) => ({ value: g.name, label: g.displayName && g.displayName !== g.name ? `${g.name} (${g.displayName})` : g.name }));

/** Mapping keys compare ignoring case and surrounding space, as sync matches them. */
export const normalizeDnKey = (dn: string): string => dn.trim().toUpperCase();

const LEGACY_SPACE_GROUP = /^org-.+-(admin|operator|auditor|user)$/i;

/** The group a target names, ignoring case; a legacy `org-` name resolves to its `space-` group when only that exists. */
export const findMappingTarget = (target: string, groups: readonly MappingGroup[]): { group: MappingGroup; renamedFrom?: string } | null => {
    const t = target.trim().toLowerCase();
    const direct = groups.find((g) => g.name.toLowerCase() === t);
    if (direct) return { group: direct };
    if (LEGACY_SPACE_GROUP.test(target.trim())) {
        const renamed = `space-${target.trim().slice('org-'.length)}`.toLowerCase();
        const g = groups.find((x) => x.name.toLowerCase() === renamed);
        if (g) return { group: g, renamedFrom: target.trim() };
    }
    return null;
};

/**
 * An LDAP DN: RDNs of `attribute=value` separated by unescaped commas (a multi-valued RDN joined
 * by `+`), the attribute a name or dotted OID, every value non-empty, escapes RFC 4514 allows.
 * The server does not parse it; it compares strings, so this catches typos only.
 */
export const validateLdapDn = (raw: string): string | null => {
    const v = raw.trim();
    if (!v) return 'Enter the LDAP group DN.';
    if (/[\u0000-\u001f\u007f]/.test(v)) return 'A DN cannot contain control characters.';
    const parts: string[] = [];
    let current = '';
    let quoted = false;
    for (let i = 0; i < v.length; i++) {
        const ch = v[i];
        if (ch === '\\') {
            const next = v.slice(i + 1, i + 3);
            if (/^[0-9a-fA-F]{2}$/.test(next)) { current += ch + next; i += 2; continue; }
            if (i + 1 < v.length && ',+"\\<>;=# '.includes(v[i + 1])) { current += ch + v[i + 1]; i += 1; continue; }
            return `"${v}" has a backslash that escapes nothing; write \\, for a comma inside a value.`;
        }
        if (ch === '"') quoted = !quoted;
        if ((ch === ',' || ch === '+') && !quoted) { parts.push(current); current = ''; continue; }
        current += ch;
    }
    if (quoted) return `"${v}" has an unclosed quote.`;
    parts.push(current);
    for (const part of parts) {
        const eq = part.indexOf('=');
        const attr = eq > 0 ? part.slice(0, eq).trim() : '';
        const value = eq > 0 ? part.slice(eq + 1).trim() : '';
        if (!attr || !value) return `"${part.trim() || '(empty)'}" is not attribute=value; a DN reads like CN=PKI Admins,OU=Groups,DC=example,DC=com.`;
        if (!/^[A-Za-z][A-Za-z0-9-]*$/.test(attr) && !/^\d+(\.\d+)+$/.test(attr)) return `"${attr}" is not an attribute name such as CN, OU or DC.`;
    }
    return null;
};

/** Rows from the stored setting, with what could not be read. */
export const mappingRowsFromStored = (stored: unknown): { rows: KeyValueRow[]; notices: string[] } => {
    if (stored == null || (typeof stored === 'string' && !stored.trim())) return { rows: [], notices: [] };
    let obj: unknown = stored;
    if (typeof stored === 'string') {
        try { obj = JSON.parse(stored); } catch { return { rows: [], notices: ['The stored mappings are not valid JSON, so sync reads none of them. Saving replaces them with the rows below.'] }; }
    }
    if (!obj || typeof obj !== 'object' || Array.isArray(obj)) {
        return { rows: [], notices: ['The stored mappings are not a JSON object, so sync reads none of them. Saving replaces them with the rows below.'] };
    }
    const { rows, skipped } = keyValueRowsFromObject(obj);
    return { rows, notices: skipped.map((k) => `The mapping for ${k} has no group name, so it grants nothing; it is dropped.`) };
};

/** The stored setting: a JSON object string, one entry per filled row. */
export const mappingRowsToJson = (rows: readonly KeyValueRow[]): string => JSON.stringify(keyValueRowsToObject(rows));

/** The stored (DN, group) pairs, upper-cased as the server compares them for "stored unchanged". */
export const storedMappingPairs = (rows: readonly KeyValueRow[]): Set<string> =>
    new Set(rows.filter((r) => r.value.trim()).map((r) => `${r.key.toUpperCase()}\u0000${r.value.trim().toUpperCase()}`));

/**
 * The problems with one row's target group beyond the table's own checks (DN syntax, duplicate
 * DN, required cells). `groups` is null when the group list is unavailable, and then nothing is
 * judged; `stored` holds the pairs as last saved (`storedMappingPairs`).
 */
export const mappingTargetProblems = (row: KeyValueRow, groups: readonly MappingGroup[] | null, stored: ReadonlySet<string>): RowProblemInput[] => {
    const target = row.value.trim();
    if (!groups || !target) return [];
    const found = findMappingTarget(target, groups);
    if (!found) return [{ column: 'value', tone: 'warning', message: `No group named ${target} exists, so this mapping grants nothing.` }];
    const out: RowProblemInput[] = [];
    if (found.renamedFrom) out.push({ column: 'value', tone: 'warning', message: `${found.renamedFrom} was renamed to ${found.group.name} in 0.4.0; sync uses the new name, and saving rewrites it.` });
    if (isRefusedMappingTarget(found.group)) {
        const unchanged = stored.has(`${row.key.toUpperCase()}\u0000${target.toUpperCase()}`);
        out.push(unchanged
            ? { column: 'value', tone: 'warning', message: `${found.group.name} is a system or privilege-controlled group: sync skips it, and the server keeps this stored mapping only while it is unchanged.` }
            : { column: 'value', tone: 'error', message: `${found.group.name} is a system or privilege-controlled group; its membership changes only through the ceremony-gated admin paths, so the server refuses this mapping.` });
    } else if (!found.group.spaceId) {
        out.push({ column: 'value', tone: 'warning', message: `${found.group.name} is an instance group; sync grants only groups in a space, so this mapping grants nothing.` });
    }
    return out;
};
