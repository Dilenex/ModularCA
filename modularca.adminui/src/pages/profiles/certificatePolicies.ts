/**
 * A signing profile's CertificatePolicies extension as table rows: one row per policy (OID, CPS
 * URI, user notice) and one extension-wide critical flag. Pure, so tests/modularca.web.tests covers
 * the round trip.
 *
 * On the wire it stays two fields: `policyOids`, a JSON array of OIDs, and `policyQualifiersJson`,
 * `{ "<oid>": { "cpsUri", "userNotice", "critical" } }`. CertificateBuilderService marks the whole
 * extension critical when any entry's `critical` is true, so the form reads that as one checkbox
 * and writes `critical: true` on every listed policy when it is ticked. Server checks:
 * CertificatePolicyRules.cs; shared cases: tests/modularca.web.tests/src/common/certificate-policy-cases.json.
 */
import { type RowTableColumn, type TableRow, filledRows, findRowProblems, hasRowErrors } from '@shared/components/rowTable';
import { validateOid } from '@shared/validators';
import { parseListField } from './profileFormCore';

export interface PolicyRow extends TableRow {
    oid: string;
    cpsUri: string;
    userNotice: string;
}

export interface CertificatePolicies {
    rows: PolicyRow[];
    /** Mark the CertificatePolicies extension critical. */
    critical: boolean;
}

/** What loading found and dropped: qualifiers the server never used, or could not read. */
export interface LoadedCertificatePolicies extends CertificatePolicies {
    notices: string[];
}

/** RFC 5280 §4.2.1.4 explicitText; BouncyCastle truncates longer text. Mirrors CertificatePolicyRules.MaxUserNoticeLength. */
export const MAX_USER_NOTICE_LENGTH = 200;

/** The qualifier keys the server reads, case-sensitive. */
export const QUALIFIER_KEYS = ['cpsUri', 'userNotice', 'critical'] as const;

export const ANY_POLICY_OID = '2.5.29.32.0';

/** Common policies offered as you type an OID. */
export const POLICY_SUGGESTIONS: readonly { value: string; label: string }[] = [
    { value: ANY_POLICY_OID, label: 'anyPolicy' },
    { value: '2.23.140.1.2.1', label: 'CA/B Forum: domain validated (DV)' },
    { value: '2.23.140.1.2.2', label: 'CA/B Forum: organization validated (OV)' },
    { value: '2.23.140.1.2.3', label: 'CA/B Forum: individual validated (IV)' },
    { value: '2.23.140.1.1', label: 'CA/B Forum: extended validation (EV)' },
];

/** The suggestion label for an OID, or undefined. */
export const policyLabel = (oid: string): string | undefined => POLICY_SUGGESTIONS.find((s) => s.value === oid.trim())?.label;

/** A CPS pointer: an absolute http(s) URL in printable ASCII (the server encodes it as an IA5String). */
export const validateCpsUri = (raw: string): string | null => {
    const v = raw.trim();
    if (!v) return null;
    if (/[^\x21-\x7e]/.test(v)) return `"${v}" must be printable ASCII with no spaces (it is encoded as an IA5String).`;
    if (!/^https?:\/\//i.test(v)) return `"${v}" must be an absolute http:// or https:// URL.`;
    let url: URL;
    try { url = new URL(v); } catch { return `"${v}" must be an absolute http:// or https:// URL.`; }
    if (!url.hostname) return `"${v}" has no host.`;
    return null;
};

/** A user notice: at most 200 characters, no control characters or line breaks. */
export const validateUserNotice = (text: string): string | null => {
    if (!text) return null;
    if (text.length > MAX_USER_NOTICE_LENGTH) return `At most ${MAX_USER_NOTICE_LENGTH} characters (RFC 5280 explicitText); this has ${text.length}.`;
    if (/[\u0000-\u001f\u007f-\u009f]/.test(text)) return 'A user notice cannot contain control characters or line breaks.';
    return null;
};

export const POLICY_COLUMNS: readonly RowTableColumn<PolicyRow>[] = [
    {
        key: 'oid', label: 'Policy OID', kind: 'text', required: true, mono: true, width: '14rem',
        placeholder: '2.23.140.1.2.1', suggestions: POLICY_SUGGESTIONS, validate: (v) => validateOid(v),
    },
    {
        key: 'cpsUri', label: 'CPS URI', kind: 'text', mono: true, placeholder: 'https://pki.example.com/cps',
        validate: (v) => validateCpsUri(v),
    },
    {
        key: 'userNotice', label: 'User notice', kind: 'text', placeholder: 'Optional, up to 200 characters',
        maxLength: 1000, validate: (v) => validateUserNotice(v), hint: 'Up to 200 characters',
    },
];

/** OIDs compare as typed, trimmed; the server compares them exactly. */
export const POLICY_CHECKS = {
    duplicateKey: {
        column: 'oid' as const,
        message: (oid: string, first: number) => `${oid} is already listed in row ${first + 1}; each policy may appear once.`,
    },
};

export const blankPolicyRow = (): PolicyRow => ({ oid: '', cpsUri: '', userNotice: '' });

const isObject = (v: unknown): v is Record<string, unknown> => !!v && typeof v === 'object' && !Array.isArray(v);

/**
 * Rows from the stored fields. The extension is critical when any stored qualifier entry says so,
 * as the server reads it (an entry for an OID not listed included). A duplicate OID is listed once.
 * Qualifiers the server never used, or could not read, are dropped, each with a notice: a non-object
 * field, an entry for an OID not listed, a key other than cpsUri / userNotice / critical, or a
 * value of the wrong type.
 */
export const policiesFromStored = (policyOids: unknown, policyQualifiersJson: unknown): LoadedCertificatePolicies => {
    const notices: string[] = [];
    const rows: PolicyRow[] = [];
    for (const raw of parseListField(policyOids)) {
        const oid = raw.trim();
        if (!oid) continue;
        if (rows.some((r) => r.oid === oid)) { notices.push(`${oid} was listed more than once; it is kept once.`); continue; }
        rows.push({ oid, cpsUri: '', userNotice: '' });
    }

    let critical = false;
    let qualifiers: unknown = policyQualifiersJson;
    if (typeof qualifiers === 'string') {
        const text = qualifiers.trim();
        if (!text) qualifiers = {};
        else {
            try { qualifiers = JSON.parse(text); } catch { qualifiers = undefined; }
        }
    } else if (qualifiers == null) {
        qualifiers = {};
    }
    if (!isObject(qualifiers)) {
        notices.push('The stored policy qualifiers were not a JSON object, so issuance ignored them; they are dropped.');
        return { rows, critical, notices };
    }

    for (const [rawOid, entry] of Object.entries(qualifiers)) {
        const oid = rawOid.trim();
        if (entry == null) continue;
        if (!isObject(entry)) {
            notices.push(`The qualifiers for ${oid} were not an object, so issuance ignored them; dropped.`);
            continue;
        }
        if (entry.critical === true) critical = true;
        const row = rows.find((r) => r.oid === oid);
        if (!row) {
            notices.push(`Qualifiers for ${oid} were dropped: it is not one of the listed policies, so issuance never used them${entry.critical === true ? ' (its critical flag still made the extension critical, which the checkbox keeps)' : ''}.`);
            continue;
        }
        for (const [key, value] of Object.entries(entry)) {
            if (key === 'cpsUri' || key === 'userNotice') {
                if (value == null) continue;
                if (typeof value === 'string') row[key] = value;
                else notices.push(`${key} for ${oid} was not text, so issuance ignored it; dropped.`);
            } else if (key === 'critical') {
                if (typeof value !== 'boolean') notices.push(`critical for ${oid} was not true or false, so issuance ignored it; dropped.`);
            } else {
                notices.push(`"${key}" in the qualifiers for ${oid} is not a key the server reads (${QUALIFIER_KEYS.join(', ')}); dropped.`);
            }
        }
    }
    return { rows, critical, notices };
};

/** The two stored fields: the OIDs as a JSON array and the qualifiers as a JSON object, blank rows dropped. */
export const policiesToFields = (p: CertificatePolicies): { policyOids: string; policyQualifiersJson: string } => {
    const rows = filledRows(p.rows, POLICY_COLUMNS);
    const qualifiers: Record<string, { cpsUri?: string; userNotice?: string; critical?: true }> = {};
    for (const r of rows) {
        const oid = r.oid.trim();
        const entry: { cpsUri?: string; userNotice?: string; critical?: true } = {};
        if (r.cpsUri.trim()) entry.cpsUri = r.cpsUri.trim();
        if (r.userNotice.trim()) entry.userNotice = r.userNotice.trim();
        if (p.critical) entry.critical = true;
        if (Object.keys(entry).length) qualifiers[oid] = entry;
    }
    return {
        policyOids: JSON.stringify(rows.map((r) => r.oid.trim())),
        policyQualifiersJson: JSON.stringify(qualifiers),
    };
};

/** Whether any policy row would be refused by the server. */
export const policyRowsInvalid = (rows: readonly PolicyRow[]): boolean => hasRowErrors(rows, POLICY_COLUMNS, POLICY_CHECKS);

/** The problems in the rows, for a read-only view. */
export const policyRowProblems = (rows: readonly PolicyRow[]) => findRowProblems(rows, POLICY_COLUMNS, POLICY_CHECKS);
