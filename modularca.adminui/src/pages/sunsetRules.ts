/**
 * Algorithm Sunset Rules (Settings › Certificate Policy) as rows of an algorithm and a date.
 * Pure, so tests/modularca.web.tests covers it.
 *
 * Stored as `ALG:YYYY-MM-DD` strings. CertPolicyService splits each at its last colon and compares
 * ALG, ignoring case, with the request's key algorithm and size joined by a hyphen (`RSA-2048`,
 * `ECDSA-P-256`), its key algorithm alone (`RSA`, `Ed25519`, `ML-DSA-65`), or its signature
 * algorithm (`SHA1withRSA`). From the date on, issuance is refused; in the 90 days before, it
 * warns. The save-time check is ConfigInputRules.AlgorithmSunsetRuleError; shared cases:
 * tests/modularca.web.tests/src/adminui/sunset-rule-cases.json.
 */
import type { RowTableColumn, TableRow } from '@shared/components/rowTable';
import { filledRows } from '@shared/components/rowTable';
import { POLICY_SIGNATURE_ALGORITHMS } from './settingsLists';

export interface SunsetRow extends TableRow {
    algorithm: string;
    date: string;
}

/** Key algorithm and size pairs, then key algorithms, then signature algorithms, as the server names them. */
export const SUNSET_ALGORITHM_SUGGESTIONS: readonly string[] = [
    'RSA-1024', 'RSA-2048', 'RSA-3072', 'RSA-4096', 'ECDSA-P-256', 'ECDSA-P-384', 'ECDSA-P-521',
    'RSA', 'ECDSA', 'DSA', 'Ed25519', 'Ed448',
    ...POLICY_SIGNATURE_ALGORITHMS.filter((a) => !['Ed25519', 'Ed448'].includes(a)),
];

const KNOWN = new Set(SUNSET_ALGORITHM_SUGGESTIONS.map((s) => s.toLowerCase()));

/** The algorithm part: one word, no spaces or colons. */
export const validateSunsetAlgorithm = (raw: string): string | null => {
    const v = raw.trim();
    if (!v) return 'Enter an algorithm such as RSA-2048.';
    if (/[\s:\u0000-\u001f\u007f]/.test(v)) return 'One word with no spaces or colons, such as RSA-2048, ECDSA-P-256 or SHA1withRSA.';
    return null;
};

/** An algorithm spelling the server never produces matches nothing; a warning, since an unlisted OID or curve may be meant. */
export const sunsetAlgorithmWarning = (raw: string): string | null => {
    const v = raw.trim();
    if (!v || KNOWN.has(v.toLowerCase()) || /^RSA-\d+$/i.test(v) || /^\d+(\.\d+)+$/.test(v) || /^(ML-DSA|SLH-DSA)-/i.test(v)) return null;
    return `"${v}" is not a name the server compares with; it matches only a key algorithm, an algorithm-size pair such as RSA-2048, or a signature algorithm such as SHA256withRSA.`;
};

/** The date part: YYYY-MM-DD and a real calendar date. */
export const validateSunsetDate = (raw: string): string | null => {
    const v = raw.trim();
    if (!v) return 'Enter the sunset date.';
    const m = /^(\d{4})-(\d{2})-(\d{2})$/.exec(v);
    if (!m) return `"${v}" is not a date written YYYY-MM-DD.`;
    const [y, mo, d] = [Number(m[1]), Number(m[2]), Number(m[3])];
    const date = new Date(0);
    date.setUTCFullYear(y, mo - 1, d);
    if (y < 1 || date.getUTCFullYear() !== y || date.getUTCMonth() !== mo - 1 || date.getUTCDate() !== d) return `"${v}" is not a real date.`;
    return null;
};

/** One whole stored rule, as ConfigInputRules.AlgorithmSunsetRuleError judges it. */
export const sunsetRuleError = (rule: string): string | null => {
    if (!rule.trim()) return 'An algorithm sunset rule is empty.';
    const colon = rule.lastIndexOf(':');
    if (colon <= 0 || colon >= rule.length - 1) return `Sunset rule "${rule}" must be ALGORITHM:YYYY-MM-DD, e.g. RSA-2048:2030-01-01.`;
    return validateSunsetAlgorithm(rule.slice(0, colon)) ?? validateSunsetDate(rule.slice(colon + 1));
};

/** Rows from the stored rules, split at the last colon as the server splits them. */
export const sunsetRowsFromList = (list: readonly string[]): SunsetRow[] =>
    list.filter((r) => r.trim()).map((rule) => {
        const colon = rule.lastIndexOf(':');
        return colon < 0
            ? { algorithm: rule.trim(), date: '' }
            : { algorithm: rule.slice(0, colon).trim(), date: rule.slice(colon + 1).trim() };
    });

export const SUNSET_COLUMNS: readonly RowTableColumn<SunsetRow>[] = [
    {
        key: 'algorithm', label: 'Algorithm', kind: 'text', required: true, mono: true, placeholder: 'RSA-2048',
        suggestions: SUNSET_ALGORITHM_SUGGESTIONS.map((value) => ({ value, label: value })),
        validate: (v) => validateSunsetAlgorithm(v), warn: (v) => sunsetAlgorithmWarning(v),
    },
    { key: 'date', label: 'Sunset date', kind: 'date', required: true, width: '11rem', validate: (v) => validateSunsetDate(v) },
];

/** The rules to store: `ALG:YYYY-MM-DD` per filled row. */
export const sunsetRowsToList = (rows: readonly SunsetRow[]): string[] =>
    filledRows(rows, SUNSET_COLUMNS).map((r) => `${r.algorithm.trim()}:${r.date.trim()}`);
