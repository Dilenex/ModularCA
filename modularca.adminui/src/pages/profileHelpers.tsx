import React from 'react';
import { KEY_USAGE_NAMES, canonicalizeUsage } from '@shared/generated';

/* Shared constants + helper components for the Profile Management tabs and their detail pages. */

/**
 * Every key usage the issuance path can emit a bit for, generated from
 * `KeyUsageFriendlyNames.Parse`.
 *
 * This was a hand-written list of four. Because `canonicalizeUsages` DROPS a stored value that
 * matches no option, a profile carrying any of the other five — keyAgreement, nonRepudiation,
 * dataEncipherment, encipherOnly, decipherOnly, all of which the server accepts and issues — lost
 * that usage the moment someone opened the profile and saved it. Deriving the list from the
 * server's own switch statement is what makes the two sets equal by construction.
 */
export const KEY_USAGE_OPTIONS: readonly string[] = KEY_USAGE_NAMES;

/**
 * Extended-key-usage option values for a certificate profile.
 *
 * Both this list and KEY_USAGE_OPTIONS above are PERSISTED into
 * CertProfile.ExtendedKeyUsages / KeyUsages, so they must be the canonical forms the issuance
 * path resolves against OIDOptions — EKUs as OIDs, key usages as the catalog's friendly names.
 * They once held display labels ('Server Auth', 'Digital Signature'), which matched no catalog
 * row, so any cert profile edited in the admin UI was issued with NO ExtendedKeyUsage and NO
 * KeyUsage extension. Use the *_LABELS maps for presentation only.
 */
/**
 * FALLBACK ONLY. The live vocabulary comes from the OID catalog via `useEkuCatalog()`, because
 * the catalog is extensible and this list is not: `canonicalizeUsages` drops what it does not
 * recognise and the result is saved back, so a stale list here silently strips usages from a
 * profile. These entries exist so the pages still render correctly before the catalog fetch
 * resolves, and if it fails.
 *
 * Smart Card Logon and KDC Authentication are included because both are seeded defaults and both
 * are load-bearing for Windows smart-card logon — the first on the card's certificate, the second
 * on the domain controller's.
 */
export const DEFAULT_EKU_OPTIONS = [
    '1.3.6.1.5.5.7.3.1', '1.3.6.1.5.5.7.3.2', '1.3.6.1.5.5.7.3.3',
    '1.3.6.1.5.5.7.3.4', '1.3.6.1.5.5.7.3.8', '1.3.6.1.5.5.7.3.9',
    '1.3.6.1.4.1.311.20.2.2', '1.3.6.1.5.2.3.5',
];

export const DEFAULT_EKU_LABELS: Record<string, string> = {
    '1.3.6.1.5.5.7.3.1': 'Server Auth',
    '1.3.6.1.5.5.7.3.2': 'Client Auth',
    '1.3.6.1.5.5.7.3.3': 'Code Signing',
    '1.3.6.1.5.5.7.3.4': 'Email Protection',
    '1.3.6.1.5.5.7.3.8': 'Time Stamping',
    '1.3.6.1.5.5.7.3.9': 'OCSP Signing',
    '1.3.6.1.4.1.311.20.2.2': 'Smart Card Logon',
    '1.3.6.1.5.2.3.5': 'KDC Authentication',
};

/**
 * Comparison key for a usage identifier.
 *
 * Re-exported from the generated port of `UsageCatalogResolver` rather than reimplemented. It
 * used to be a local one-liner whose comment claimed to mirror `IssuanceValidationService`;
 * that class no longer has its own copy, and hand-synchronised copies of this comparison are
 * exactly how a bootstrapped root CA once ended up with no KeyUsage extension at all.
 *
 * Note this folds word-level synonyms too, which plain normalisation cannot: "Key Certificate
 * Signing", "Key Cert Sign" and "keyCertSign" all reduce to the same key, as do "OCSP Signer"
 * and "OCSPSigning".
 */
export const normalizeUsageKey = canonicalizeUsage;

/**
 * Maps stored usage values onto the canonical option values, dropping anything unrecognisable.
 *
 * Necessary because a profile field can hold any of four things by now: the canonical value, the
 * catalog friendly name, an old display label, or — for rows written while the CSV/JSON parse bug
 * was live — fragments of a JSON array such as `["[]"` or `"Server Auth"`. Canonicalising
 * collapses all of those onto the same key, so the toggles show the real selection and the next
 * save rewrites the field in canonical form.
 *
 * Dropping the unresolvable is only safe while this function's vocabulary matches the server's,
 * because the result is written straight back on save — a value dropped here is a value REMOVED
 * from the profile. That is why both the option lists and the comparison now come from generated
 * code instead of hand-written tables.
 */
export const canonicalizeUsages = (
    values: string[],
    canonical: readonly string[],
    aliases: Record<string, string> = {},
): string[] => {
    const lookup = new Map<string, string>();
    for (const c of canonical) lookup.set(canonicalizeUsage(c), c);
    for (const [alias, target] of Object.entries(aliases)) lookup.set(canonicalizeUsage(alias), target);

    const out: string[] = [];
    for (const v of values) {
        const hit = lookup.get(canonicalizeUsage(v));
        if (hit && !out.includes(hit)) out.push(hit);
    }
    return out;
};

/**
 * Names that should resolve to an EKU OID.
 *
 * Still hand-written because this maps a NAME onto an OID, and the profile fields store OIDs —
 * `canonicalizeUsage` alone cannot bridge that. But it needs only one entry per OID now: the
 * lookup is keyed by the canonical form, which already folds every spelling of a given usage
 * together. The previous table carried two spellings per OID and still missed the two the
 * bootstrap seeder uses — "Server Authentication" and "OCSP Signer" — because neither is a
 * punctuation variant of "Server Auth" or "OCSP Signing"; they differ in words.
 */
export const DEFAULT_EKU_ALIASES: Record<string, string> = {
    serverAuth: '1.3.6.1.5.5.7.3.1',
    clientAuth: '1.3.6.1.5.5.7.3.2',
    codeSigning: '1.3.6.1.5.5.7.3.3',
    emailProtection: '1.3.6.1.5.5.7.3.4',
    timeStamping: '1.3.6.1.5.5.7.3.8',
    ocspSigning: '1.3.6.1.5.5.7.3.9',
    smartcardLogon: '1.3.6.1.4.1.311.20.2.2',
    kdcAuthentication: '1.3.6.1.5.2.3.5',
};

/**
 * Display labels for the nine key usages.
 *
 * Presentation only — never persist these. `canonicalizeUsage` maps every one of them back onto
 * its canonical value, so a profile written with a label by an older build still resolves.
 */
export const KEY_USAGE_LABELS: Record<string, string> = {
    digitalSignature: 'Digital Signature',
    nonRepudiation: 'Non Repudiation',
    keyEncipherment: 'Key Encipherment',
    dataEncipherment: 'Data Encipherment',
    keyAgreement: 'Key Agreement',
    keyCertSign: 'Key Cert Sign',
    crlSign: 'CRL Sign',
    encipherOnly: 'Encipher Only',
    decipherOnly: 'Decipher Only',
};

export const keyUsageLabel = (v: string): string => KEY_USAGE_LABELS[v] ?? v;

export const ALLOWED_KEY_ALGORITHM_OPTIONS = [
    'RSA', 'ECDSA', 'Ed25519', 'Ed448', 'ML-DSA-44', 'ML-DSA-65', 'ML-DSA-87', 'SLH-DSA-SHA2-128F',
];
export const ALLOWED_KEY_SIZE_OPTIONS = [
    '2048', '3072', '4096', '7680', '8192', 'P-256', 'P-384', 'P-521',
];
// The ...andMGF1 entries are RSASSA-PSS. They are NOT optional extras: CertPolicy
// .RsaSignaturePadding defaults to "PSS", so KeyAlgorithmPolicy signs RSA requests as
// SHA-n-withRSAandMGF1. Omitting them here meant a cert profile created through this UI could
// never permit the signatures the server actually produces, and every RSA issuance against
// such a profile failed. The seeded profiles and BootstrapModularCA always included them —
// only this picker did not.
export const ALLOWED_SIGNATURE_ALGORITHM_OPTIONS = [
    'SHA256withRSA', 'SHA384withRSA', 'SHA512withRSA',
    'SHA256withRSAandMGF1', 'SHA384withRSAandMGF1', 'SHA512withRSAandMGF1',
    'SHA256withECDSA', 'SHA384withECDSA', 'SHA512withECDSA',
    'Ed25519', 'Ed448',
    'ML-DSA-44', 'ML-DSA-65', 'ML-DSA-87', 'SLH-DSA-SHA2-128F',
];

/** Labels the RSASSA-PSS entries so an author picking algorithms knows what MGF1 means. */
export const formatSignatureAlgorithmLabel = (alg: string) =>
    alg.endsWith('andMGF1') ? `${alg.replace('andMGF1', '')} (RSA-PSS)` : alg;

export const SIGNING_ALLOWED_ALGORITHM_OPTIONS = ['RSA', 'ECDSA', 'Ed25519', 'Ed448', 'ML-DSA-44', 'ML-DSA-65', 'ML-DSA-87', 'SLH-DSA-SHA2-128F'];

/** Common EKU OIDs with display names for signing profile EKU picker */
/**
 * Fallback signing-profile EKU options, derived from the same defaults. Live values come from
 * `useEkuCatalog()`; see DEFAULT_EKU_OPTIONS for why a hardcoded list cannot be the source.
 */
export const DEFAULT_SIGNING_EKU_OPTIONS: { oid: string; label: string }[] =
    DEFAULT_EKU_OPTIONS.map((oid) => ({ oid, label: DEFAULT_EKU_LABELS[oid] ?? oid }));

/** SSH certificate extension allow/require options. */
export const SSH_EXTENSION_OPTIONS = [
    'permit-pty', 'permit-port-forwarding', 'permit-agent-forwarding',
    'permit-X11-forwarding', 'permit-user-rc',
    'no-pty', 'no-port-forwarding', 'no-agent-forwarding',
    'no-X11-forwarding', 'no-user-rc',
];

export const inputClass = 'w-full px-3 py-2 bg-gray-50 dark:bg-gray-900 border border-gray-300 dark:border-gray-700 rounded text-sm text-gray-900 dark:text-white focus:outline-none focus:border-blue-500';
export const labelClass = 'block text-xs text-gray-600 dark:text-gray-400 mb-1';

/** Parse a JSON array field from the API (could be string or array) into a string array */
/**
 * Reads a list-valued profile field regardless of the shape the API returned it in.
 *
 * The backend canonicalises these to a JSON array string (CertProfileService.NormalizeJsonStringArray,
 * SigningProfileService), but that normaliser also ACCEPTS a comma-separated string on write and
 * converts it — so a field can legitimately arrive as `["a","b"]`, as `a, b`, or already as an array
 * depending on how it was last written and by which client.
 *
 * Parsing a JSON array with `.split(',')` yields tokens like `["a"` and `"b"]`, which then match no
 * option in a toggle list. That renders as "nothing selected", which reads to a user as "my changes
 * did not save" even though the write succeeded — the bug this helper exists to prevent.
 */
export const parseListField = (val: any): string[] => {
    if (Array.isArray(val)) return val.map(String);
    if (typeof val !== 'string') return [];
    const trimmed = val.trim();
    if (!trimmed) return [];
    if (trimmed.startsWith('[')) {
        try {
            const parsed = JSON.parse(trimmed);
            if (Array.isArray(parsed)) return parsed.map(String);
        } catch { /* fall through to comma-separated */ }
    }
    return trimmed.split(',').map((s) => s.trim()).filter(Boolean);
};

export const parseJsonArray = (val: any): string[] => {
    if (Array.isArray(val)) return val.map(String);
    if (typeof val === 'string') {
        try { const parsed = JSON.parse(val); return Array.isArray(parsed) ? parsed.map(String) : []; }
        catch { return []; }
    }
    return [];
};

/** Render an array (or JSON string) as comma-separated badges */
export const BadgeList: React.FC<{ items: any }> = ({ items }) => {
    const arr = parseJsonArray(items);
    if (arr.length === 0) return <span className="text-gray-600 text-xs">None</span>;
    return (
        <div className="flex flex-wrap gap-1">
            {arr.map((v, i) => (
                <span key={i} className="px-2 py-0.5 text-xs rounded bg-blue-50 dark:bg-blue-900/40 text-blue-800 dark:text-blue-300 border border-blue-300 dark:border-blue-800">{v}</span>
            ))}
        </div>
    );
};

/** Multi-select toggle buttons for an array field */
export const MultiToggle: React.FC<{
    options: readonly string[];
    selected: string[];
    onChange: (next: string[]) => void;
    formatLabel?: (opt: string) => string;
}> = ({ options, selected, onChange, formatLabel }) => (
    <div className="flex flex-wrap gap-2">
        {options.map((opt) => {
            const active = selected.includes(opt);
            return (
                <button key={opt} type="button"
                    onClick={() => onChange(active ? selected.filter((v) => v !== opt) : [...selected, opt])}
                    className={`px-2 py-1 text-xs rounded border transition-colors ${active ? 'bg-blue-50 dark:bg-blue-900/50 text-blue-800 dark:text-blue-300 border-blue-300 dark:border-blue-700' : 'bg-gray-50 dark:bg-gray-900 text-gray-600 dark:text-gray-400 border-gray-300 dark:border-gray-700 hover:border-gray-500'}`}>
                    {formatLabel ? formatLabel(opt) : opt}
                </button>
            );
        })}
    </div>
);

/** Decorates RSA 7680 / 8192 with a "(high compute)" hint so profile authors and
 *  cert requesters know those sizes carry significant keygen overhead. */
export const formatKeySizeLabel = (size: string) =>
    (size === '7680' || size === '8192') ? `${size} (high compute)` : size;

/** Field source indicator for resolved profile views */
export const FieldSourceBadge: React.FC<{ source?: string }> = ({ source }) => {
    if (!source) return null;
    const isOverridden = source === 'overridden';
    return (
        <span className={`ml-2 px-1.5 py-0.5 text-[10px] rounded border ${isOverridden
            ? 'bg-green-50 dark:bg-green-900/40 text-green-800 dark:text-green-300 border-green-300 dark:border-green-700'
            : 'bg-gray-200 dark:bg-gray-700/40 text-gray-600 dark:text-gray-400 border-gray-400 dark:border-gray-600'}`}>
            {isOverridden ? 'overridden' : 'inherited'}
        </span>
    );
};

/** Wrapper that adds a colored left border based on field source */
export const SourceBorderedField: React.FC<{ source?: string; label: string; value?: string | null }> = ({ source, label, value }) => {
    const borderColor = source === 'overridden' ? 'border-l-green-500' : source === 'inherited' ? 'border-l-gray-500' : '';
    return (
        <div className={`pl-3 border-l-2 ${borderColor}`}>
            <div className="flex items-center">
                <span className="text-xs text-gray-600 dark:text-gray-400">{label}</span>
                <FieldSourceBadge source={source} />
            </div>
            <span className="text-sm text-gray-900 dark:text-white">{value || '-'}</span>
        </div>
    );
};
