import React from 'react';

/* Shared constants + helper components for the Profile Management tabs and their detail pages. */

export const KEY_USAGE_OPTIONS = [
    'digitalSignature', 'keyEncipherment', 'keyCertSign', 'crlSign',
];
/**
 * Certificate-profile usage option values.
 *
 * These are the values PERSISTED into CertProfile.KeyUsages / ExtendedKeyUsages, so they must be the
 * canonical forms the issuance path resolves against OIDOptions — EKUs as OIDs, key usages as the
 * catalog's friendly names. They previously held display labels ('Server Auth', 'Digital Signature'),
 * which matched no catalog row, so any cert profile edited in the admin UI was issued with NO
 * ExtendedKeyUsage and NO KeyUsage extension. Use the *_LABELS maps for presentation only.
 */
export const EKU_OPTIONS = [
    '1.3.6.1.5.5.7.3.1', '1.3.6.1.5.5.7.3.2', '1.3.6.1.5.5.7.3.3',
    '1.3.6.1.5.5.7.3.4', '1.3.6.1.5.5.7.3.8', '1.3.6.1.5.5.7.3.9',
];

export const EKU_LABELS: Record<string, string> = {
    '1.3.6.1.5.5.7.3.1': 'Server Auth',
    '1.3.6.1.5.5.7.3.2': 'Client Auth',
    '1.3.6.1.5.5.7.3.3': 'Code Signing',
    '1.3.6.1.5.5.7.3.4': 'Email Protection',
    '1.3.6.1.5.5.7.3.8': 'Time Stamping',
    '1.3.6.1.5.5.7.3.9': 'OCSP Signing',
};

export const ekuLabel = (v: string): string => EKU_LABELS[v] ?? v;

export const KEY_USAGE_LABELS: Record<string, string> = {
    digitalSignature: 'Digital Signature',
    keyEncipherment: 'Key Encipherment',
    keyCertSign: 'Key Cert Sign',
    crlSign: 'CRL Sign',
};

export const keyUsageLabel = (v: string): string => KEY_USAGE_LABELS[v] ?? v;

export const ALLOWED_KEY_ALGORITHM_OPTIONS = [
    'RSA', 'ECDSA', 'Ed25519', 'Ed448', 'ML-DSA-44', 'ML-DSA-65', 'ML-DSA-87', 'SLH-DSA-SHA2-128F',
];
export const ALLOWED_KEY_SIZE_OPTIONS = [
    '2048', '3072', '4096', '7680', '8192', 'P-256', 'P-384', 'P-521',
];
export const ALLOWED_SIGNATURE_ALGORITHM_OPTIONS = [
    'SHA256withRSA', 'SHA384withRSA', 'SHA512withRSA',
    'SHA256withECDSA', 'SHA384withECDSA', 'SHA512withECDSA',
    'Ed25519', 'Ed448',
    'ML-DSA-44', 'ML-DSA-65', 'ML-DSA-87', 'SLH-DSA-SHA2-128F',
];

export const SIGNING_ALLOWED_ALGORITHM_OPTIONS = ['RSA', 'ECDSA', 'Ed25519', 'Ed448', 'ML-DSA-44', 'ML-DSA-65', 'ML-DSA-87', 'SLH-DSA-SHA2-128F'];

/** Common EKU OIDs with display names for signing profile EKU picker */
export const SIGNING_EKU_OPTIONS: { oid: string; label: string }[] = [
    { oid: '1.3.6.1.5.5.7.3.1', label: 'Server Auth' },
    { oid: '1.3.6.1.5.5.7.3.2', label: 'Client Auth' },
    { oid: '1.3.6.1.5.5.7.3.3', label: 'Code Signing' },
    { oid: '1.3.6.1.5.5.7.3.4', label: 'Email Protection' },
    { oid: '1.3.6.1.5.5.7.3.8', label: 'Time Stamping' },
    { oid: '1.3.6.1.5.5.7.3.9', label: 'OCSP Signing' },
];

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
    options: string[];
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
