import { KEY_USAGE_NAMES, canonicalizeUsage } from '@shared/generated';

/*
 * Pure helpers shared by the profile form models. No React here, so the models can be covered by
 * tests/modularca.web.tests; profileHelpers.tsx re-exports everything below for the pages.
 */

/** Whether a profile form is creating a new profile or editing a stored one. */
export type ProfileFormMode = 'create' | 'edit';

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
 * FALLBACK ONLY. The live vocabulary comes from the OID catalog via `useEkuCatalog()`, because
 * the catalog is extensible and this list is not: `canonicalizeUsages` drops what it does not
 * recognise and the result is saved back, so a stale list here silently strips usages from a
 * profile. These entries exist so the pages still render correctly before the catalog fetch
 * resolves, and if it fails.
 *
 * Both this list and KEY_USAGE_OPTIONS are PERSISTED into CertProfile.ExtendedKeyUsages /
 * KeyUsages, so they must be the canonical forms the issuance path resolves against OIDOptions —
 * EKUs as OIDs, key usages as the catalog's friendly names.
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

/**
 * Names that should resolve to an EKU OID.
 *
 * Still hand-written because this maps a NAME onto an OID, and the profile fields store OIDs —
 * `canonicalizeUsage` alone cannot bridge that. One entry per OID is enough: the lookup is keyed by
 * the canonical form, which already folds every spelling of a given usage together.
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

/** The EKU vocabulary a form model canonicalises against; `useEkuCatalog()` satisfies it. */
export interface EkuVocabulary {
    options: readonly string[];
    aliases: Record<string, string>;
}

/** The built-in EKU vocabulary, used until (or unless) the catalog is supplied. */
export const DEFAULT_EKU_VOCABULARY: EkuVocabulary = { options: DEFAULT_EKU_OPTIONS, aliases: DEFAULT_EKU_ALIASES };

/**
 * Comparison key for a usage identifier, re-exported from the generated port of
 * `UsageCatalogResolver` rather than reimplemented.
 */
export const normalizeUsageKey = canonicalizeUsage;

/**
 * Maps stored usage values onto the canonical option values, dropping anything unrecognisable.
 *
 * A profile field can hold the canonical value, the catalog friendly name, an old display label,
 * or fragments of a JSON array written while the CSV/JSON parse bug was live. Canonicalising
 * collapses all of those onto the same key, so the toggles show the real selection and the next
 * save rewrites the field in canonical form. Dropping the unresolvable is only safe while this
 * vocabulary matches the server's, because the result is written straight back on save.
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
 * Reads a list-valued profile field regardless of the shape the API returned it in: a JSON array
 * string, a comma-separated string, or a real array. Splitting a JSON array on ',' yields tokens
 * like `["a"` that match no toggle option, which renders as "nothing selected".
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

/** Parses a JSON array field from the API (string or array) into a string array. */
export const parseJsonArray = (val: any): string[] => {
    if (Array.isArray(val)) return val.map(String);
    if (typeof val === 'string') {
        try { const parsed = JSON.parse(val); return Array.isArray(parsed) ? parsed.map(String) : []; }
        catch { return []; }
    }
    return [];
};

/**
 * True when the Inherits From / Enable Inheritance pair disagree.
 *
 * ProfileResolutionService applies a parent only when BOTH `InheritanceEnabled` is true and
 * `InheritsFromId` is set, so either half on its own is a no-op the server accepts silently. The
 * profile forms block Save on this instead of storing a setting that does nothing.
 */
export const inheritancePairInconsistent = (inheritsFromId: string, inheritanceEnabled: boolean): boolean =>
    (!!inheritsFromId && !inheritanceEnabled) || (!inheritsFromId && inheritanceEnabled);

/** Returns the SSH extensions required but not allowed; empty when Allowed is unrestricted. */
export const sshRequiredNotAllowed = (required: string[], allowed: string[]): string[] =>
    allowed.length === 0 ? [] : required.filter((r) => !allowed.includes(r));

/** An optional text field as the API wants it: null when blank, the text otherwise. */
export const textOrNull = (value: string): string | null => (value ? value : null);

/** Splits a comma-separated input into trimmed, non-empty entries. */
export const splitCommaList = (value: string): string[] =>
    value ? value.split(',').map((s) => s.trim()).filter(Boolean) : [];

export const NAME_REQUIRED_REASON = 'A name is required before the profile can be saved.';
export const INHERITANCE_REASON = 'Save is disabled until the inheritance settings agree: either choose a parent and turn inheritance on, or clear both.';
