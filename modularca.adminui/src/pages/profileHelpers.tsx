import React from 'react';
import { KEY_USAGE_NAMES, canonicalizeUsage } from '@shared/generated';
import { inputClass, labelClass, FieldHint } from '@shared/components/forms';
import { formatIso8601Duration } from './validityCeiling';

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
/**
 * A certificate authority has TWO ids, and picking the wrong one is silent.
 *
 * `/api/v1/admin/authorities` returns both `id` (the CertificateAuthorities row) and
 * `certificateId` (the CA's own certificate). Different fields key on different ones:
 *
 *   - CA scope on a certificate, request or SSH request profile is a foreign key to the CA ROW.
 *   - A signing profile's issuer, and a CRL schedule's caCertificateId, key on the CERTIFICATE.
 *
 * Every CA `<select>` used to be written `value={a.certificateId || a.id}`, which is right for the
 * second group and wrong for the first. The failure is not uniform, which is what made it hard to
 * see: CertProfiles and RequestProfiles carry a real foreign key, so posting a certificate id was
 * rejected outright and CA-scoping a profile simply failed — but only for a CA that had already
 * been issued a certificate, because a CA without one fell through to `|| a.id` and worked.
 * SshRequestProfiles have no such constraint, so there the wrong id was stored without complaint
 * and the profile ended up scoped to a CA that does not exist.
 *
 * These two helpers exist so the choice has to be made explicitly at each call site.
 */

/** The CertificateAuthorities row id — for anything named `certificateAuthorityId`. */
export const caRowId = (ca: any): string => ca?.id ?? '';

/** The CA's certificate id — for a signing profile issuer or a CRL schedule. */
export const caCertId = (ca: any): string => ca?.certificateId ?? '';

/** Display name for a CA, falling back through the fields the API may populate. */
export const caDisplayName = (ca: any): string =>
    ca?.name || ca?.commonName || ca?.label || ca?.id || '';

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

/**
 * Renders a *ceiling* list — one where an empty value means "unrestricted", not "nothing".
 *
 * Seven fields carry this inverted semantic: a signing profile's AllowedEKUs and
 * AllowedAlgorithms and a cert profile's AllowedKeyAlgorithms / AllowedKeySizes /
 * AllowedSignatureAlgorithms (all gated on `?.Count > 0` in IssuanceValidationService), plus an
 * SSH cert profile's AllowedExtensions and AllowedPrincipalPatterns (AdminSshController).
 * SSH RequiredExtensions is deliberately NOT one of them — it is a floor, so "None" is correct. Rendering those
 * through the plain BadgeList printed "None", telling the operator the ceiling permitted nothing
 * at the exact moment it permitted everything — which is how an EKU that was present in both the
 * catalog and the cert profile could vanish at issuance with nothing on screen to explain it.
 */
export const CeilingList: React.FC<{ items: any; raw?: any; noun?: string }> = ({ items, raw, noun = 'value' }) => {
    // A field that has not loaded yet is unknown, not unrestricted. Rendering the affirmative
    // claim during a fetch would flash a statement about policy that may be false once the data
    // arrives, so undefined/null is held back instead.
    if (items === undefined || items === null) {
        return <span className="text-xs text-gray-600 dark:text-gray-400">—</span>;
    }

    // Emptiness is decided from `raw` when supplied, because the labelled list is lossy:
    // canonicalizeUsages drops any entry it cannot resolve against the catalog, and the catalog
    // falls back to a hardcoded subset before its fetch resolves or if that fetch fails. Deciding
    // from the labelled list would print an affirmative "Unrestricted" for a ceiling that does
    // restrict — a worse failure than the "None" this replaced, because it is a confident claim
    // rather than a vague one. When labels are unavailable, show the raw values instead.
    // parseListField, not parseJsonArray: these fields legitimately arrive as a JSON array, as a
    // comma-separated string, or as a real array (SigningProfileService stores AllowedAlgorithms
    // verbatim while normalising AllowedEKUs on the adjacent line, and PolicySyncService writes
    // operator YAML straight through). parseJsonArray returns [] for every shape but the first,
    // which would print an affirmative "Unrestricted" over a ceiling that does restrict.
    const source = parseListField(raw !== undefined ? raw : items);
    if (source.length === 0) {
        return (
            <span className="text-xs text-amber-600 dark:text-amber-400">
                Unrestricted — every {noun} is permitted
            </span>
        );
    }
    // Show labels only when every entry resolved. canonicalizeUsages drops what it cannot match,
    // so a partially-resolved list (a custom OID, or the catalog fetch still in flight) would
    // display fewer restrictions than the ceiling actually imposes.
    const labelled = parseListField(items);
    return <BadgeList items={labelled.length === source.length ? labelled : source} />;
};

/** Multi-select toggle buttons for an array field */
/**
 * Warns that the picker above is offering values the server's OID catalog does not hold.
 *
 * A profile built from one of these cannot issue. IssuanceValidationService resolves usages
 * against that same catalog, finds nothing, and refuses with MCA-POL-000 — whose message is about
 * the profile's spelling, which sends the reader to the one place the fault is not. The gap
 * belongs here, where the choice is made, rather than at enrollment.
 *
 * Renders nothing on a healthy installation, which is the normal case and should be silent.
 */
export const CatalogGapNotice: React.FC<{ missing: string[]; kind: string }> = ({ missing, kind }) => {
    if (missing.length === 0) return null;
    return (
        <p className="mt-1 text-xs text-amber-800 dark:text-amber-300">
            {missing.length} {kind}{missing.length === 1 ? '' : 's'} offered here{' '}
            {missing.length === 1 ? 'is' : 'are'} missing from the server&apos;s OID catalog
            ({missing.join(', ')}). A profile using {missing.length === 1 ? 'it' : 'them'} will be
            refused at issuance. Add the missing entries under OID options, or run the catalog
            backfill.
        </p>
    );
};

export const MultiToggle: React.FC<{
    options: readonly string[];
    selected: string[];
    onChange: (next: string[]) => void;
    formatLabel?: (opt: string) => string;
    /** Native tooltip per chip, for options whose name alone does not say what they do. */
    titleFor?: (opt: string) => string | undefined;
    /**
     * Helper text under the chips. Pass {@link CEILING_HINT} for every "Allowed …" list so the
     * editor says the same thing {@link CeilingList} says on the read-only side: an empty
     * selection is unrestricted, not empty.
     */
    hint?: React.ReactNode;
    /** Warn-tone line under the hint, shown only when set. */
    warning?: React.ReactNode;
}> = ({ options, selected, onChange, formatLabel, titleFor, hint, warning }) => (
    <>
        <div className="flex flex-wrap gap-2">
            {options.map((opt) => {
                const active = selected.includes(opt);
                return (
                    <button key={opt} type="button" title={titleFor ? titleFor(opt) : undefined}
                        onClick={() => onChange(active ? selected.filter((v) => v !== opt) : [...selected, opt])}
                        className={`px-2 py-1 text-xs rounded border transition-colors ${active ? 'bg-blue-50 dark:bg-blue-900/50 text-blue-800 dark:text-blue-300 border-blue-300 dark:border-blue-700' : 'bg-gray-50 dark:bg-gray-900 text-gray-600 dark:text-gray-400 border-gray-300 dark:border-gray-700 hover:border-gray-500'}`}>
                        {formatLabel ? formatLabel(opt) : opt}
                    </button>
                );
            })}
        </div>
        {hint && <FieldHint>{hint}</FieldHint>}
        {warning && <FieldHint tone="warn">{warning}</FieldHint>}
    </>
);

/**
 * The one sentence every "Allowed …" editor shows under its chips.
 *
 * It is the editing-side twin of the "Unrestricted — every … is permitted" line CeilingList
 * prints on the read-only side. The two were written together so an operator who reads one and
 * then the other is told the same thing about the same empty list.
 */
export const CEILING_HINT = 'Leave every option off to allow all of them. These are ceilings: none selected means unrestricted, not none.';

/**
 * Hint for a cert profile's Key Usages / Extended Key Usages pickers, which are NOT ceilings.
 *
 * IssuanceValidationService stamps these into the issued certificate (after the signing
 * profile's Allowed EKUs ceiling has filtered them). An empty list therefore means the extension
 * is omitted, which is the opposite of what the "Allowed …" lists a few rows down mean, and the
 * two kinds of picker look identical. Saying so here is what keeps them apart.
 */
export const REQUESTED_USAGE_HINT = 'Written into every certificate issued with this profile. Leave empty to omit the extension. The signing profile’s Allowed EKUs may still drop entries it does not permit.';

/** Tooltip text for each SSH certificate extension the pickers offer. */
export const SSH_EXTENSION_TITLES: Record<string, string> = {
    'permit-pty': 'Allows the session to allocate a terminal (interactive shell).',
    'permit-port-forwarding': 'Allows TCP port forwarding (ssh -L / -R / -D).',
    'permit-agent-forwarding': 'Allows the SSH agent to be forwarded to the remote host.',
    'permit-X11-forwarding': 'Allows X11 display forwarding.',
    'permit-user-rc': 'Allows ~/.ssh/rc to run on login.',
    'no-pty': 'Explicitly denies terminal allocation; the certificate can run commands but not open a shell.',
    'no-port-forwarding': 'Explicitly denies TCP port forwarding.',
    'no-agent-forwarding': 'Explicitly denies SSH agent forwarding.',
    'no-X11-forwarding': 'Explicitly denies X11 forwarding.',
    'no-user-rc': 'Explicitly denies running ~/.ssh/rc on login.',
};
export const sshExtensionTitle = (ext: string): string | undefined => SSH_EXTENSION_TITLES[ext];

/**
 * Expands the compact rendering formatIso8601Duration produces ("1y 6mo", "12h") into words
 * ("1 year 6 months", "12 hours") for the live preview under a validity input.
 */
const expandCompactDuration = (compact: string): string => {
    const words: Record<string, [string, string]> = {
        y: ['year', 'years'], mo: ['month', 'months'], w: ['week', 'weeks'], d: ['day', 'days'],
        h: ['hour', 'hours'], min: ['minute', 'minutes'], s: ['second', 'seconds'],
    };
    return compact.split(' ').map((tok) => {
        const m = /^(\d+)(y|mo|w|d|h|min|s)$/.exec(tok);
        if (!m) return tok;
        const n = Number(m[1]);
        const [one, many] = words[m[2]];
        return `${n} ${n === 1 ? one : many}`;
    }).join(' ');
};

/**
 * Helper text under a "Validity Period Min/Max" or "Max Validity Period" input.
 *
 * States the format with worked examples, names the other two layers that can shorten a
 * certificate (tenant cap and issuing CA expiry) so the operator does not treat this field as the
 * final word, and previews the parsed value live. formatIso8601Duration echoes anything it does
 * not recognise verbatim, so "output equals input" is the parse-failure signal.
 */
export const DurationHint: React.FC<{ value: string; id?: string }> = ({ value, id }) => {
    const trimmed = value.trim();
    const compact = trimmed ? formatIso8601Duration(trimmed) : null;
    const parsed = compact !== null && compact !== trimmed;
    return (
        <>
            <FieldHint id={id}>
                ISO 8601 duration: P90D is 90 days, P1Y one year, P18M eighteen months, PT12H twelve hours.
                The certificate&apos;s real ceiling is the strictest of this profile, the tenant&apos;s cap and the issuing CA&apos;s own expiry.
                {parsed && <> <span className="font-medium">= {expandCompactDuration(compact!)}</span></>}
            </FieldHint>
            {trimmed && !parsed && (
                <FieldHint tone="warn">
                    &ldquo;{trimmed}&rdquo; is not a recognised ISO 8601 duration. It must start with P, use whole numbers, and put time units after a T (for example P1Y6M or PT36H).
                </FieldHint>
            )}
        </>
    );
};

/**
 * True when the Inherits From / Enable Inheritance pair disagree.
 *
 * ProfileResolutionService applies a parent only when BOTH `InheritanceEnabled` is true and
 * `InheritsFromId` is set, so either half on its own is a no-op the server accepts silently. The
 * create and edit forms block Save on this instead of storing a setting that does nothing.
 */
export const inheritancePairInconsistent = (inheritsFromId: string, inheritanceEnabled: boolean): boolean =>
    (!!inheritsFromId && !inheritanceEnabled) || (!inheritsFromId && inheritanceEnabled);

/**
 * The explanatory line under an "Enable Inheritance" checkbox, plus the warn line when the pair
 * above is inconsistent. Rendered once per form so the four X.509 profile surfaces say the same
 * thing.
 */
export const InheritanceHint: React.FC<{ inheritsFromId: string; inheritanceEnabled: boolean }> = ({ inheritsFromId, inheritanceEnabled }) => (
    <>
        <FieldHint>
            Inheritance applies only when this is on and a parent is chosen above. The parent sets the baseline; this profile may only make it stricter. Blank fields here take the parent&apos;s value.
        </FieldHint>
        {inheritsFromId && !inheritanceEnabled && (
            <FieldHint tone="warn">A parent is selected but inheritance is off, so it has no effect.</FieldHint>
        )}
        {!inheritsFromId && inheritanceEnabled && (
            <FieldHint tone="warn">Inheritance is on but no parent is selected.</FieldHint>
        )}
    </>
);

/**
 * Warn line placed beside a disabled Create/Save button, naming what is still missing so the
 * operator is told before clicking rather than after.
 */
export const SubmitBlockedHint: React.FC<{ reasons: (string | false | null | undefined)[] }> = ({ reasons }) => {
    const active = reasons.filter((r): r is string => typeof r === 'string' && r.length > 0);
    if (active.length === 0) return null;
    return <FieldHint tone="warn">{active.join(' ')}</FieldHint>;
};

/**
 * Hint under a signing profile's single-line Name Constraints JSON inputs.
 *
 * CertificateBuilderService.ParseSubtrees reads a JSON array of "TYPE:value" strings, where TYPE
 * is DNS, IP, EMAIL, URI or DN. The old placeholder showed an object ({"permitted":[...]}), which
 * that parser cannot read at all.
 */
export const NAME_CONSTRAINTS_HINT = 'A JSON array of "TYPE:value" strings, TYPE being DNS, IP, EMAIL, URI or DN, for example ["DNS:example.com", "EMAIL:example.com", "IP:10.0.0.0/255.0.0.0"]. Entries in any other shape are ignored. Leave blank for no constraint.';
export const NAME_CONSTRAINTS_PLACEHOLDER = '["DNS:example.com", "EMAIL:example.com"]';

/** Hint under a signing profile's Max Path Length input. */
export const MAX_PATH_LENGTH_HINT = 'How many more CA levels may sit below this one; 0 means it may issue end-entity certificates only. Leave blank to omit the path length constraint.';

/**
 * Hint under a cert profile's CT Log IDs input. CertificateIssuanceService passes an empty list
 * as null to CtSubmissionService, which then submits to every enabled CT log, and a submission
 * failure is logged and never blocks issuance.
 */
export const CT_LOG_IDS_HINT = 'JSON array of CT log IDs to submit to, for example ["<log-id>", "<log-id>"]. Only read when CT Enabled is on. Leave blank to submit to every enabled CT log; if no CT log is enabled, nothing is submitted and the certificate is still issued. A failed submission is logged and never blocks issuance.';

/** Hint under a cert profile's CT Enabled checkbox; the read-only twin of {@link CT_LOG_IDS_HINT}. */
export const CT_ENABLED_HINT = 'When on, each issued certificate is submitted to the CT logs listed in CT Log IDs, or to every enabled log if that field is blank. A parent profile with CT on cannot be turned off here.';

/** Hint under an SSH signing profile's Force Command input. */
export const FORCE_COMMAND_HINT = 'Every session using a certificate from this profile runs this command instead of the one the user asked for, including scp and sftp. Leave blank for normal shell access.';

/**
 * Hint under an SSH cert profile's Required Extensions picker.
 *
 * Both issuance controllers check the caller's requested extensions against Allowed first and
 * append Required afterwards, so a required-but-not-allowed extension is still written into every
 * certificate while a caller who asks for it by name is refused. The forms block save on that.
 */
export const SSH_REQUIRED_EXTENSIONS_HINT = 'Required must be a subset of Allowed. Required extensions are added to every certificate after the Allowed check, so one that is required here but not allowed above still lands in the certificate while a requester who names it explicitly is refused. Save is blocked until the two agree.';

/** Returns the SSH extensions required but not allowed; empty when Allowed is unrestricted. */
export const sshRequiredNotAllowed = (required: string[], allowed: string[]): string[] =>
    allowed.length === 0 ? [] : required.filter((r) => !allowed.includes(r));

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
