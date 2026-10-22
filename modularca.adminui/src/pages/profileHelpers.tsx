import React from 'react';
import { DEFAULT_EKU_OPTIONS, parseJsonArray, parseListField } from './profiles/profileFormCore';
import { FieldHint } from '@shared/components/forms';
import { formatIso8601Duration } from './validityCeiling';
import { DEFAULT_EKU_LABELS, KEY_USAGE_LABELS } from './profiles/usageLabels';

/* Shared constants + helper components for the Profile Management tabs and their detail pages. */

export {
    KEY_USAGE_OPTIONS, DEFAULT_EKU_OPTIONS, DEFAULT_EKU_ALIASES, normalizeUsageKey, canonicalizeUsages,
    parseListField, parseJsonArray, inheritancePairInconsistent, sshRequiredNotAllowed,
} from './profiles/profileFormCore';

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

// The label tables live in a module with no React in it, so pure code can read them too.
export { DEFAULT_EKU_LABELS, KEY_USAGE_LABELS } from './profiles/usageLabels';

export const keyUsageLabel = (v: string): string => KEY_USAGE_LABELS[v] ?? v;

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


/** Render an array (or JSON string) as comma-separated badges */
export const BadgeList: React.FC<{ items: any }> = ({ items }) => {
    const arr = parseJsonArray(items);
    if (arr.length === 0) return <span className="text-ink-muted text-xs">None</span>;
    return (
        <div className="flex flex-wrap gap-1">
            {arr.map((v, i) => (
                <span key={i} className="px-2 py-0.5 text-xs rounded bg-accent-soft text-accent-ink border border-accent/40">{v}</span>
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
        return <span className="text-xs text-ink-muted">—</span>;
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
            <span className="text-xs text-warn">
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
        <p className="mt-1 text-xs text-warn">
            {missing.length} {kind}{missing.length === 1 ? '' : 's'} offered here{' '}
            {missing.length === 1 ? 'is' : 'are'} missing from the server&apos;s OID catalog
            ({missing.join(', ')}). A profile using {missing.length === 1 ? 'it' : 'them'} will be
            refused at issuance. Add the missing entries under OID options, or run the catalog
            backfill.
        </p>
    );
};

/**
 * Hint for a cert profile's Key Usages / Extended Key Usages lists, which are NOT ceilings.
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
    'no-pty': 'Withholds permit-pty, even when it is also named: the certificate can run commands but not open a shell. Adds nothing to the certificate.',
    'no-port-forwarding': 'Withholds permit-port-forwarding, even when it is also named. Adds nothing to the certificate.',
    'no-agent-forwarding': 'Withholds permit-agent-forwarding, even when it is also named. Adds nothing to the certificate.',
    'no-X11-forwarding': 'Withholds permit-X11-forwarding, even when it is also named. Adds nothing to the certificate.',
    'no-user-rc': 'Withholds permit-user-rc, even when it is also named. Adds nothing to the certificate.',
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
 * certificate (space cap and issuing CA expiry) so the operator does not treat this field as the
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
                The certificate&apos;s real ceiling is the strictest of this profile, the space&apos;s cap and the issuing CA&apos;s own expiry.
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

/** Hint under a signing profile's Max Path Length input. */
export const MAX_PATH_LENGTH_HINT = 'How many more CA levels may sit below this one; 0 means it may issue end-entity certificates only. Leave blank to omit the path length constraint.';

/**
 * Hint under a cert profile's CT Logs picker. A blank CtLogIds makes CtSubmissionService submit
 * to every enabled log; a list is filtered to its enabled logs, so a list of disabled logs submits
 * nothing. A blank child inherits its parent's list (ProfileResolutionService). A submission
 * failure is logged and never blocks issuance.
 */
export const CT_LOG_IDS_HINT = 'Every enabled log submits each issued certificate to every CT log enabled at the time; on a profile that inherits, the parent profile decides instead. Only these logs submits to the ticked logs that are enabled, skipping disabled ones, so if none of them is enabled nothing is submitted. A failed submission is logged and never blocks issuance.';

/** Hint under a cert profile's CT Enabled checkbox; {@link CT_LOG_IDS_HINT} explains the log choice. */
export const CT_ENABLED_HINT = 'When on, each issued certificate is submitted to the CT logs chosen below. A parent profile with CT on cannot be turned off here.';

/** Hint under an SSH signing profile's Force Command input. */
export const FORCE_COMMAND_HINT = 'Every session using a certificate from this profile runs this command instead of the one the user asked for, including scp and sftp. Leave blank to force no command.';

/**
 * Hint under an SSH cert profile's Required Extensions picker.
 *
 * Both issuance controllers check the caller's requested extensions against Allowed first and
 * append Required afterwards, so a required-but-not-allowed extension is still written into every
 * certificate while a caller who asks for it by name is refused. The forms block save on that.
 */
export const SSH_REQUIRED_EXTENSIONS_HINT = 'Required must be a subset of Allowed. Required extensions are added to every certificate after the Allowed check, so one that is required here but not allowed above still lands in the certificate while a requester who names it explicitly is refused. Save is blocked until the two agree. A required no-* name withholds its permit-* from every certificate.';

/** Field source indicator for resolved profile views */
export const FieldSourceBadge: React.FC<{ source?: string }> = ({ source }) => {
    if (!source) return null;
    const isOverridden = source === 'overridden';
    return (
        <span className={`ml-2 px-1.5 py-0.5 text-[10px] rounded border ${isOverridden
            ? 'bg-ok-soft text-ok border-ok/40'
            : 'bg-sunken text-ink-muted border-line-strong'}`}>
            {isOverridden ? 'overridden' : 'inherited'}
        </span>
    );
};

/** Wrapper that adds a colored left border based on field source */
export const SourceBorderedField: React.FC<{ source?: string; label: string; value?: string | null }> = ({ source, label, value }) => {
    const borderColor = source === 'overridden' ? 'border-l-ok' : source === 'inherited' ? 'border-l-line-strong' : '';
    return (
        <div className={`pl-3 border-l-2 ${borderColor}`}>
            <div className="flex items-center">
                <span className="text-xs text-ink-muted">{label}</span>
                <FieldSourceBadge source={source} />
            </div>
            <span className="text-sm text-ink">{value || '-'}</span>
        </div>
    );
};
