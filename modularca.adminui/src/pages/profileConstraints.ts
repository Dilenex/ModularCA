import type { NamedUsage, ProfilePairConstraints, ServerKeyOption } from '@shared/generated';
import { periodRangeText } from '@shared/periodText';
import { DEFAULT_EKU_ALIASES } from './profiles/profileFormCore';
import { DEFAULT_EKU_LABELS, KEY_USAGE_LABELS } from './profiles/usageLabels';

/** One fact a profile imposes, as a label and its value. */
export interface ConstraintLine {
    label: string;
    value: string;
    /** `warn` for a line the reader must act on. */
    tone?: 'warn';
}

/** The facts one profile contributes, under the name of what they are about. */
export interface ConstraintGroup {
    title: string;
    /** The profile the facts come from. */
    from?: string;
    lines: ConstraintLine[];
}

/** A subject rule of a request profile, as the request form holds it. */
export interface SubjectRule {
    field: string;
    requirement: string;
    fixedValue?: string | null;
    regex?: string | null;
    maxLength?: number | null;
    defaultValue?: string | null;
}

/** The SAN rules of a request profile, as the request form holds them. */
export interface SanRuleSet {
    allowedTypes: string[];
    required: boolean;
    rules: Record<string, { regex?: string | null; maxCount: number }>;
}

/** What the request form knows of a request profile. */
export interface RequestProfileRules {
    name: string;
    subjectDnRules: SubjectRule[];
    sanRules: SanRuleSet;
    requireApproval: boolean;
    requiredApprovalCount?: number;
}

const is = (requirement: string, wanted: string) => requirement.trim().toLowerCase() === wanted;

/** A key usage in words; a name the console does not know is shown as stored. */
export function keyUsageWords(value: string): string {
    const key = Object.keys(KEY_USAGE_LABELS).find((k) => k.toLowerCase() === value.replace(/[^a-z0-9]/gi, '').toLowerCase());
    return key ? KEY_USAGE_LABELS[key] : value;
}

/** An extended key usage in words: the console's own label for a usage it knows, else the catalog's name. */
export function extendedKeyUsageWords(usage: NamedUsage): string {
    return DEFAULT_EKU_LABELS[usage.value] ?? DEFAULT_EKU_LABELS[DEFAULT_EKU_ALIASES[usage.value]] ?? usage.name;
}

/**
 * What a request profile says about the names of a request: the subject fields it requires,
 * forbids, fixes and fills in, their patterns, the SAN types it allows, and approval.
 */
export function namesGroup(profile: RequestProfileRules): ConstraintGroup {
    const rules = profile.subjectDnRules;
    const lines: ConstraintLine[] = [];
    const fields = (wanted: (r: SubjectRule) => boolean) => rules.filter(wanted).map((r) => r.field).join(', ');

    const required = fields((r) => is(r.requirement, 'required') && !r.fixedValue);
    const forbidden = fields((r) => is(r.requirement, 'forbidden') && !r.fixedValue);
    const fixed = rules.filter((r) => r.fixedValue).map((r) => `${r.field} = ${r.fixedValue}`).join(', ');
    const defaults = rules.filter((r) => r.defaultValue && !r.fixedValue).map((r) => `${r.field} = ${r.defaultValue}`).join(', ');
    const patterns = rules.filter((r) => r.regex).map((r) => `${r.field}: ${r.regex}`);

    if (required) lines.push({ label: 'Required', value: required });
    if (forbidden) lines.push({ label: 'Not allowed', value: forbidden });
    if (fixed) lines.push({ label: 'Set by the profile', value: fixed });
    if (defaults) lines.push({ label: 'Filled in if left out', value: defaults });
    for (const pattern of patterns) lines.push({ label: 'Must match', value: pattern });
    if (lines.length === 0) lines.push({ label: 'Subject', value: 'No rule' });

    const san = profile.sanRules;
    if (san.allowedTypes.length === 0) {
        lines.push({ label: 'SANs', value: 'None allowed' });
    } else {
        const types = san.allowedTypes.map((type) => {
            const rule = Object.entries(san.rules ?? {}).find(([key]) => key.toLowerCase() === type.toLowerCase())?.[1];
            return rule ? `${type} (up to ${rule.maxCount})` : type;
        });
        lines.push({ label: 'SANs', value: `${types.join(', ')}${san.required ? '; at least one' : ''}` });
        for (const [type, rule] of Object.entries(san.rules ?? {})) {
            if (rule.regex) lines.push({ label: 'Must match', value: `${type}: ${rule.regex}` });
        }
    }

    lines.push({
        label: 'Approval',
        value: profile.requireApproval
            ? (profile.requiredApprovalCount && profile.requiredApprovalCount > 1 ? `Required, ${profile.requiredApprovalCount} approvals` : 'Required')
            : 'Not required by this profile',
    });
    return { title: 'Names', from: profile.name, lines };
}

/** Who issues the certificate and which names that CA may sign. */
export function issuerGroup(signingProfileName: string, constraints: ProfilePairConstraints): ConstraintGroup {
    const lines: ConstraintLine[] = [
        { label: 'Issued by', value: constraints.issuingCaName ?? 'No CA: this signing profile names none', tone: constraints.issuingCaName ? undefined : 'warn' },
    ];
    if (constraints.nameConstraintsPermitted.length > 0) lines.push({ label: 'Names limited to', value: constraints.nameConstraintsPermitted.join(', ') });
    if (constraints.nameConstraintsExcluded.length > 0) lines.push({ label: 'Names excluded', value: constraints.nameConstraintsExcluded.join(', ') });
    return { title: 'Issuing CA', from: signingProfileName, lines };
}

/** What the certificate profile gives the certificate and how long it may live. */
export function certificateGroup(certProfileName: string, constraints: ProfilePairConstraints): ConstraintGroup {
    return { title: 'Certificate', from: certProfileName, lines: usageLines(constraints.keyUsages, constraints.extendedKeyUsages, constraints.validityPeriodMin, constraints.validityPeriodMax).concat(
        { label: 'Wildcard names', value: constraints.allowWildcard ? 'Allowed' : 'Not allowed' }) };
}

function usageLines(keyUsages: string[], extendedKeyUsages: NamedUsage[], validityMin: string | null | undefined, validityMax: string | null | undefined): ConstraintLine[] {
    return [
        keyUsages.length > 0
            ? { label: 'Key usage', value: keyUsages.map(keyUsageWords).join(', ') }
            : { label: 'Key usage', value: 'None: the profile lists no key usage', tone: 'warn' as const },
        { label: 'Extended key usage', value: extendedKeyUsages.length > 0 ? extendedKeyUsages.map(extendedKeyUsageWords).join(', ') : 'None' },
        { label: 'Validity', value: periodRangeText(validityMin, validityMax) || 'No limit in the profile' },
    ];
}

/** The keys a profile pair accepts, an algorithm to a line, in the order the server gave. */
export function keysGroup(options: ServerKeyOption[], refusedCount: number): ConstraintGroup {
    const byAlgorithm = new Map<string, string[]>();
    for (const option of options) {
        const sizes = byAlgorithm.get(option.algorithm) ?? [];
        if (option.keySize) sizes.push(option.keySize);
        byAlgorithm.set(option.algorithm, sizes);
    }
    const sized = [...byAlgorithm].filter(([, sizes]) => sizes.length > 0).map(([algorithm, sizes]) => `${algorithm} ${sizes.join(', ')}`);
    const unsized = [...byAlgorithm].filter(([, sizes]) => sizes.length === 0).map(([algorithm]) => algorithm);
    const lines: ConstraintLine[] = options.length === 0
        ? [{ label: 'Accepted', value: 'None: these two profiles accept no key the CA can generate', tone: 'warn' }]
        : [...sized, ...(unsized.length > 0 ? [unsized.join(', ')] : [])].map((value, i) => ({ label: i === 0 ? 'Accepted' : '', value }));
    if (refusedCount > 0 && options.length > 0) lines.push({ label: 'Not accepted', value: `${refusedCount} other key${refusedCount === 1 ? '' : 's'}` });
    return { title: 'Keys', lines };
}

/** A certificate profile as the CA page's profile read lists it. */
export interface InfrastructureProfileFacts {
    name: string;
    keyUsages: string[];
    extendedKeyUsages: NamedUsage[];
    validityPeriodMin?: string | null;
    validityPeriodMax?: string | null;
}

/**
 * What one of a CA's own certificates gets from the profile its picker holds, with the problem
 * of that profile when the server reports one for it.
 */
export function infrastructureGroup(title: string, profile: InfrastructureProfileFacts | undefined, problem: string | null): ConstraintGroup {
    if (!profile) return { title, lines: [{ label: 'Profile', value: problem ?? 'Not found', tone: 'warn' }] };
    const lines = usageLines(profile.keyUsages, profile.extendedKeyUsages, profile.validityPeriodMin, profile.validityPeriodMax);
    lines[2] = { label: 'Profile validity', value: lines[2].value };
    if (problem) lines.push({ label: 'Problem', value: problem, tone: 'warn' });
    return { title, from: profile.name, lines };
}
