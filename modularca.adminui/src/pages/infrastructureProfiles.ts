import type { NamedUsage } from '@shared/generated';
import { infrastructureGroup, type ConstraintGroup } from './profileConstraints';

/** A certificate a CA issues to itself, with the profile it is issued under. */
export interface InfrastructureRole {
    key: string;
    name: string;
    defaultProfileName: string;
    /** The seeded default profile's id; null when it does not exist yet. */
    defaultProfileId?: string | null;
    /** The profile the CA names; null when it uses the default. */
    chosenProfileId: string | null;
    profileId: string | null;
    profileName: string | null;
    /** Why the profile in effect cannot do the job; null when it can. */
    problem: string | null;
}

/** An end-entity profile the CA may issue under, with the roles it suits and what it gives a certificate. */
export interface InfrastructureCandidate {
    id: string;
    name: string;
    suits: string[];
    keyUsages?: string[];
    extendedKeyUsages?: NamedUsage[];
    validityPeriodMin?: string | null;
    validityPeriodMax?: string | null;
}

export interface InfrastructureProfilesAnswer {
    roles: InfrastructureRole[];
    candidates: InfrastructureCandidate[];
    /** The key these certificates are given, which follows the CA's key. */
    subjectKey?: string | null;
    /** The lifetime asked for, before the profile and the CA shorten it. */
    lifetimeYears?: number;
    caNotAfter?: string | null;
}

/** What each picker holds: the role's key to a profile id, '' for the default. */
export type InfrastructureChoices = Record<string, string>;

export const DEFAULT_CHOICE = '';

/** The saved choices, as the pickers start. */
export function savedChoices(roles: InfrastructureRole[]): InfrastructureChoices {
    return Object.fromEntries(roles.map((r) => [r.key, r.chosenProfileId ?? DEFAULT_CHOICE]));
}

/**
 * The profiles a role's picker offers beside the default: those that suit it, without the
 * default profile itself, and the one it names now even when that one no longer suits, so a
 * saved choice is never missing from its own picker. The default profiles of the other roles
 * (<paramref name="otherDefaults"/>) are left out: each exists for its own certificate.
 */
export function choicesFor(role: InfrastructureRole, candidates: InfrastructureCandidate[], otherDefaults: string[] = []): InfrastructureCandidate[] {
    return candidates.filter((c) => c.id === role.chosenProfileId
        || (c.suits.includes(role.key) && c.name !== role.defaultProfileName && !otherDefaults.includes(c.name)));
}

/** The default profile names of every role but <paramref name="role"/>. */
export function otherDefaultNames(role: InfrastructureRole, roles: InfrastructureRole[]): string[] {
    return roles.filter((r) => r.key !== role.key).map((r) => r.defaultProfileName);
}

/** The roles whose picker differs from what is saved. */
export function changedRoles(roles: InfrastructureRole[], choices: InfrastructureChoices): InfrastructureRole[] {
    return roles.filter((r) => (choices[r.key] ?? DEFAULT_CHOICE) !== (r.chosenProfileId ?? DEFAULT_CHOICE));
}

/** The body of the save: every role's profile id, null for the default. */
export function toRequest(choices: InfrastructureChoices): Record<string, string | null> {
    const id = (key: string) => choices[key] || null;
    return {
        ocspResponderCertProfileId: id('ocspResponder'),
        tsaCertProfileId: id('tsa'),
        cmpSignerCertProfileId: id('cmpSigner'),
    };
}

/**
 * What each certificate gets from the profile its picker holds now, saved or not: a group to a
 * role, in the roles' order. The server's problem for a role is about the saved profile, so it
 * is shown only while the picker still holds that one.
 */
export function roleConstraintGroups(answer: InfrastructureProfilesAnswer, choices: InfrastructureChoices): ConstraintGroup[] {
    return answer.roles.map((role) => {
        const held = choices[role.key] ?? DEFAULT_CHOICE;
        const shownId = held || role.defaultProfileId || null;
        const profile = answer.candidates.find((c) => c.id === shownId);
        const saved = held === (role.chosenProfileId ?? DEFAULT_CHOICE);
        return infrastructureGroup(roleLabel(role), profile && {
            name: profile.name,
            keyUsages: profile.keyUsages ?? [],
            extendedKeyUsages: profile.extendedKeyUsages ?? [],
            validityPeriodMin: profile.validityPeriodMin,
            validityPeriodMax: profile.validityPeriodMax,
        }, saved ? role.problem : null);
    });
}

/**
 * What all three certificates get whatever their profile: the key, which follows the CA's, and
 * the lifetime, which the profile's longest validity and the CA's own expiry shorten.
 */
export function sharedConstraintGroup(answer: InfrastructureProfilesAnswer, formatDate: (iso: string) => string): ConstraintGroup {
    const years = answer.lifetimeYears ?? 10;
    return {
        title: 'All three',
        lines: [
            { label: 'Key', value: answer.subjectKey ? `${answer.subjectKey}, following the CA's key` : "Follows the CA's key" },
            {
                label: 'Lifetime',
                value: `${years} years, or less where the profile's longest validity is shorter`
                    + (answer.caNotAfter ? `; never past the CA's expiry on ${formatDate(answer.caNotAfter)}` : ''),
            },
        ],
    };
}

/** A certificate profile row, as far as its uses go. */
interface ProfileUses {
    systemPurpose?: string | null;
    infrastructureUses?: string[] | null;
}

/** Whether the server will refuse to delete the profile: it is found by name, or a CA names it. */
export function certProfileInUse(profile: ProfileUses): boolean {
    return !!profile.systemPurpose || (profile.infrastructureUses?.length ?? 0) > 0;
}

/** Why the profile is in use, in one line; '' when it is not. */
export function certProfileUseText(profile: ProfileUses): string {
    const parts: string[] = [];
    if (profile.systemPurpose) parts.push(`Found by name: ${profile.systemPurpose}.`);
    if (profile.infrastructureUses?.length) parts.push(`Named by ${profile.infrastructureUses.join('; ')}.`);
    return parts.join(' ');
}

/** The label of a role's picker. */
export function roleLabel(role: InfrastructureRole): string {
    switch (role.key) {
        case 'ocspResponder': return 'OCSP responder';
        case 'tsa': return 'TSA signer';
        case 'cmpSigner': return 'CMP signer';
        default: return role.name;
    }
}
