/** A certificate a CA issues to itself, with the profile it is issued under. */
export interface InfrastructureRole {
    key: string;
    name: string;
    defaultProfileName: string;
    /** The profile the CA names; null when it uses the default. */
    chosenProfileId: string | null;
    profileId: string | null;
    profileName: string | null;
    /** Why the profile in effect cannot do the job; null when it can. */
    problem: string | null;
}

/** An end-entity profile the CA may issue under, with the roles it suits. */
export interface InfrastructureCandidate {
    id: string;
    name: string;
    suits: string[];
}

export interface InfrastructureProfilesAnswer {
    roles: InfrastructureRole[];
    candidates: InfrastructureCandidate[];
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
 * saved choice is never missing from its own picker.
 */
export function choicesFor(role: InfrastructureRole, candidates: InfrastructureCandidate[]): InfrastructureCandidate[] {
    return candidates.filter((c) => c.id === role.chosenProfileId
        || (c.suits.includes(role.key) && c.name !== role.defaultProfileName));
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
