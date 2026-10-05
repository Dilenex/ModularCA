/**
 * A ceremony the server would not open because it could never reach its quorum: nobody but the
 * caller, or too few people, can approve it (409, MCA-CFG-020 / MCA-CFG-021). This module reads
 * that refusal and decides which next steps to offer, and words the two related notices: a
 * pending ceremony that is stuck, and a requirement about to be turned on where nobody could
 * approve. Free of React and the router so the web tests cover it.
 */

/** Nobody other than the caller can approve. */
export const CEREMONY_NO_APPROVER = 'MCA-CFG-020';
/** Some can approve, but fewer than the ceremony needs. */
export const CEREMONY_QUORUM_UNREACHABLE = 'MCA-CFG-021';

/** The id of the key-ceremony controls on the Settings page and on a space's page. */
export const KEY_CEREMONIES_ANCHOR = 'key-ceremonies';

/** Where the instance's key-ceremony switch is: the Security tab of Settings. */
export const INSTANCE_CEREMONY_SETTINGS_PATH = `/settings?tab=Security#${KEY_CEREMONIES_ANCHOR}`;

/** Where a space's key-ceremony switch is: its own page. */
export function spaceCeremonySettingsPath(spaceId: string): string {
    return `/spaces/${encodeURIComponent(spaceId)}#${KEY_CEREMONIES_ANCHOR}`;
}

/** Where accounts are added and given roles. */
export const USERS_PATH = '/users';

/** The refusal, as the server reports it. */
export interface CeremonyRefusal {
    code: string;
    /** The server's sentence: who can approve and that nothing was started. */
    detail: string;
    requiredApprovals: number;
    /** Accounts other than the caller that could approve. */
    eligibleApprovers: number;
    /** Whose requirement switch opened the ceremony; null when no switch governs this kind. */
    requirementScope: 'instance' | 'space' | null;
    spaceId: string | null;
    spaceName: string | null;
    /** True only for a system super-administrator, who may turn that switch off directly. */
    canDisableRequirement: boolean;
}

const isRecord = (v: unknown): v is Record<string, unknown> => !!v && typeof v === 'object' && !Array.isArray(v);
const text = (v: unknown): string | null => (typeof v === 'string' && v.trim() ? v : null);
const count = (v: unknown): number => (typeof v === 'number' && Number.isFinite(v) && v > 0 ? Math.floor(v) : 0);

/**
 * Reads the refusal from what the API client threw, or null for any other failure. Takes the
 * error structurally (`status`, `problem.code`, `problem.detail`, `problem.raw`) so it needs no
 * import from the client.
 */
export function readCeremonyRefusal(err: unknown): CeremonyRefusal | null {
    if (!isRecord(err) || err.status !== 409 || !isRecord(err.problem)) return null;
    const code = text(err.problem.code);
    if (code !== CEREMONY_NO_APPROVER && code !== CEREMONY_QUORUM_UNREACHABLE) return null;
    const raw = isRecord(err.problem.raw) ? err.problem.raw : {};
    const named = raw.requirementScope === 'instance' || raw.requirementScope === 'space' ? raw.requirementScope : null;
    const spaceId = named === 'space' ? text(raw.spaceId) : null;
    // A space switch the response cannot name is no switch the console can link to.
    const scope = named === 'space' && !spaceId ? null : named;
    return {
        code,
        detail: text(err.problem.detail) ?? text(raw.detail) ?? text(raw.error)
            ?? (code === CEREMONY_NO_APPROVER ? 'You’re the only administrator who can approve this.' : 'Too few administrators can approve this.'),
        requiredApprovals: Math.max(1, count(raw.requiredApprovals)),
        eligibleApprovers: count(raw.eligibleApprovers),
        requirementScope: scope,
        spaceId,
        spaceName: scope === 'space' ? text(raw.spaceName) : null,
        canDisableRequirement: raw.canDisableRequirement === true && scope !== null,
    };
}

/** What the person looking at the refusal may open. */
export interface RefusalViewer {
    /** Holds system.manage at system scope: Settings and the space pages admit them. */
    isSystemAdmin: boolean;
    /** Holds user.manage at system scope: the Users page admits them. */
    canManageUsers: boolean;
}

/** One next step, as a link inside the console. */
export interface RefusalLink {
    key: 'instance-switch' | 'space-switch' | 'add-administrator';
    label: string;
    to: string;
}

/**
 * The next steps to offer, each only when the viewer can take it: the switch for the scope that
 * opened the ceremony (a super who can open that page), and adding an administrator (a viewer
 * who manages users).
 */
export function ceremonyRefusalLinks(refusal: CeremonyRefusal, viewer: RefusalViewer): RefusalLink[] {
    const links: RefusalLink[] = [];
    if (refusal.canDisableRequirement && viewer.isSystemAdmin) {
        if (refusal.requirementScope === 'instance')
            links.push({ key: 'instance-switch', label: 'Key ceremony settings for the instance', to: INSTANCE_CEREMONY_SETTINGS_PATH });
        else if (refusal.requirementScope === 'space' && refusal.spaceId)
            links.push({
                key: 'space-switch',
                label: `Key ceremony settings for space ${refusal.spaceName ?? refusal.spaceId}`,
                to: spaceCeremonySettingsPath(refusal.spaceId),
            });
    }
    if (viewer.canManageUsers)
        links.push({ key: 'add-administrator', label: 'Add an administrator', to: USERS_PATH });
    return links;
}

/** The sentence that goes with the links: what each does, or whom to ask when there are none. */
export function ceremonyRefusalAdvice(refusal: CeremonyRefusal, links: readonly RefusalLink[]): string {
    const hasSwitch = links.some((l) => l.key !== 'add-administrator');
    const canAdd = links.some((l) => l.key === 'add-administrator');
    const scope = refusal.requirementScope === 'instance'
        ? 'the instance'
        : refusal.requirementScope === 'space' ? `space ${refusal.spaceName ?? refusal.spaceId}` : null;
    const lower = refusal.eligibleApprovers > 0 ? ' or lower its approvals' : '';

    if (hasSwitch && canAdd)
        return `Turn the key ceremony requirement off${lower} for ${scope}, or add another administrator who can approve, then try again.`;
    if (hasSwitch)
        return `Turn the key ceremony requirement off${lower} for ${scope}, then try again.`;
    if (canAdd)
        return scope
            ? `Add another administrator who can approve, or ask a system super-administrator to turn the key ceremony requirement off for ${scope}.`
            : 'Add another administrator who can approve, or ask a system super-administrator to make this change directly.';
    return scope
        ? `Ask a system super-administrator to add another administrator, or to turn the key ceremony requirement off for ${scope}.`
        : 'Ask a system super-administrator to add another administrator, or to make this change directly.';
}

/** The fields of a ceremony's detail that say whether it can still be approved. */
export interface CeremonyReach {
    status?: string | null;
    quorumReachable?: boolean | null;
    approvalsStillNeeded?: number | null;
    eligibleApprovers?: number | null;
}

/**
 * For a pending ceremony that can no longer reach its quorum (one opened before the server
 * refused them), what to tell whoever opens it; null when it can still be approved or the
 * server did not say.
 */
export function stuckCeremonyNotice(detail: CeremonyReach | null | undefined): string | null {
    if (!detail || detail.status !== 'Pending' || detail.quorumReachable !== false) return null;
    const eligible = count(detail.eligibleApprovers);
    const needed = Math.max(1, count(detail.approvalsStillNeeded));
    if (eligible === 0)
        return 'No one else can approve this ceremony, so it will stay pending until it expires.';
    return `This ceremony still needs ${needed} approval${needed === 1 ? '' : 's'} and only ${eligible} other `
        + `administrator${eligible === 1 ? '' : 's'} can approve it, so it will stay pending until it expires.`;
}

/** A key-ceremony requirement as a form is about to save it. */
export interface RequirementDraft {
    /** Whether the requirement is on in the form. */
    required: boolean;
    /** Whether it is on as saved. */
    wasRequired: boolean;
    /** The approvals the form asks for. */
    approvals: number;
    /** Accounts other than the viewer that could approve in this scope; null when not known. */
    eligibleApprovers: number | null;
    /** "the instance" or "this space". */
    scope: string;
}

/**
 * The warning to show before a requirement is saved that nobody, or too few, could satisfy.
 * It warns and does not block: null when the requirement is off, when enough people can
 * approve, or when the count is not known.
 */
export function requirementWarning(draft: RequirementDraft): string | null {
    if (!draft.required || draft.eligibleApprovers === null) return null;
    const approvals = Math.max(1, Math.floor(draft.approvals) || 1);
    const eligible = Math.max(0, Math.floor(draft.eligibleApprovers));
    if (eligible >= approvals) return null;

    const consequence = `you will not be able to create, revoke or delete CAs of ${draft.scope} until ${
        eligible === 0 ? 'a second administrator exists' : 'more administrators can approve'}.`;
    if (eligible === 0)
        return draft.wasRequired
            ? `Key ceremonies are on for ${draft.scope}, but no other administrator can approve one: ${consequence}`
            : `No other administrator can approve a key ceremony for ${draft.scope}. If you turn this on, ${consequence}`;
    return `A key ceremony for ${draft.scope} would need ${approvals} approvals and only ${eligible} other `
        + `administrator${eligible === 1 ? '' : 's'} can approve. ${draft.wasRequired ? 'As it stands' : 'If you save this'}, ${consequence}`;
}
