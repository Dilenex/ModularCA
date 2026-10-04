/**
 * What the Create CA panel says about the scope it creates in. Free of React so the web tests
 * cover it.
 *
 * Whether a create opens a key ceremony is the target scope's `RequireKeyCeremony`: the
 * instance's for an instance CA, the space's otherwise (EffectivePolicyResolver on the server).
 * The console does not always know it: the space list is system-admin only and a space
 * administrator has no endpoint that reports their space's policy. Unknown is `null`, and the
 * panel then says what may happen instead of guessing.
 */

/** The space selector's value for an instance CA (no space); sent as scope "instance". */
export const INSTANCE_SCOPE = '__instance__';

/** The ceremony policy the console has been able to read. */
export interface CeremonyPolicySource {
    /** The instance's `RequireKeyCeremony`, or undefined when it could not be read. */
    instance?: boolean | null;
    /** Spaces with their `RequireKeyCeremony` where the space list carried it. */
    spaces: ReadonlyArray<{ id: string; requireKeyCeremony?: boolean | null }>;
}

/** Whether creating a CA in `target` opens a key ceremony; `null` when the console cannot tell. */
export function ceremonyRequiredFor(target: string, source: CeremonyPolicySource): boolean | null {
    if (!target) return null;
    if (target === INSTANCE_SCOPE) return typeof source.instance === 'boolean' ? source.instance : null;
    const space = source.spaces.find((s) => s.id === target);
    return typeof space?.requireKeyCeremony === 'boolean' ? space.requireKeyCeremony : null;
}

/** The create button's label for the CA type, the target's ceremony requirement and whether a submit is in flight. */
export function createCaButtonLabel(caType: 'root' | 'intermediate', ceremony: boolean | null, busy: boolean): string {
    const kind = caType === 'root' ? 'Root' : 'Intermediate';
    if (busy) return ceremony === true ? 'Starting Ceremony...' : ceremony === false ? 'Creating...' : 'Submitting...';
    return ceremony === true ? `Start ${kind} CA Ceremony` : `Create ${kind} CA`;
}

/** Shown under the button when the target's ceremony requirement is unknown. */
export const CEREMONY_UNKNOWN_HINT =
    'If this scope requires a key ceremony, submitting starts one for approval instead of creating the CA at once.';
