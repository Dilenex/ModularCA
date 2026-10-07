/**
 * Which profiles are instance-wide, and who may change them. An instance-wide profile applies to
 * every space, so the server lets only a caller holding the capability that creates one, at
 * system scope, update or delete it: cert.revoke for certificate and request profiles, ca.manage
 * for signing profiles. A space-scoped caller may still read and link it. The list and detail
 * pages hide Edit and Delete for such a caller rather than offering an action the server refuses.
 */

/** A certificate profile bound to neither a space nor a CA. */
export const isInstanceWideCertProfile = (p: { spaceId?: string | null; certificateAuthorityId?: string | null } | null | undefined): boolean =>
    !!p && !p.spaceId && !p.certificateAuthorityId;

/** A signing profile with no issuing CA. */
export const isUnboundSigningProfile = (p: { issuerId?: string | null } | null | undefined): boolean =>
    !!p && !p.issuerId;

/** A request profile bound to no CA. */
export const isUnboundRequestProfile = (p: { certificateAuthorityId?: string | null } | null | undefined): boolean =>
    !!p && !p.certificateAuthorityId;

/** Whether a profile may be changed or deleted: always unless instance-wide, then only with the capability at system scope. */
export const mayChangeProfile = (instanceWide: boolean, holdsAtSystemScope: boolean): boolean =>
    !instanceWide || holdsAtSystemScope;

/** Said on a detail page whose profile the caller may not change. */
export const INSTANCE_WIDE_READ_ONLY =
    'This profile is instance-wide: it applies to every space. Changing or deleting it needs system scope.';
