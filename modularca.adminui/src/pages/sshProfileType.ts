/**
 * The certificate type of an SSH request profile or SSH certificate profile, as the console
 * reads and sends it: `user`, `host`, or none (null on a stored profile, `either` in a request),
 * which serves both. A profile whose type is set is refused by the sign routes for a certificate
 * of the other type, so the forms offer only the profiles that fit. No React here, so it is
 * covered by tests/modularca.web.tests.
 */

export type SshCertificateType = 'user' | 'host';

/** What a profile form holds and what a create or update body sends. */
export type SshProfileTypeChoice = SshCertificateType | 'either';

/** The choices of the profile forms' "Certificate type" field, in display order. */
export const SSH_PROFILE_TYPE_OPTIONS: ReadonlyArray<{ value: SshProfileTypeChoice; label: string }> = [
    { value: 'user', label: 'User' },
    { value: 'host', label: 'Host' },
    { value: 'either', label: 'Either' },
];

export const SSH_PROFILE_TYPE_HINT =
    'User: offered only for user certificates. Host: offered only for host certificates. Either: offered for both, as every profile was before it had a type.';

/** The form's choice for a stored profile: its type, or `either` when it has none. */
export function profileTypeChoice(stored: unknown): SshProfileTypeChoice {
    return stored === 'user' || stored === 'host' ? stored : 'either';
}

/** "User", "Host" or "Either", for a table cell and a drawer. */
export function profileTypeLabel(stored: unknown): string {
    const choice = profileTypeChoice(stored);
    return SSH_PROFILE_TYPE_OPTIONS.find((o) => o.value === choice)!.label;
}

/** Whether a profile may be used for a certificate of `type`: its own type is that one, or it has none. */
export function servesCertificateType(profile: { certificateType?: string | null } | null | undefined, type: SshCertificateType): boolean {
    const own = profile?.certificateType;
    return !own || own === type;
}

/** The profiles a form offers for a certificate of `type`. */
export function profilesForCertificateType<T extends { certificateType?: string | null }>(profiles: readonly T[], type: SshCertificateType): T[] {
    return profiles.filter((p) => servesCertificateType(p, type));
}

/** Who the admin sign form signs for: asked first, before any profile is offered. */
export type SshSignFor = 'user' | 'service' | 'host';

/** The certificate type each answer comes to: a service identity carries a user certificate. */
export const certificateTypeFor = (signFor: SshSignFor): SshCertificateType => (signFor === 'host' ? 'host' : 'user');

/** The answer the form starts on for an SSH CA key: a host for a key that signs host certificates only. */
export function defaultSignFor(caKey: { isUserCa?: boolean; isHostCa?: boolean }): SshSignFor {
    return caKey.isUserCa === false && caKey.isHostCa ? 'host' : 'user';
}

/** Whether an SSH CA key signs the certificate an answer comes to; a key that does not say signs both. */
export function keySignsFor(caKey: { isUserCa?: boolean; isHostCa?: boolean }, signFor: SshSignFor): boolean {
    return certificateTypeFor(signFor) === 'host' ? caKey.isHostCa !== false : caKey.isUserCa !== false;
}
