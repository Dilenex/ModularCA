/**
 * The CA picker of the certificate request form: which CAs it offers, which one it starts on,
 * and what the three profile pickers hold once a CA is chosen.
 *
 * The issuing CA is the first decision of a request, and it used to be made by accident, inside
 * the signing profile: a requester of two CAs could pair one CA's request profile with the
 * other's signing profile and learn of it on submit. Everything here reads the lists the form
 * already loads; the rules are the server's submit check restated over the fields those lists
 * carry (`RequestProfileEnforcement.BindingAdmits` and `CertProfileScope.Admits`), and
 * `SelfServiceProfileListTests` holds the two sides equal for every CA of every kind of caller.
 */

/** A CA a request can be issued from. */
export interface RequestCa {
    id: string;
    name: string;
    /** The CA's space; null for an instance CA. */
    spaceId: string | null;
}

/** A signing profile row of either list, as far as the picker reads it. */
export interface SigningProfileRow {
    id: string;
    name?: string | null;
    isDefault?: boolean;
    /** The live CA the profile issues from; null or absent when it has no issuer. */
    caId?: string | null;
    caName?: string | null;
    caSpaceId?: string | null;
}

/** A request profile row, as far as the picker reads it. */
export interface RequestProfileRow {
    id: string;
    /** The CA the profile is bound to; null or absent when it is unbound. */
    certificateAuthorityId?: string | null;
}

/** A certificate profile with its own scope: no space and no CA is instance-wide. */
export interface ScopedCertProfile {
    id: string;
    name: string;
    spaceId?: string | null;
    certificateAuthorityId?: string | null;
}

/** The console's scope, as far as the picker reads it (`Scope` in `scope.ts` fits). */
export type PickerScope =
    | { kind: 'all' }
    | { kind: 'mine' }
    | { kind: 'space'; spaceId: string }
    | { kind: 'ca'; caId: string };

/** What the three profile pickers hold. */
export interface ProfileSelections {
    caId: string;
    requestProfileId: string;
    signingProfileId: string;
    certProfileId: string;
}

/**
 * The CAs the caller can request from: the CA of each listed signing profile, once each, by
 * name. A signing profile with no issuer names no CA and adds none, so it never reaches the
 * form. `canUse` leaves out a CA whose signing profiles the caller can see and not submit
 * against; the self-service list holds only what can be submitted against and needs none.
 */
export function requestCas(signingProfiles: SigningProfileRow[], canUse?: (caId: string) => boolean): RequestCa[] {
    const seen = new Map<string, RequestCa>();
    for (const p of signingProfiles) {
        if (!p.caId || seen.has(p.caId)) continue;
        if (canUse && !canUse(p.caId)) continue;
        seen.set(p.caId, { id: p.caId, name: p.caName || p.caId, spaceId: p.caSpaceId ?? null });
    }
    return [...seen.values()].sort((a, b) => a.name.localeCompare(b.name) || a.id.localeCompare(b.id));
}

/**
 * The CAs the picker offers under the console's scope: that CA under a CA scope, the space's
 * CAs under a space scope, every one under "all CAs" and in self-service.
 */
export function casInScope(cas: RequestCa[], scope: PickerScope): RequestCa[] {
    switch (scope.kind) {
        case 'ca': return cas.filter(c => c.id === scope.caId);
        case 'space': return cas.filter(c => c.spaceId === scope.spaceId);
        default: return cas;
    }
}

/**
 * The CA the picker holds after the offered CAs changed (the lists arrived, or the scope
 * switcher moved): the only one when one is offered, which covers a caller with one CA, a
 * console scoped to a CA and a badge that leaves one; otherwise the current choice while it is
 * still offered; otherwise none, so the picker opens empty.
 */
export function settleCa(current: string, offered: RequestCa[]): string {
    if (offered.length === 1) return offered[0].id;
    return offered.some(c => c.id === current) ? current : '';
}

/** The signing profiles of one CA; none while no CA is chosen. */
export function signingProfilesOf<T extends SigningProfileRow>(signingProfiles: T[], caId: string): T[] {
    return caId ? signingProfiles.filter(p => p.caId === caId) : [];
}

/** The CA's signing profile a request starts on: the one flagged default, failing that its first; '' when it has none. */
export function defaultSigningProfileId(signingProfiles: SigningProfileRow[], caId: string): string {
    const own = signingProfilesOf(signingProfiles, caId);
    return (own.find(p => p.isDefault) ?? own[0])?.id ?? '';
}

/** The request profiles that go with one CA: those bound to it and the unbound ones; none while no CA is chosen. */
export function requestProfilesOf<T extends RequestProfileRow>(requestProfiles: T[], caId: string): T[] {
    return caId ? requestProfiles.filter(p => !p.certificateAuthorityId || p.certificateAuthorityId === caId) : [];
}

/**
 * Whether the CA may issue under the certificate profile: an instance-wide profile fits every
 * CA; any other only a CA of its own space (the instance, for no space) and, when it is bound
 * to a CA, only that CA.
 */
export function caAdmitsCertProfile(profile: ScopedCertProfile, ca: RequestCa): boolean {
    const profileSpace = profile.spaceId ?? null;
    const profileCa = profile.certificateAuthorityId ?? null;
    if (profileSpace === null && profileCa === null) return true;
    return profileSpace === ca.spaceId && (profileCa === null || profileCa === ca.id);
}

/** The certificate profiles the CA admits, in their order; none while no CA is chosen. */
export function certProfilesOf<T extends ScopedCertProfile>(certProfiles: T[], ca: RequestCa | null | undefined): T[] {
    return ca ? certProfiles.filter(p => caAdmitsCertProfile(p, ca)) : [];
}

/**
 * What the profile pickers hold right after a CA is chosen, whatever they held before: no
 * request profile, the CA's default signing profile, no certificate profile. Choosing no CA
 * empties all three.
 */
export function selectionsForCa(caId: string, signingProfiles: SigningProfileRow[]): ProfileSelections {
    return { caId, requestProfileId: '', signingProfileId: defaultSigningProfileId(signingProfiles, caId), certProfileId: '' };
}
