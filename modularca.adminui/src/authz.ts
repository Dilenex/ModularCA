import { Capabilities, type Capability } from '@shared/generated';

/**
 * Capability checks over the `capabilities` payload of `GET /api/v1/me`.
 *
 * Pure functions, no React: the auth context wraps them for components, the sign-in pages use
 * them to pick a landing portal, and the test project covers them directly. The server resolves
 * the four grant sources into this shape (`EffectiveCapabilities` in ModularCA.Auth); nothing
 * here knows about roles, templates or group names.
 */

/** The capabilities that apply on one CA, as `/api/v1/me` reports them. */
export interface CaCapabilities {
    id: string;
    label: string;
    name: string;
    isSshCa: boolean;
    /** The space the CA belongs to, or null for an instance CA; the console's space scope groups CAs by it. */
    spaceId: string | null;
    /** Empty for an instance CA. */
    spaceName: string;
    /** What a space scope in a console URL names; empty for an instance CA. */
    spaceSlug: string;
    capabilities: Capability[];
}

/** A space the user may scope to: one that holds at least one CA they can administer. */
export interface SpaceOption {
    id: string;
    name: string;
    slug: string;
}

/** The capabilities held across a whole space, as `/api/v1/me` reports them. */
export interface SpaceCapabilities {
    id: string;
    name: string;
    slug: string;
    /** Held space-wide (plus the system-scoped ones); a grant on one CA never lands here. */
    capabilities: Capability[];
}

/** System-scoped capabilities plus every CA and space the user holds anything on. */
export interface EffectiveCapabilities {
    /** Held at system scope; these apply to every CA. */
    system: Capability[];
    /** Every CA with at least one capability, ordered by label. */
    cas: CaCapabilities[];
    /**
     * Every space with at least one capability held space-wide, ordered by name. A space
     * administrator of a space with no CA yet appears here and nowhere else.
     */
    spaces?: SpaceCapabilities[];
}

/** No capabilities anywhere: the shape to use while `/api/v1/me` has not answered. */
export const NO_CAPABILITIES: EffectiveCapabilities = { system: [], cas: [], spaces: [] };

/**
 * Whether `capability` is held on `caId`, or at system scope when no CA is given.
 *
 * The per-CA sets already include the system-scoped capabilities, so a system-level holder
 * passes on every CA without a second lookup here.
 */
export function can(caps: EffectiveCapabilities | null | undefined, capability: Capability, caId?: string | null): boolean {
    if (!caps) return false;
    if (!caId) return caps.system.includes(capability);
    const ca = caps.cas.find(c => c.id === caId);
    return !!ca && ca.capabilities.includes(capability);
}

/**
 * Whether `capability` is held at system scope or on any CA. This is what the server's CA-scoped
 * list endpoints ask of a route that names no CA, so a space-wide grant over a space with no CA
 * yet does not count here; see `canSpaceWide` for the pages that work without one.
 */
export function canAnywhere(caps: EffectiveCapabilities | null | undefined, capability: Capability): boolean {
    if (!caps) return false;
    return caps.system.includes(capability) || caps.cas.some(c => c.capabilities.includes(capability));
}

/** Whether `capability` is held space-wide on any space, whether or not the space has a CA yet. */
export function canSpaceWide(caps: EffectiveCapabilities | null | undefined, capability: Capability): boolean {
    if (!caps) return false;
    return (caps.spaces ?? []).some(s => s.capabilities.includes(capability));
}

/**
 * Whether `capability` is held at system scope or on at least one SSH CA. SSH CAs belong to the
 * instance, so this never depends on the console's scope.
 */
export function canOnAnySshCa(caps: EffectiveCapabilities | null | undefined, capability: Capability): boolean {
    if (!caps) return false;
    return caps.system.includes(capability) || caps.cas.some(c => c.isSshCa && c.capabilities.includes(capability));
}

/**
 * The SSH tabs of the pages that carry SSH beside X.509: the SSH CA keys on Authorities, the SSH
 * certificates on All Certificates, signing a key on Request Certificate, and in self-service
 * the request form and the list of the reader's own certificates.
 */
export type SshTabPlace = 'keys' | 'certificates' | 'sign' | 'selfRequest' | 'selfCertificates';

/**
 * Whether the caller can use an SSH tab, by the right its routes ask: listing the keys and
 * signing need cert.revoke on an SSH CA, the certificate list cert.view, and the self-service
 * tabs cert.request. A holder of system-scoped ca.manage also has the keys tab, where a new SSH
 * CA key is generated.
 */
export function canUseSshTab(caps: EffectiveCapabilities | null | undefined, place: SshTabPlace): boolean {
    switch (place) {
        case 'keys': return canOnAnySshCa(caps, Capabilities.CertRevoke) || can(caps, Capabilities.CaManage);
        case 'certificates': return canOnAnySshCa(caps, Capabilities.CertView);
        case 'sign': return canOnAnySshCa(caps, Capabilities.CertRevoke);
        case 'selfRequest':
        case 'selfCertificates': return canOnAnySshCa(caps, Capabilities.CertRequest);
    }
}

/** The capabilities a Requester holds: the self-service pair. */
const SELF_SERVICE_ONLY: ReadonlySet<Capability> = new Set([Capabilities.CertRequest, Capabilities.CertView]);

/**
 * Whether the user has anything to do in the management console: any capability beyond the
 * self-service pair, at any scope. A user without it landing on `/admin` is sent to `/user`
 * instead of a dashboard of failing admin calls.
 */
export function canUseAdminConsole(caps: EffectiveCapabilities | null | undefined): boolean {
    if (!caps) return false;
    const beyond = (c: Capability) => !SELF_SERVICE_ONLY.has(c);
    return caps.system.some(beyond) || caps.cas.some(ca => ca.capabilities.some(beyond))
        || (caps.spaces ?? []).some(s => s.capabilities.some(beyond));
}

/** The CAs the user may pick as a console scope: those with a console capability on them. */
export function consoleCas(caps: EffectiveCapabilities | null | undefined): CaCapabilities[] {
    if (!caps) return [];
    return caps.cas.filter(ca => ca.capabilities.some(c => !SELF_SERVICE_ONLY.has(c)));
}

/** The administrable CAs with no space: the instance's own (the system signing CA, SSH CAs). */
export function instanceCas(caps: EffectiveCapabilities | null | undefined): CaCapabilities[] {
    return consoleCas(caps).filter(ca => ca.spaceId == null);
}

/**
 * The spaces the user may scope to: those holding an administrable CA, in first-seen order,
 * then those administered space-wide that have no CA yet. Instance CAs belong to no space.
 */
export function spacesOf(caps: EffectiveCapabilities | null | undefined): SpaceOption[] {
    const seen = new Map<string, SpaceOption>();
    for (const ca of consoleCas(caps)) {
        if (ca.spaceId != null && !seen.has(ca.spaceId)) seen.set(ca.spaceId, { id: ca.spaceId, name: ca.spaceName || ca.spaceSlug, slug: ca.spaceSlug });
    }
    for (const s of caps?.spaces ?? []) {
        if (!seen.has(s.id) && s.capabilities.some(c => !SELF_SERVICE_ONLY.has(c))) seen.set(s.id, { id: s.id, name: s.name || s.slug, slug: s.slug });
    }
    return [...seen.values()];
}

/** Whether `capability` is held space-wide or on any CA of the space. */
export function canInSpace(caps: EffectiveCapabilities | null | undefined, capability: Capability, spaceId: string): boolean {
    if (!caps) return false;
    if (caps.spaces?.some(s => s.id === spaceId && s.capabilities.includes(capability))) return true;
    return caps.cas.some(c => c.spaceId === spaceId && c.capabilities.includes(capability));
}

/**
 * Whether `capability` is held at system scope or on a CA of the space: what a CA-scoped list
 * endpoint needs, which a space-wide grant over a space with no CA does not meet.
 */
export function canOnCaInSpace(caps: EffectiveCapabilities | null | undefined, capability: Capability, spaceId: string): boolean {
    if (!caps) return false;
    return caps.system.includes(capability) || caps.cas.some(c => c.spaceId === spaceId && c.capabilities.includes(capability));
}

/**
 * Whether `capability` is held for the whole space: at system scope or space-wide. This is
 * what creating a CA in the space takes; holding it on one CA of the space is not enough,
 * which is why this is not `canInSpace`.
 */
export function canAtSpace(caps: EffectiveCapabilities | null | undefined, capability: Capability, spaceId: string): boolean {
    if (!caps) return false;
    if (caps.system.includes(capability)) return true;
    const s = caps.spaces?.find(x => x.id === spaceId);
    return !!s && s.capabilities.includes(capability);
}
