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
    /** The tenant the CA belongs to; the console's tenant scope groups CAs by it. */
    tenantId: string;
    tenantName: string;
    /** What a tenant scope in a console URL names. */
    tenantSlug: string;
    capabilities: Capability[];
}

/** A tenant the user may scope to: one that holds at least one CA they can administer. */
export interface TenantOption {
    id: string;
    name: string;
    slug: string;
}

/** The capabilities held across a whole tenant, as `/api/v1/me` reports them. */
export interface TenantCapabilities {
    id: string;
    name: string;
    slug: string;
    /** Held tenant-wide (plus the system-scoped ones); a grant on one CA never lands here. */
    capabilities: Capability[];
}

/** System-scoped capabilities plus every CA and tenant the user holds anything on. */
export interface EffectiveCapabilities {
    /** Held at system scope; these apply to every CA. */
    system: Capability[];
    /** Every CA with at least one capability, ordered by label. */
    cas: CaCapabilities[];
    /**
     * Every tenant with at least one capability held tenant-wide, ordered by name. A tenant
     * administrator of a tenant with no CA yet appears here and nowhere else.
     */
    tenants?: TenantCapabilities[];
}

/** No capabilities anywhere: the shape to use while `/api/v1/me` has not answered. */
export const NO_CAPABILITIES: EffectiveCapabilities = { system: [], cas: [], tenants: [] };

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

/** Whether `capability` is held at system scope or on any CA at all. */
export function canAnywhere(caps: EffectiveCapabilities | null | undefined, capability: Capability): boolean {
    if (!caps) return false;
    return caps.system.includes(capability) || caps.cas.some(c => c.capabilities.includes(capability));
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
    return caps.system.some(beyond) || caps.cas.some(ca => ca.capabilities.some(beyond));
}

/** The CAs the user may pick as a console scope: those with a console capability on them. */
export function consoleCas(caps: EffectiveCapabilities | null | undefined): CaCapabilities[] {
    if (!caps) return [];
    return caps.cas.filter(ca => ca.capabilities.some(c => !SELF_SERVICE_ONLY.has(c)));
}

/**
 * The tenants the user may scope to: those holding an administrable CA, in first-seen order,
 * then those administered tenant-wide that have no CA yet.
 */
export function tenantsOf(caps: EffectiveCapabilities | null | undefined): TenantOption[] {
    const seen = new Map<string, TenantOption>();
    for (const ca of consoleCas(caps)) {
        if (!seen.has(ca.tenantId)) seen.set(ca.tenantId, { id: ca.tenantId, name: ca.tenantName || ca.tenantSlug, slug: ca.tenantSlug });
    }
    for (const t of caps?.tenants ?? []) {
        if (!seen.has(t.id) && t.capabilities.some(c => !SELF_SERVICE_ONLY.has(c))) seen.set(t.id, { id: t.id, name: t.name || t.slug, slug: t.slug });
    }
    return [...seen.values()];
}

/** Whether `capability` is held on any CA of the tenant. */
export function canInTenant(caps: EffectiveCapabilities | null | undefined, capability: Capability, tenantId: string): boolean {
    if (!caps) return false;
    return caps.cas.some(c => c.tenantId === tenantId && c.capabilities.includes(capability));
}

/**
 * Whether `capability` is held for the whole tenant: at system scope or tenant-wide. This is
 * what creating a CA in the tenant takes; holding it on one CA of the tenant is not enough,
 * which is why this is not `canInTenant`.
 */
export function canAtTenant(caps: EffectiveCapabilities | null | undefined, capability: Capability, tenantId: string): boolean {
    if (!caps) return false;
    if (caps.system.includes(capability)) return true;
    const t = caps.tenants?.find(x => x.id === tenantId);
    return !!t && t.capabilities.includes(capability);
}
