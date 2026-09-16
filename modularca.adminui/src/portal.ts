/**
 * Which portal this page load belongs to.
 *
 * One console bundle serves three route prefixes. `/admin` is the management console, `/user`
 * is the self-service portal, and the sign-in pages (`/login`, `/banner`, `/mfa-*`) sit at the
 * site root, shared by both, since a person signs in once and is then sent to whichever portal
 * fits their account. The server hands the same `index.html` to all of them, and the bundle
 * decides what to be from the path it was loaded under. Everything that used to hard-code
 * `/admin` (the router basename, the login redirect, the post-MFA callback path) reads from here.
 *
 * Resolved once at module load. A page load never changes portal; crossing over is a full
 * navigation to the other prefix (see the switch link in the sidebar), which re-resolves this.
 */
import { canUseAdminConsole as canUseConsole, type EffectiveCapabilities } from './authz';

export type Portal = 'admin' | 'user' | 'auth';

const path = window.location.pathname;
export const PORTAL: Portal = path.startsWith('/admin') ? 'admin' : path.startsWith('/user') ? 'user' : 'auth';

/** Route basename for the router: `/admin`, `/user`, or `` for the root-level sign-in pages. */
export const BASENAME = PORTAL === 'auth' ? '' : `/${PORTAL}`;

/** The other portal's basename, for the cross-link in the sidebar. */
export const OTHER_BASENAME = PORTAL === 'admin' ? '/user' : '/admin';

/** Short label shown under the wordmark and in the mobile header. */
export const PORTAL_LABEL = PORTAL === 'admin' ? 'Administration' : 'Self-Service';

/** The sign-in pages. Site-root paths, identical from every portal. */
export const LOGIN_PATH = '/login';
export const MFA_SETUP_PATH = '/mfa-setup';

/** The minimal shape of `/api/v1/me` this module needs to pick a landing page. */
export interface PortalUser {
    capabilities?: EffectiveCapabilities | null;
}

/**
 * Whether a user has anything to do in the management console: any capability beyond the
 * self-service pair, at any scope (see authz.ts).
 */
export function canUseAdminConsole(user: PortalUser | null | undefined): boolean {
    return canUseConsole(user?.capabilities);
}

/** Where a freshly signed-in user lands when nothing asked for a specific page. */
export function homeFor(user: PortalUser | null | undefined): string {
    return canUseAdminConsole(user) ? '/admin/dashboard' : '/user/dashboard';
}

/**
 * Accepts a `returnUrl` only if it is a same-origin path into one of the portals. Anything
 * else (another origin, a protocol-relative `//host`, an API path) is dropped, so the login
 * page cannot be used as an open redirect.
 */
export function safeReturnUrl(candidate: string | null | undefined): string | null {
    if (!candidate) return null;
    if (!/^\/(admin|user|docs)(\/|\?|$)/.test(candidate)) return null;
    if (candidate.startsWith('//')) return null;
    return candidate;
}

const RETURN_KEY = 'modca:returnUrl';

/** Keeps a validated returnUrl across the sign-in pages (login → MFA → callback). */
export function rememberReturnUrl(candidate: string | null | undefined): void {
    const safe = safeReturnUrl(candidate);
    try {
        if (safe) sessionStorage.setItem(RETURN_KEY, safe);
    } catch { /* storage unavailable: the user simply lands on their home page */ }
}

/** Reads and clears the remembered returnUrl. */
export function consumeReturnUrl(): string | null {
    try {
        const v = sessionStorage.getItem(RETURN_KEY);
        sessionStorage.removeItem(RETURN_KEY);
        return safeReturnUrl(v);
    } catch {
        return null;
    }
}

/**
 * Sends the browser to the sign-in page, remembering where it was so sign-in can bring it
 * back. A full navigation: the sign-in pages live outside every portal basename.
 */
export function goToLogin(): void {
    const here = window.location.pathname + window.location.search;
    window.location.replace(`${LOGIN_PATH}?returnUrl=${encodeURIComponent(here)}`);
}
