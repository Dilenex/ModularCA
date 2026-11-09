/**
 * The CSRF double-submit cookie the backend sets for every SPA.
 *
 * Over HTTPS it is `__Host-CSRF-TOKEN` (the browser only accepts it Secure, host-only and on `/`,
 * so a sibling subdomain cannot plant one); over plain HTTP, where a `__Host-` cookie cannot exist,
 * it is `CSRF-TOKEN`. The prefixed cookie is read first: a leftover unprefixed one from an older
 * release can still sit in the jar until the server deletes it, and the server never accepts it
 * over HTTPS.
 */
const CSRF_COOKIE_NAMES = ['__Host-CSRF-TOKEN', 'CSRF-TOKEN'] as const;

/** The header the backend compares with the cookie. */
export const CSRF_HEADER = 'X-CSRF-Token';

/**
 * Returns the decoded CSRF token from `cookieString` (defaults to `document.cookie`), preferring
 * `__Host-CSRF-TOKEN` over `CSRF-TOKEN`, or null when neither is set.
 */
export function readCsrfCookie(cookieString?: string): string | null {
    const jar = cookieString ?? (typeof document === 'undefined' ? '' : document.cookie);
    for (const name of CSRF_COOKIE_NAMES) {
        const m = jar.match(new RegExp(`(?:^|;\\s*)${name}=([^;]*)`));
        if (m) {
            try {
                return decodeURIComponent(m[1]);
            } catch {
                return m[1];
            }
        }
    }
    return null;
}

/** `{ 'X-CSRF-Token': token }` when a token is set, otherwise an empty object. */
export function csrfHeader(cookieString?: string): Record<string, string> {
    const token = readCsrfCookie(cookieString);
    return token ? { [CSRF_HEADER]: token } : {};
}
