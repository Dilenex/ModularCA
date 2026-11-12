import { scopeKey, type Scope } from '../scope';

/**
 * Which CA the Windows Autoenrollment page shows, and when it follows the scope switcher.
 *
 * The page names its CA in the URL (`/authorities/windows/:id`), so a link opens the CA it names
 * whatever the scope is. Once open it follows the switcher as Protocol Configuration does: picking
 * a CA there moves the page to that CA; a space or "all CAs" names no single CA and leaves the page
 * where it is.
 */

/** The fields of a listed CA the choice reads. */
export interface MsaeCaOption {
    id: string;
    spaceId?: string | null;
}

/** The page's path for one CA. */
export function msaeSetupPath(caId: string): string {
    return `/authorities/windows/${caId}`;
}

/**
 * The CA the page shows: the route's, else the scoped one, else the first listed in the scoped
 * space, else the first the operator can see. Empty while there is nothing to choose from.
 */
export function msaeSelectedCa(routeCaId: string | undefined, scope: Scope, authorities: readonly MsaeCaOption[]): string {
    if (routeCaId) return routeCaId;
    if (scope.kind === 'ca' && scope.caId) return scope.caId;
    const inSpace = scope.kind === 'space' ? authorities.find((c) => c.spaceId === scope.spaceId) : null;
    return (inSpace ?? authorities[0])?.id ?? '';
}

/**
 * The CA to move the page to after a scope change, or `null` to stay.
 *
 * `followedKey` is the `scopeKey` the page last acted on. Nothing moves while the scope is the
 * same one (so the page's own CA picker, and a link naming a CA outside the scope, are left
 * alone), when the new scope names no single CA, or when the page already shows the scoped CA.
 */
export function msaeScopeFollow(followedKey: string, scope: Scope, routeCaId: string | undefined): string | null {
    if (scopeKey(scope) === followedKey) return null;
    if (scope.kind !== 'ca' || !scope.caId) return null;
    return scope.caId === routeCaId ? null : scope.caId;
}
