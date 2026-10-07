import { rewriteLegacyScope } from './scope';

/**
 * Where a console path renamed in 0.4.0 now lives: `/tenants` and `/tenants/:id` became
 * `/spaces` and `/spaces/:id`, query string kept (a `?tenant=` in it becomes `?space=`). `null`
 * for any other path. Kept for one release so bookmarks still land; remove in 0.5.
 */
export function legacySpacePath(pathname: string, search = ''): string | null {
    const match = /^\/tenants(?:\/([^/]+))?\/?$/.exec(pathname);
    if (!match) return null;
    const query = (rewriteLegacyScope(search) ?? new URLSearchParams(search)).toString();
    return (match[1] ? `/spaces/${match[1]}` : '/spaces') + (query ? `?${query}` : '');
}
