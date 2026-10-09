import { rewriteLegacyScope } from './scope';
import { CERTIFICATES_PATH, SELF_CERTIFICATES_PATH, withKindTab } from './pages/sshPlaces';

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

const withQuery = (path: string, query: URLSearchParams): string => {
    const text = query.toString();
    return text ? `${path}?${text}` : path;
};

/**
 * Where a path of the administration console's SSH CA page, folded into tabs in 0.4.2, now
 * lives: `/ssh` is the SSH tab of All Certificates, `/ssh/ca-keys/:id` the key's page under
 * Authorities and `/ssh/certs/:id` the certificate's page under Certificates, query string kept.
 * `null` for any other path. Kept for one release so bookmarks still land; remove in 0.5.
 */
export function legacySshPath(pathname: string, search = ''): string | null {
    const key = /^\/ssh\/ca-keys\/([^/]+)\/?$/.exec(pathname);
    if (key) return withQuery(`/authorities/ssh/${key[1]}`, new URLSearchParams(search));
    const certificate = /^\/ssh\/certs\/([^/]+)\/?$/.exec(pathname);
    if (certificate) return withQuery(`${CERTIFICATES_PATH}/ssh/${certificate[1]}`, new URLSearchParams(search));
    if (/^\/ssh\/?$/.test(pathname)) return withQuery(CERTIFICATES_PATH, withKindTab(search, 'SSH'));
    return null;
}

/**
 * Where the self-service SSH Certificates page, folded into tabs in 0.4.2, now lives: `/ssh` is
 * the SSH tab of My Certificates, query string kept. `null` for any other path. Kept for one
 * release so bookmarks still land; remove in 0.5.
 */
export function legacySelfSshPath(pathname: string, search = ''): string | null {
    return /^\/ssh\/?$/.test(pathname) ? withQuery(SELF_CERTIFICATES_PATH, withKindTab(search, 'SSH')) : null;
}
