import { useEffect } from 'react';
import { useLocation, matchPath } from 'react-router-dom';

/**
 * Sets the browser tab title per route. Mounted once inside the Router; on navigation it resolves the
 * current path to a friendly name and sets document.title to "<Page> · ModularCA Docs". Ordered
 * most-specific → least-specific (first match wins); matchPath uses end:true so list routes don't
 * swallow deeper paths.
 */
const SUFFIX = 'ModularCA Docs';

const ROUTE_TITLES: Array<[string, string]> = [
    ['/overview', 'Overview'],
    ['/setup-guide', 'Setup Guide'],
    ['/api/:category', 'API Reference'],

    ['/ui/admin', 'Admin UI'],
    ['/ui/user', 'User UI'],
    ['/ui/public', 'Public UI'],
    ['/ui/setup', 'Setup UI'],

    ['/architecture/auth-flow', 'Auth Flow'],
    ['/architecture/certificate-issuance', 'Certificate Issuance'],
    ['/architecture/ca-hierarchy', 'CA Hierarchy'],
    ['/architecture/space-model', 'Space Model'],
    ['/architecture/config-lifecycle', 'Config Lifecycle'],
];

function titleForPath(pathname: string): string | null {
    for (const [pattern, title] of ROUTE_TITLES) {
        if (matchPath(pattern, pathname)) return title;
    }
    return null;
}

const TitleManager: React.FC = () => {
    const { pathname } = useLocation();
    useEffect(() => {
        const t = titleForPath(pathname);
        document.title = t ? `${t} · ${SUFFIX}` : SUFFIX;
    }, [pathname]);
    return null;
};

export default TitleManager;
