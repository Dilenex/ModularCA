import { useEffect } from 'react';
import { useLocation, matchPath } from 'react-router-dom';
import { PORTAL } from '../portal';

/**
 * Sets the browser tab title per route (replacing the hardcoded "ModularCA Dashboard"). Mounted once
 * inside the Router; on every navigation it resolves the current path to a friendly name and sets
 * `document.title` to "<Page> · ModularCA". Titles mirror the sidebar nav labels where one exists.
 *
 * The list is ordered MOST-SPECIFIC → LEAST-SPECIFIC and the first match wins, so a static sub-route
 * (e.g. /certificates/requests) must precede its param sibling (/certificates/:serial), otherwise the
 * param route would swallow it. matchPath uses end:true by default, so a list route like /certificates
 * never matches a deeper path.
 */
const SUFFIX = 'ModularCA';

// Sign-in pages at the site root, shared by both portals.
const AUTH_ROUTE_TITLES: Array<[string, string]> = [
    ['/login', 'Sign In'],
    ['/mfa-setup', 'MFA Setup'],
    ['/mfa-verify', 'Verify MFA'],
    ['/mfa-callback', 'Signing In'],
    ['/banner', 'Login Banner'],
];

// Self-service portal (/user). Flat: every page is one segment deep.
const USER_ROUTE_TITLES: Array<[string, string]> = [
    ['/dashboard', 'Dashboard'],
    ['/request', 'Request Certificate'],
    ['/requests', 'My Requests'],
    ['/certificates', 'My Certificates'],
    ['/ssh', 'SSH Certificates'],
    ['/authorities', 'CA Information'],
    ['/account', 'My Account'],
    ['/security', 'My Account'], // legacy path → redirects to /account

    // Auth (outside the main shell)
    ['/login', 'Sign In'],
    ['/mfa-setup', 'MFA Setup'],
    ['/mfa-verify', 'Verify MFA'],
    ['/mfa-callback', 'Signing In'],
    ['/banner', 'Login Banner'],

    ['/', 'Dashboard'],
];

// Management console (/admin).
const ADMIN_ROUTE_TITLES: Array<[string, string]> = [
    ['/dashboard', 'Dashboard'],
    ['/health', 'System Health'],
    ['/account', 'My Account'],
    ['/security', 'My Account'], // legacy path → redirects to /account

    // Certificates
    ['/certificates/requests/:id', 'Request Detail'],
    ['/certificates/requests', 'Pending Requests'],
    ['/certificates/request', 'Request Certificate'],
    ['/certificates/search', 'Certificate Search'],
    ['/certificates/expiry', 'Expiry Calendar'],
    ['/certificates/:serial', 'Certificate Detail'],
    ['/certificates', 'All Certificates'],

    // Intelligence
    ['/intel/inventory', 'Cert Inventory'],
    ['/intel/compliance', 'Compliance'],
    ['/intel/vulnerabilities', 'Vulnerabilities'],

    // CA management
    ['/authorities/manage/:id', 'CA Detail'],
    ['/authorities/manage', 'Authorities'],
    ['/authorities/protocols', 'Protocol Config'],
    ['/authorities/:caId/ldap', 'LDAP Publishers'],

    // Profiles
    ['/profiles/cert/:id', 'Certificate Profile'],
    ['/profiles/request/:id', 'Request Profile'],
    ['/profiles/signing/:id', 'Signing Profile'],
    ['/profiles/ssh-cert/:id', 'SSH Certificate Profile'],
    ['/profiles/ssh-request/:id', 'SSH Request Profile'],
    ['/profiles/ssh-signing/:id', 'SSH Signing Profile'],
    ['/profiles', 'Profiles'],

    // SSH
    ['/ssh/ca-keys/:id', 'SSH CA Key'],
    ['/ssh/certs/:id', 'SSH Certificate'],
    ['/ssh', 'SSH CA'],

    // Distribution
    ['/distribution/crl/:id', 'CRL Schedule'],
    ['/distribution/ldap/:id', 'LDAP Publisher'],
    ['/distribution', 'CA Distribution'],

    ['/trust-anchors', 'Trust Anchors'],
    ['/webtls', 'Web TLS Certificate'],
    ['/templates', 'Certificate Templates'],
    ['/crl', 'CRL'],
    ['/banner', 'Login Banner'],

    // Access & identity
    ['/users/:id', 'User Detail'],
    ['/users', 'Users'],
    ['/groups/:id', 'Group Detail'],
    ['/groups', 'Groups'],
    ['/roles/:id', 'Role Detail'],
    ['/roles', 'Roles'],
    ['/enrollment', 'Enrollment'],
    ['/acme', 'ACME'],

    // Administration
    ['/ceremonies', 'Ceremonies'],
    ['/tenants/:id', 'Tenant Detail'],
    ['/tenants', 'Tenants & Quotas'],
    ['/quotas', 'Quotas'],
    ['/settings', 'Settings'],
    ['/audit/:type/:id', 'Audit Entry'],
    ['/audit', 'Audit Logs'],
    ['/notifications', 'Notifications'],
    ['/whitelists/:id', 'Whitelist Detail'],
    ['/whitelists', 'Whitelists'],
    ['/backup', 'Backup & Restore'],
    ['/schedules/jobs/:name', 'Scheduler Job'],
    ['/schedules', 'Schedules'],

    // Auth (rendered outside the Layout, but still worth a title)
    ['/login', 'Sign In'],
    ['/mfa-setup', 'MFA Setup'],
    ['/mfa-verify', 'Verify MFA'],
    ['/mfa-callback', 'Signing In'],
];

const ROUTE_TITLES = PORTAL === 'admin' ? ADMIN_ROUTE_TITLES : PORTAL === 'user' ? USER_ROUTE_TITLES : AUTH_ROUTE_TITLES;

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
