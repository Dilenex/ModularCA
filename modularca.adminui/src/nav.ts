import { SYSTEM_ADMIN, CA_MANAGE, CA_AUDIT, CERT_VIEW, CERT_REQUEST, GROUP_MANAGE, USER_MANAGE, TOKEN_MANAGE, type Gate } from './gates';
import { PORTAL } from './portal';

/**
 * The console's navigation, as data: one table for the management console and one for the
 * self-service portal. The sidebar renders it and the global search indexes it, so a page
 * reachable from one is reachable from the other, under the same gate.
 */
export interface NavItem {
    name: string;
    path: string;
    icon: string;
    /**
     * The gate the current user must pass for this entry to render, checked under the
     * selected scope (see gates.ts and ScopeContext.allows). Omit for entries every
     * authenticated user can see.
     */
    gate?: Gate;
    /** Extra words the search matches on, for pages people look for under another name. */
    keywords?: string[];
}

export interface NavSection {
    title: string;
    items: NavItem[];
}

// Management console navigation, shown under /admin.
export const adminNavSections: NavSection[] = [
    {
        title: 'Overview',
        items: [
            { name: 'Dashboard', path: '/dashboard', icon: '⌂', keywords: ['home', 'overview'] },
            { name: 'System Health', path: '/health', icon: '♥', gate: SYSTEM_ADMIN, keywords: ['status', 'disaster recovery', 'features'] },
        ]
    },
    {
        title: 'Certificates',
        items: [
            { name: 'All Certificates', path: '/certificates', icon: '⎇', gate: CERT_VIEW, keywords: ['certs', 'revoke', 'search'] },
            { name: 'Request Certificate', path: '/certificates/request', icon: '+', gate: CERT_REQUEST, keywords: ['issue', 'csr', 'new certificate'] },
            { name: 'Pending Requests', path: '/certificates/requests', icon: '✉', gate: CERT_VIEW, keywords: ['csr', 'approve', 'approval'] },
            { name: 'Cert Inventory', path: '/intel/inventory', icon: '⚐', gate: CERT_VIEW, keywords: ['health summary'] },
            { name: 'Compliance', path: '/intel/compliance', icon: '☑', gate: CA_MANAGE, keywords: ['findings', 'vulnerabilities'] },
            { name: 'Expiry Calendar', path: '/certificates/expiry', icon: '☒', gate: CERT_VIEW, keywords: ['renewal', 'expiring'] },
        ]
    },
    {
        title: 'CA Management',
        items: [
            { name: 'Authorities', path: '/authorities/manage', icon: '⚿', gate: CA_MANAGE, keywords: ['ca', 'certificate authority', 'root', 'intermediate'] },
            { name: 'Profiles', path: '/profiles', icon: '☰', gate: CA_MANAGE, keywords: ['signing profile', 'cert profile', 'request profile'] },
            // Templates are consumed by Windows autoenrollment (MSAE): the policy service offers
            // them to clients and the enrollment service issues from the one a CSR names.
            { name: 'Templates', path: '/templates', icon: '✂', gate: CA_MANAGE, keywords: ['msae', 'autoenrollment', 'windows'] },
            { name: 'CA Distribution', path: '/distribution', icon: '✖', gate: CA_MANAGE, keywords: ['crl', 'ldap', 'service urls', 'aia', 'ocsp'] },
            { name: 'Trust Anchors', path: '/trust-anchors', icon: '⚓', gate: SYSTEM_ADMIN, keywords: ['trust store', 'external ca'] },
            { name: 'SSH CA', path: '/ssh', icon: '⌘', gate: CERT_VIEW, keywords: ['ssh certificates', 'ssh keys'] },
            { name: 'Protocol Config', path: '/authorities/protocols', icon: '⇄', gate: CA_MANAGE, keywords: ['acme', 'est', 'scep', 'cmp', 'msae', 'protocols'] },
        ]
    },
    {
        title: 'Access & Identity',
        items: [
            { name: 'Users', path: '/users', icon: '☺', gate: USER_MANAGE, keywords: ['accounts', 'people'] },
            { name: 'Groups', path: '/groups', icon: '⚇', gate: GROUP_MANAGE, keywords: ['membership'] },
            { name: 'Roles', path: '/roles', icon: '☆', gate: SYSTEM_ADMIN, keywords: ['capabilities', 'permissions'] },
            { name: 'Enrollment', path: '/enrollment', icon: '⚷', gate: TOKEN_MANAGE, keywords: ['tokens', 'credentials', 'cmp credential'] },
            { name: 'ACME', path: '/acme', icon: 'A', gate: CA_MANAGE, keywords: ['eab', 'directory'] },
        ]
    },
    {
        title: 'Administration',
        items: [
            // Ceremonies covers both key ceremonies (CA key ops) and controlled-user approvals
            // (promote/demote/delete of privileged users), so it lives with governance/oversight
            // here rather than CA Management; its quorum config is in Settings, also Administration.
            // Placed at the top of this group as it's used more often than the rest.
            { name: 'Ceremonies', path: '/ceremonies', icon: '☸', gate: CA_MANAGE, keywords: ['quorum', 'approvals', 'key ceremony'] },
            { name: 'Tenants & Quotas', path: '/tenants', icon: '☖', gate: SYSTEM_ADMIN, keywords: ['tenant', 'quota'] },
            { name: 'Settings', path: '/settings', icon: '⚙', gate: SYSTEM_ADMIN, keywords: ['configuration', 'security policy', 'password policy', 'feature flags'] },
            { name: 'Audit Logs', path: '/audit', icon: '≣', gate: CA_AUDIT, keywords: ['audit trail', 'events', 'history'] },
            { name: 'Notifications', path: '/notifications', icon: '♪', gate: CA_MANAGE, keywords: ['email', 'webhooks', 'alerts'] },
            { name: 'Whitelists', path: '/whitelists', icon: '⛨', gate: SYSTEM_ADMIN, keywords: ['allow list', 'ip', 'network'] },
            { name: 'Backup & Restore', path: '/backup', icon: '⬇', gate: SYSTEM_ADMIN, keywords: ['disaster recovery', 'export'] },
            { name: 'Schedules', path: '/schedules', icon: '⧖', gate: SYSTEM_ADMIN, keywords: ['jobs', 'scheduler', 'cron'] },
            { name: 'Web TLS Certificate', path: '/webtls', icon: '⛉', gate: SYSTEM_ADMIN, keywords: ['https', 'server certificate'] },
        ]
    }
];

// Self-service navigation, shown under /user. Every entry is reachable by any authenticated
// user; the pages behind them call the /api/v1/user/* endpoints, which scope to the caller.
export const userNavSections: NavSection[] = [
    {
        title: 'Overview',
        items: [
            { name: 'Dashboard', path: '/dashboard', icon: '⌂', keywords: ['home'] },
        ]
    },
    {
        title: 'Certificates',
        items: [
            { name: 'Request Certificate', path: '/request', icon: '+', keywords: ['csr', 'new certificate'] },
            { name: 'My Certificates', path: '/certificates', icon: '⎇', keywords: ['certs', 'download', 'renew'] },
            { name: 'Request Status', path: '/requests', icon: '✉', keywords: ['pending', 'approval'] },
        ]
    },
    {
        title: 'SSH',
        items: [
            { name: 'SSH Certificates', path: '/ssh', icon: '⌘' },
        ]
    },
    {
        title: 'CA Information',
        items: [
            { name: 'Trusted CAs', path: '/authorities', icon: '⚿', keywords: ['ca certificate', 'chain', 'crl'] },
        ]
    },
];

/** Pages every authenticated user has, outside the sidebar sections. */
export const accountNavItems: NavItem[] = [
    { name: 'My Account', path: '/account', icon: '☺', keywords: ['profile', 'security', 'mfa', 'badges', 'password'] },
];

/** The navigation for the portal this bundle was loaded under. */
export const navSections: NavSection[] = PORTAL === 'admin' ? adminNavSections : userNavSections;
