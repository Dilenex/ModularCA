import { scopeLabel, scopeSpaceId, type Scope } from '../scope';

/**
 * Where SSH lives in the two consoles: a tab beside X.509 on the pages people already use, and
 * a page of its own for one SSH CA key and for one SSH certificate. The tab is carried in the
 * address as the Profiles page carries its own (`?tab=SSH`), so a link can open a page on its
 * SSH tab. No React here, so it is covered by tests/modularca.web.tests.
 */

/** The tabs of a page that carries SSH beside X.509, in display order. X.509 is the default. */
export const KIND_TABS = ['X.509', 'SSH'] as const;
export type KindTab = typeof KIND_TABS[number];

/** The query-string key the tab is carried in, as on the Profiles page. */
export const TAB_PARAM = 'tab';

/** The tabs a reader is shown: each only when they can use it. */
export function kindTabs(canUse: { x509: boolean; ssh: boolean }): KindTab[] {
    return KIND_TABS.filter((tab) => (tab === 'SSH' ? canUse.ssh : canUse.x509));
}

/**
 * The tab to show: the one the address asks for when the reader has it, otherwise the first
 * they have. Null when they have none.
 */
export function activeKindTab(requested: string | null | undefined, tabs: readonly KindTab[]): KindTab | null {
    return tabs.find((tab) => tab === requested) ?? tabs[0] ?? null;
}

/** The query string with the tab set. The default tab is left out of the address. */
export function withKindTab(search: string | URLSearchParams, tab: KindTab): URLSearchParams {
    const params = new URLSearchParams(typeof search === 'string' ? search : search.toString());
    if (tab === KIND_TABS[0]) params.delete(TAB_PARAM);
    else params.set(TAB_PARAM, tab);
    return params;
}

const sshTab = (path: string) => `${path}?${TAB_PARAM}=SSH`;

/* ── the administration console ──────────────────────────────────────────── */

/** Authorities, where the SSH tab lists the SSH CA keys. */
export const AUTHORITIES_PATH = '/authorities/manage';
export const SSH_CA_KEYS_PATH = sshTab(AUTHORITIES_PATH);

/** The route pattern of one SSH CA key's page. */
export const SSH_CA_KEY_ROUTE = '/authorities/ssh/:id';
export const sshCaKeyPath = (id: string): string => `/authorities/ssh/${encodeURIComponent(id)}`;

/** All Certificates, where the SSH tab lists the SSH certificates. */
export const CERTIFICATES_PATH = '/certificates';
export const SSH_CERTIFICATES_PATH = sshTab(CERTIFICATES_PATH);

/** The route pattern of one SSH certificate's page. */
export const SSH_CERTIFICATE_ROUTE = '/certificates/ssh/:id';

/**
 * A link to one SSH certificate's page. `usedName` marks the login name a host log line showed.
 */
export function sshCertificatePath(cert: { id: string; sshCaKeyId?: string | null }, usedName?: string | null): string {
    const query = new URLSearchParams();
    if (cert.sshCaKeyId) query.set('caKey', cert.sshCaKeyId);
    if (usedName) query.set('used', usedName);
    const text = query.toString();
    return `/certificates/ssh/${encodeURIComponent(cert.id)}${text ? `?${text}` : ''}`;
}

/** Request Certificate, where the SSH tab signs a key. */
export const CERTIFICATE_REQUEST_PATH = '/certificates/request';
export const SSH_SIGN_PATH = sshTab(CERTIFICATE_REQUEST_PATH);

/* ── self-service ────────────────────────────────────────────────────────── */

/** Self-service Request Certificate, where the SSH tab holds the request form. */
export const SELF_REQUEST_PATH = '/request';
export const SELF_SSH_REQUEST_PATH = sshTab(SELF_REQUEST_PATH);

/** Self-service My Certificates, where the SSH tab lists the reader's SSH certificates. */
export const SELF_CERTIFICATES_PATH = '/certificates';
export const SELF_SSH_CERTIFICATES_PATH = sshTab(SELF_CERTIFICATES_PATH);

/* ── the console's scope ─────────────────────────────────────────────────── */

/**
 * What an SSH tab says in place of its content while the console's scope is confined to a
 * space: SSH CAs belong to the instance, so a space has none. Null under any other scope.
 */
export function sshScopeSentence(scope: Scope): string | null {
    if (scopeSpaceId(scope) == null) return null;
    return `SSH CAs belong to the instance, not to a space, so the scope ${scopeLabel(scope)} holds none. Change the scope in the sidebar to see them.`;
}
