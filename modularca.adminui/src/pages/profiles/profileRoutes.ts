/**
 * Paths for the six profile types: the Profile Management tab each one lists under, its
 * /profiles/<type>/new create page and its /profiles/<type>/:id detail page. App.tsx, the list
 * tabs and the detail pages all build their links from here.
 */

/** The Profile Management tabs, in display order. */
export const PROFILE_TABS = ['Certificate Profiles', 'Signing Profiles', 'Request Profiles', 'SSH Signing', 'SSH Cert', 'SSH Request'] as const;
export type ProfileTab = typeof PROFILE_TABS[number];

export type ProfileType = 'cert' | 'signing' | 'request' | 'ssh-signing' | 'ssh-cert' | 'ssh-request';

/** The path segment that selects a create page instead of a stored profile. */
export const NEW_PROFILE_SEGMENT = 'new';

const listPath = (tab: ProfileTab) => `/profiles?tab=${encodeURIComponent(tab)}`;

export const PROFILE_TYPES: Record<ProfileType, { tab: ProfileTab; listPath: string; noun: string }> = {
    'cert': { tab: 'Certificate Profiles', listPath: listPath('Certificate Profiles'), noun: 'certificate profile' },
    'signing': { tab: 'Signing Profiles', listPath: listPath('Signing Profiles'), noun: 'signing profile' },
    'request': { tab: 'Request Profiles', listPath: listPath('Request Profiles'), noun: 'request profile' },
    'ssh-signing': { tab: 'SSH Signing', listPath: listPath('SSH Signing'), noun: 'SSH signing profile' },
    'ssh-cert': { tab: 'SSH Cert', listPath: listPath('SSH Cert'), noun: 'SSH cert profile' },
    'ssh-request': { tab: 'SSH Request', listPath: listPath('SSH Request'), noun: 'SSH request profile' },
};

/** The route pattern of a type's create page; declared before the `:id` route. */
export const profileNewRoute = (type: ProfileType) => `/profiles/${type}/${NEW_PROFILE_SEGMENT}`;

/** The route pattern of a type's detail page. */
export const profileDetailRoute = (type: ProfileType) => `/profiles/${type}/:id`;

/** A link to a type's create page. */
export const profileNewPath = profileNewRoute;

/** A link to one stored profile. */
export const profileDetailPath = (type: ProfileType, id: string) => `/profiles/${type}/${encodeURIComponent(id)}`;
