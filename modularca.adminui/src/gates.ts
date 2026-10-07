import { Capabilities, type Capability } from '@shared/generated';

/**
 * What a page or a sidebar entry requires of the caller.
 *
 * `requires` names a capability; `scoped` says whether it is checked against the selected CA
 * scope (a CA-scoped page such as certificates or profiles) or at system scope (a page that
 * administers the whole installation). One table, used by both the routes in App.tsx and the
 * sidebar in Layout.tsx, so a hidden link and a reachable URL can never disagree.
 *
 * The capability chosen for each gate is the one the page's own API enforces, so the console
 * shows what the server will answer. Role and template names appear nowhere on the client.
 */
export interface Gate {
    requires: Capability;
    scoped?: boolean;
    /**
     * For a scoped gate: whether a space-wide grant over a space with no CA yet also admits. Most
     * CA-scoped pages list through endpoints that need the capability on at least one CA, so
     * only a page that works before the space has a CA sets this.
     */
    spaceWide?: boolean;
}

/** Installation-wide administration: settings, backup, spaces, roles, schedules, TLS. */
export const SYSTEM_ADMIN: Gate = { requires: Capabilities.SystemManage };

/** Running CAs across the installation (SystemOperator on the server): notification delivery. */
export const SYSTEM_OPERATOR: Gate = { requires: Capabilities.CaManage };

/** Managing a CA within the scope: profiles, distribution, protocols. */
export const CA_MANAGE: Gate = { requires: Capabilities.CaManage, scoped: true };

/**
 * Creating a space's CAs and deciding its ceremonies: the authorities list and ceremonies, which
 * a space administrator needs before the space has its first CA.
 */
export const CA_MANAGE_SPACE: Gate = { requires: Capabilities.CaManage, scoped: true, spaceWide: true };

/** Reading the audit trail within the scope. */
export const CA_AUDIT: Gate = { requires: Capabilities.AuditView, scoped: true };

/** Seeing certificates and requests within the scope. */
export const CERT_VIEW: Gate = { requires: Capabilities.CertView, scoped: true };

/** Submitting a certificate request within the scope. */
export const CERT_REQUEST: Gate = { requires: Capabilities.CertRequest, scoped: true };

/** Managing groups within the scope. */
export const GROUP_MANAGE: Gate = { requires: Capabilities.GroupManage, scoped: true };

/** Managing user accounts, which are installation-wide. */
export const USER_MANAGE: Gate = { requires: Capabilities.UserManage };

/** Managing enrollment credentials within the scope. */
export const TOKEN_MANAGE: Gate = { requires: Capabilities.TokenManage, scoped: true };
