import type { ApiEndpoint } from '../../types';
import { adminConfiguration } from './configuration';
import { adminLdap } from './ldap';
import { adminLdapPublishers } from './ldap-publishers';
import { adminTrustAnchors } from './trust-anchors';
import { adminApiKeys, adminSettings } from './api-keys';

export const adminConfig: ApiEndpoint[] = [
    ...adminConfiguration,
    ...adminLdap,
    ...adminLdapPublishers,
    ...adminTrustAnchors,
    ...adminApiKeys,
    ...adminSettings,
];
