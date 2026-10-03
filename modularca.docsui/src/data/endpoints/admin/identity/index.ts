import type { ApiEndpoint } from '../../types';
import { adminGroups } from './groups';
import { adminUsers } from './users';
import { adminSpaces } from './spaces';
import { adminCertPermissions } from './cert-permissions';
import { adminEnrollmentTokens } from './enrollment-tokens';

export const adminIdentity: ApiEndpoint[] = [
    ...adminGroups,
    ...adminUsers,
    ...adminSpaces,
    ...adminCertPermissions,
    ...adminEnrollmentTokens,
];
