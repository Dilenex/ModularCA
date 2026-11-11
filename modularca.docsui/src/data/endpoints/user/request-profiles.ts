import type { ApiEndpoint } from '../types';

export const userRequestProfiles: ApiEndpoint[] = [
    {
        method: 'GET',
        path: '/api/v1/user/request-profiles',
        summary: 'List the request profiles the caller can submit a certificate request under: the unbound ones and those of the CAs they hold cert.request on.',
        auth: 'Authorize (CaUser)',
        category: 'User Request Profiles',
        headers: [
            { name: 'Authorization', type: 'Bearer token', required: true, description: 'JWT access token from /api/v1/auth/login' },
        ],
        responseDescription: 'Array of request profiles with their constraints, the CA each is bound to (certificateAuthorityId, null when unbound) and, in certProfiles, the certificate profiles each one names that the caller can request under.',
        notes: 'Each certProfiles entry has id, name and the certificate profile\'s own scope: spaceId and certificateAuthorityId, both null for an instance-wide profile. An unbound request profile can name certificate profiles of several CAs. For one CA (caId and caSpaceId from GET /api/v1/user/signing-profiles), a submission takes the request profiles bound to that CA or to none, and of their certificate profiles the instance-wide ones and those whose spaceId is the CA\'s space and whose certificateAuthorityId is null or that CA.',
    },
];
