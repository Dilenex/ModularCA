import type { ApiEndpoint } from '../../types';

export const adminSecurityPolicy: ApiEndpoint[] = [
    {
        method: 'GET',
        path: '/api/v1/admin/security-policy',
        summary: 'Get the current runtime-tunable security policy (session lockout, MFA TTLs, OCSP posture, login banner).',
        auth: 'Authorize (SystemAdmin)',
        category: 'Admin Security Policy',
        headers: [
            { name: 'Authorization', type: 'Bearer token', required: true, description: 'JWT access token from /api/v1/auth/login' },
        ],
        responseDescription: 'Security policy row with 21 knobs across session, MFA, and OCSP domains.',
    },
    {
        method: 'PUT',
        path: '/api/v1/admin/security-policy',
        summary: 'Update the runtime-tunable security policy. Partial update — null fields are left unchanged. TTL fields are clamped to their documented ranges on write.',
        auth: 'Authorize (SystemAdmin)',
        category: 'Admin Security Policy',
        headers: [
            { name: 'Authorization', type: 'Bearer token', required: true, description: 'JWT access token from /api/v1/auth/login' },
            { name: 'X-MFA-Token', type: 'string', required: true, description: 'Step-up MFA token scoped to update-config; scoped to disable-ceremony-requirement instead when a system super-administrator turns the instance\'s key ceremony requirement off' },
        ],
        responseDescription: 'Updated security policy row, or 202 with a ceremonyId when a non-super change to the instance\'s ceremony requirement or approvals opens an InstancePolicyChange ceremony.',
        notes: 'Changes take effect on the next request scope (cache invalidated on PUT, no restart required). The whole endpoint needs a system administrator; system operators can neither read nor change it. A change to userQuorum needs a system super-administrator (403 otherwise).',
    },
];
