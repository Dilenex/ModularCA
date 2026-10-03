import type { ApiEndpoint } from '../../types';

export const adminPolicy: ApiEndpoint[] = [
    {
        method: 'POST',
        path: '/api/v1/admin/policy/check',
        summary: 'Check a certificate request against the configured policy engine.',
        auth: 'Authorize (CaOperator)',
        category: 'Admin Policy',
        headers: [
            { name: 'Authorization', type: 'Bearer token', required: true, description: 'JWT access token from /api/v1/auth/login' },
        ],
        responseDescription: 'Policy check result with any violations.',
    },
    {
        method: 'POST',
        path: '/api/v1/admin/policy/sync',
        summary: 'Sync policies from an external source.',
        auth: 'Authorize (SystemAdmin)',
        category: 'Admin Policy',
        headers: [
            { name: 'Authorization', type: 'Bearer token', required: true, description: 'JWT access token from /api/v1/auth/login' },
        ],
        responseDescription: 'Sync result.',
    },
];
