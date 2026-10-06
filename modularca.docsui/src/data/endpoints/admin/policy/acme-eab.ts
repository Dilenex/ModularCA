import type { ApiEndpoint } from '../../types';

export const adminAcmeEab: ApiEndpoint[] = [
    {
        method: 'GET',
        path: '/api/v1/admin/acme/eab-keys',
        summary: 'List all ACME External Account Binding keys.',
        auth: 'Authorize (CaOperator)',
        category: 'Admin ACME EAB',
        headers: [
            { name: 'Authorization', type: 'Bearer token', required: true, description: 'JWT access token from /api/v1/auth/login' },
        ],
        responseDescription: 'Array of EAB keys.',
    },
    {
        method: 'POST',
        path: '/api/v1/admin/acme/eab-keys',
        summary: 'Create a new ACME EAB key.',
        auth: 'Authorize (CaOperator)',
        category: 'Admin ACME EAB',
        headers: [
            { name: 'Authorization', type: 'Bearer token', required: true, description: 'JWT access token from /api/v1/auth/login' },
            { name: 'X-MFA-Token', type: 'string', required: false, description: 'Step-up MFA token from /api/v1/auth/mfa/verify-stepup for create-eab-key. Required for this operation.' },
        ],
        responseDescription: 'Created EAB key with ID and MAC key.',
    },
    {
        method: 'DELETE',
        path: '/api/v1/admin/acme/eab-keys/{id}',
        summary: 'Delete an ACME EAB key.',
        auth: 'Authorize (CaOperator)',
        category: 'Admin ACME EAB',
        headers: [
            { name: 'Authorization', type: 'Bearer token', required: true, description: 'JWT access token from /api/v1/auth/login' },
        ],
        responseDescription: 'Deletion confirmation.',
    },
];
