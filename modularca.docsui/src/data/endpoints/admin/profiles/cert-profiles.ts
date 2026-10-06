import type { ApiEndpoint } from '../../types';

export const adminCertProfiles: ApiEndpoint[] = [
    {
        method: 'GET',
        path: '/api/v1/admin/cert-profiles',
        summary: 'List all certificate profiles.',
        auth: 'Authorize (CaAuditor)',
        category: 'Admin Cert Profiles',
        headers: [
            { name: 'Authorization', type: 'Bearer token', required: true, description: 'JWT access token from /api/v1/auth/login' },
        ],
        responseDescription: 'Array of certificate profiles.',
    },
    {
        method: 'GET',
        path: '/api/v1/admin/cert-profiles/{id}',
        summary: 'Get a certificate profile by ID.',
        auth: 'Authorize (CaAuditor)',
        category: 'Admin Cert Profiles',
        headers: [
            { name: 'Authorization', type: 'Bearer token', required: true, description: 'JWT access token from /api/v1/auth/login' },
        ],
        responseDescription: 'Certificate profile details.',
    },
    {
        method: 'GET',
        path: '/api/v1/admin/cert-profiles/{id}/resolved',
        summary: 'Get the resolved (inherited) certificate profile, merging system and CA-level overrides.',
        auth: 'Authorize (CaAuditor)',
        category: 'Admin Cert Profiles',
        headers: [
            { name: 'Authorization', type: 'Bearer token', required: true, description: 'JWT access token from /api/v1/auth/login' },
        ],
        responseDescription: 'Resolved profile with effective values after inheritance.',
    },
    {
        method: 'POST',
        path: '/api/v1/admin/cert-profiles/{id}/validate-inheritance',
        summary: 'Validate a certificate profile\'s inheritance chain for conflicts.',
        auth: 'Authorize (CaAuditor)',
        category: 'Admin Cert Profiles',
        headers: [
            { name: 'Authorization', type: 'Bearer token', required: true, description: 'JWT access token from /api/v1/auth/login' },
        ],
        responseDescription: 'Validation result with any inheritance violations.',
    },
    {
        method: 'POST',
        path: '/api/v1/admin/cert-profiles',
        summary: 'Create a new certificate profile.',
        auth: 'Authorize (CaOperator)',
        category: 'Admin Cert Profiles',
        headers: [
            { name: 'Authorization', type: 'Bearer token', required: true, description: 'JWT access token from /api/v1/auth/login' },
            { name: 'X-MFA-Token', type: 'string', required: false, description: 'Step-up MFA token from /api/v1/auth/mfa/verify-stepup for create-cert-profile. Required for this operation.' },
        ],
        responseDescription: 'Created certificate profile.',
    },
    {
        method: 'PUT',
        path: '/api/v1/admin/cert-profiles/{id}',
        summary: 'Update a certificate profile.',
        auth: 'Authorize (CaOperator)',
        category: 'Admin Cert Profiles',
        headers: [
            { name: 'Authorization', type: 'Bearer token', required: true, description: 'JWT access token from /api/v1/auth/login' },
        ],
        responseDescription: 'Updated certificate profile.',
    },
    {
        method: 'DELETE',
        path: '/api/v1/admin/cert-profiles/{id}',
        summary: 'Delete a certificate profile.',
        auth: 'Authorize (CaOperator)',
        category: 'Admin Cert Profiles',
        headers: [
            { name: 'Authorization', type: 'Bearer token', required: true, description: 'JWT access token from /api/v1/auth/login' },
        ],
        responseDescription: 'Deletion confirmation.',
    },
];
