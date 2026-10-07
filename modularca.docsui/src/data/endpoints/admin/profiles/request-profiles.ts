import type { ApiEndpoint } from '../../types';

export const adminRequestProfiles: ApiEndpoint[] = [
    {
        method: 'GET',
        path: '/api/v1/admin/request-profiles',
        summary: 'List all request profiles ordered by name. Supports optional filtering by CA ID. Non-system-admin callers see only profiles they have capability grants for.',
        auth: 'Authorize (CaOperator)',
        category: 'Admin Request Profiles',
        queryParams: [
            { name: 'caId', type: 'guid', required: false, description: 'Optional certificate authority ID to filter profiles by CA scope. Without this, returns all profiles (system-wide + CA-scoped)' },
        ],
        headers: [
            { name: 'Authorization', type: 'Bearer token', required: true, description: 'JWT access token from /api/v1/auth/login' },
        ],
        responseDescription: 'Array of request profiles with subject DN rules, SAN rules, approval requirements, and validity constraints.',
    },
    {
        method: 'GET',
        path: '/api/v1/admin/request-profiles/{id}',
        summary: 'Get a single request profile by ID, including inheritance fields.',
        auth: 'Authorize (CaOperator)',
        category: 'Admin Request Profiles',
        headers: [
            { name: 'Authorization', type: 'Bearer token', required: true, description: 'JWT access token from /api/v1/auth/login' },
        ],
        responseDescription: 'Request profile details with full configuration.',
    },
    {
        method: 'GET',
        path: '/api/v1/admin/request-profiles/{id}/resolved',
        summary: 'Get the effective (merged) request profile after resolving inheritance from parent profiles. Useful for previewing actual constraints that will apply.',
        auth: 'Authorize (CaAuditor)',
        category: 'Admin Request Profiles',
        headers: [
            { name: 'Authorization', type: 'Bearer token', required: true, description: 'JWT access token from /api/v1/auth/login' },
        ],
        responseDescription: 'Resolved profile with effective values after inheritance merge.',
    },
    {
        method: 'POST',
        path: '/api/v1/admin/request-profiles/{id}/validate-inheritance',
        summary: 'Validate that a request profile\'s inheritance overrides do not violate the parent profile\'s constraints.',
        auth: 'Authorize (CaAuditor)',
        category: 'Admin Request Profiles',
        headers: [
            { name: 'Authorization', type: 'Bearer token', required: true, description: 'JWT access token from /api/v1/auth/login' },
        ],
        responseDescription: '{ isValid: boolean, errors: string[] }. Empty errors array when valid.',
    },
    {
        method: 'POST',
        path: '/api/v1/admin/request-profiles',
        summary: 'Create a new request profile with subject DN rules, SAN rules, enrollment constraints, and optional inheritance configuration.',
        auth: 'Authorize (CaOperator)',
        category: 'Admin Request Profiles',
        headers: [
            { name: 'Authorization', type: 'Bearer token', required: true, description: 'JWT access token from /api/v1/auth/login' },
            { name: 'X-MFA-Token', type: 'string', required: false, description: 'Step-up MFA token from /api/v1/auth/mfa/verify-stepup for create-request-profile. Required for this operation.' },
        ],
        responseDescription: 'Created request profile with ID.',
    },
    {
        method: 'PUT',
        path: '/api/v1/admin/request-profiles/{id}',
        summary: 'Update an existing request profile with new rules, constraints, and optional inheritance configuration. Requires step-up MFA.',
        auth: 'Authorize (CaOperator)',
        category: 'Admin Request Profiles',
        headers: [
            { name: 'Authorization', type: 'Bearer token', required: true, description: 'JWT access token from /api/v1/auth/login' },
            { name: 'X-MFA-Token', type: 'string', required: true, description: 'Step-up MFA token from /api/v1/auth/mfa/verify-stepup' },
        ],
        responseDescription: 'Updated request profile.',
    },
    {
        method: 'DELETE',
        path: '/api/v1/admin/request-profiles/{id}',
        summary: 'Delete a request profile by ID. Requires step-up MFA.',
        auth: 'Authorize (CaOperator)',
        category: 'Admin Request Profiles',
        headers: [
            { name: 'Authorization', type: 'Bearer token', required: true, description: 'JWT access token from /api/v1/auth/login' },
            { name: 'X-MFA-Token', type: 'string', required: true, description: 'Step-up MFA token from /api/v1/auth/mfa/verify-stepup' },
        ],
        responseDescription: 'No content (204) on success. Returns 404 if profile not found.',
    },
];
