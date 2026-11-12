import type { ApiEndpoint } from '../../types';

export const adminRequestProfiles: ApiEndpoint[] = [
    {
        method: 'GET',
        path: '/api/v1/admin/request-profiles',
        summary: 'List the request profiles the caller may see, ordered by name. Optionally narrowed to a CA or a space, as the console\'s scope switcher does. Non-system-admin callers see only profiles they have capability grants for.',
        auth: 'Authorize (CaOperator)',
        category: 'Admin Request Profiles',
        queryParams: [
            { name: 'caId', type: 'guid', required: false, description: 'Optional CA view: the profiles bound to this CA, and the unbound (system-wide) ones.' },
            { name: 'spaceId', type: 'guid', required: false, description: 'Optional space view: the profiles bound to a CA of this space, and the unbound (system-wide) ones. A profile bound to an instance CA or to a CA of another space is left out.' },
        ],
        notes: 'caId and spaceId only narrow the list: they are applied after the caller\'s own limits, so naming a CA or a space the caller cannot see shows none of its profiles. With both, a profile must be in both views. The query key that spaceId replaced in 0.4.0 is refused with 400.',
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
        notes: 'Inheritance resolves the whole chain: the profile is clamped against its parent\'s effective values, so a limit set on a grandparent binds even when the profile in between leaves the field unset.',
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
        notes: 'The profile is judged against its parent\'s effective values, every ancestor applied. A required approval count of 0 inherits the parent\'s and is not an error.',
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
