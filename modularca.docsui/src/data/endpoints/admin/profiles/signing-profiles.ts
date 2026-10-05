import type { ApiEndpoint } from '../../types';

export const adminSigningProfiles: ApiEndpoint[] = [
    {
        method: 'GET',
        path: '/api/v1/admin/signing-profiles',
        summary: 'List all signing profiles including allowed cert profile IDs and inheritance configuration. Non-system-admin callers see only profiles they have capability grants for.',
        auth: 'Authorize (CaAuditor)',
        category: 'Admin Signing Profiles',
        headers: [
            { name: 'Authorization', type: 'Bearer token', required: true, description: 'JWT access token from /api/v1/auth/login' },
        ],
        responseDescription: 'Array of signing profiles with algorithm constraints, name constraints, policy OIDs, and inheritance config.',
    },
    {
        method: 'GET',
        path: '/api/v1/admin/signing-profiles/{id}',
        summary: 'Get a single signing profile by ID, including allowed cert profile IDs and inheritance configuration.',
        auth: 'Authorize (CaAuditor)',
        category: 'Admin Signing Profiles',
        headers: [
            { name: 'Authorization', type: 'Bearer token', required: true, description: 'JWT access token from /api/v1/auth/login' },
        ],
        responseDescription: 'Signing profile details with full configuration.',
    },
    {
        method: 'POST',
        path: '/api/v1/admin/signing-profiles',
        summary: 'Create a new signing profile with optional allowed cert profile links and inheritance configuration.',
        auth: 'Authorize (CaAdmin)',
        category: 'Admin Signing Profiles',
        headers: [
            { name: 'Authorization', type: 'Bearer token', required: true, description: 'JWT access token from /api/v1/auth/login' },
        ],
        responseDescription: 'Created signing profile.',
        notes: 'Each allowed cert profile must be visible to the caller and usable by the issuing CA: an instance-wide profile (no space, no CA), a profile of the CA’s space bound to no CA, or one bound to this CA. An unbound signing profile takes instance-wide profiles only. Anything else is refused with 400 (code MCA-CFG-019 when out of scope).',
    },
    {
        method: 'PUT',
        path: '/api/v1/admin/signing-profiles/{id}',
        summary: 'Update an existing signing profile and replace its allowed cert profile links and inheritance configuration. Requires step-up MFA.',
        auth: 'Authorize (CaAdmin)',
        category: 'Admin Signing Profiles',
        headers: [
            { name: 'Authorization', type: 'Bearer token', required: true, description: 'JWT access token from /api/v1/auth/login' },
            { name: 'X-MFA-Token', type: 'string', required: true, description: 'Step-up MFA token from /api/v1/auth/mfa/verify-stepup' },
        ],
        responseDescription: 'No content (204) on success.',
        notes: 'Triggers a security alert when a signing profile is updated. Each allowed cert profile must be visible to the caller and usable by the issuing CA: an instance-wide profile (no space, no CA), a profile of the CA’s space bound to no CA, or one bound to this CA. An unbound signing profile takes instance-wide profiles only. Anything else is refused with 400 (code MCA-CFG-019 when out of scope). A link already on the profile need not be visible to the caller.',
    },
    {
        method: 'DELETE',
        path: '/api/v1/admin/signing-profiles/{id}',
        summary: 'Delete a signing profile and its associated cert profile links. Requires step-up MFA.',
        auth: 'Authorize (CaAdmin)',
        category: 'Admin Signing Profiles',
        headers: [
            { name: 'Authorization', type: 'Bearer token', required: true, description: 'JWT access token from /api/v1/auth/login' },
            { name: 'X-MFA-Token', type: 'string', required: true, description: 'Step-up MFA token from /api/v1/auth/mfa/verify-stepup' },
        ],
        responseDescription: 'No content (204) on success.',
        notes: 'Triggers a security alert when a signing profile is deleted.',
    },
    {
        method: 'PUT',
        path: '/api/v1/admin/signing-profiles/{id}/allowed-cert-profiles',
        summary: 'Replace the set of allowed cert profile IDs for the specified signing profile. Requires step-up MFA.',
        auth: 'Authorize (CaAdmin)',
        category: 'Admin Signing Profiles',
        requestBody: [
            { name: '(body)', type: 'guid[]', required: true, description: 'Array of certificate profile GUIDs to allow for this signing profile' },
        ],
        headers: [
            { name: 'Authorization', type: 'Bearer token', required: true, description: 'JWT access token from /api/v1/auth/login' },
            { name: 'X-MFA-Token', type: 'string', required: true, description: 'Step-up MFA token from /api/v1/auth/mfa/verify-stepup' },
        ],
        responseDescription: 'No content (204) on success.',
        notes: 'A signing profile outside the caller’s space fence is not found (404). Each allowed cert profile must be visible to the caller and usable by the issuing CA: an instance-wide profile (no space, no CA), a profile of the CA’s space bound to no CA, or one bound to this CA. An unbound signing profile takes instance-wide profiles only. Anything else is refused with 400 (code MCA-CFG-019 when out of scope). A link already on the profile need not be visible to the caller.',
    },
    {
        method: 'GET',
        path: '/api/v1/admin/signing-profiles/{id}/allowed-cert-profiles',
        summary: 'Get the list of allowed cert profile IDs for the specified signing profile.',
        auth: 'Authorize (CaAuditor)',
        category: 'Admin Signing Profiles',
        headers: [
            { name: 'Authorization', type: 'Bearer token', required: true, description: 'JWT access token from /api/v1/auth/login' },
        ],
        responseDescription: 'Array of allowed certificate profile GUIDs.',
    },
];
