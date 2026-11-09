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
        responseDescription: 'Array of certificate profiles, each with its expiry warning settings (expiryWarningPercent, expiryWarningMaxWindow, expiryAlertPercent, expiryAlertMaxWindow, expiryNeverWarn, expiryWarningOverridesParent).',
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
        responseDescription: 'Resolved profile with effective values after inheritance, including the effective expiry warning settings, and fieldSources: the source of each field by its C# property name (for example ExpiryWarningPercent), "inherited", "overridden" or "clamped" (the child would warn later than its parent allows, so the parent\'s value is used).',
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
        responseDescription: 'Validation result with any inheritance violations, including expiry warning values that would warn later than the parent (unless the profile overrides its parent\'s expiry settings).',
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
        requestBody: [
            { name: 'expiryWarningPercent', type: 'int | null', required: false, description: 'Share of a certificate\'s lifetime, 1 to 100, that remains when its expiry warning (amber) starts. Null takes the parent\'s value or the default, 30. A CA certificate whose profile sets neither this nor expiryWarningMaxWindow warns 30 days before expiry.' },
            { name: 'expiryWarningMaxWindow', type: 'string | null', required: false, description: 'Longest warning window, an ISO 8601 duration such as P30D or PT6H. Null for no cap (or the parent\'s).' },
            { name: 'expiryAlertPercent', type: 'int | null', required: false, description: 'Share of the lifetime, 1 to 100 and no larger than expiryWarningPercent, that remains when the expiry alert (red) starts. Null takes the parent\'s value or the default, 10. A CA certificate whose profile sets neither alert value alerts 7 days before expiry.' },
            { name: 'expiryAlertMaxWindow', type: 'string | null', required: false, description: 'Longest alert window, an ISO 8601 duration, no longer than expiryWarningMaxWindow. Null for no cap (or the parent\'s).' },
            { name: 'expiryNeverWarn', type: 'bool', required: false, description: 'The certificates are renewed automatically: neither warning is raised and no expiry e-mail is sent. A certificate that expires unreplaced still counts as expired, not replaced. The seeded Web TLS Certificate Profile has it set.' },
            { name: 'expiryWarningOverridesParent', type: 'bool', required: false, description: 'With inheritance: the expiry values set here replace the parent\'s as they are. Without it, a child may only warn earlier than its parent (a percent and window at least the parent\'s, never-warn only when the parent never warns); a later value is clamped to the parent\'s. Between two CA profiles, a level the parent leaves unset counts as its CA default window, 30 days for the warning and 7 for the alert, so a longer window on the child is kept.' },
        ],
        responseDescription: 'Created certificate profile.',
        notes: 'The request also takes the profile\'s usages, validity, key and signature limits, CT settings, CA scope and inheritance. Expiry warning settings outside the ranges above are refused with 400, code MCA-PRF-001.',
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
        requestBody: [
            { name: 'expiryWarningPercent', type: 'int | null', required: false, description: 'Share of a certificate\'s lifetime, 1 to 100, that remains when its expiry warning (amber) starts. Null takes the parent\'s value or the default, 30. A CA certificate whose profile sets neither this nor expiryWarningMaxWindow warns 30 days before expiry.' },
            { name: 'expiryWarningMaxWindow', type: 'string | null', required: false, description: 'Longest warning window, an ISO 8601 duration such as P30D or PT6H. Null for no cap (or the parent\'s).' },
            { name: 'expiryAlertPercent', type: 'int | null', required: false, description: 'Share of the lifetime, 1 to 100 and no larger than expiryWarningPercent, that remains when the expiry alert (red) starts. Null takes the parent\'s value or the default, 10. A CA certificate whose profile sets neither alert value alerts 7 days before expiry.' },
            { name: 'expiryAlertMaxWindow', type: 'string | null', required: false, description: 'Longest alert window, an ISO 8601 duration, no longer than expiryWarningMaxWindow. Null for no cap (or the parent\'s).' },
            { name: 'expiryNeverWarn', type: 'bool', required: false, description: 'The certificates are renewed automatically: neither warning is raised and no expiry e-mail is sent. A certificate that expires unreplaced still counts as expired, not replaced. The seeded Web TLS Certificate Profile has it set.' },
            { name: 'expiryWarningOverridesParent', type: 'bool', required: false, description: 'With inheritance: the expiry values set here replace the parent\'s as they are. Without it, a child may only warn earlier than its parent (a percent and window at least the parent\'s, never-warn only when the parent never warns); a later value is clamped to the parent\'s. Between two CA profiles, a level the parent leaves unset counts as its CA default window, 30 days for the warning and 7 for the alert, so a longer window on the child is kept.' },
        ],
        responseDescription: 'Updated certificate profile.',
        notes: 'Takes every field of the create request. Invalid expiry warning settings are refused with 400, code MCA-PRF-001. When the expiry warning settings or the inheritance change, the expiry warning and alert instants of the profile\'s valid certificates (not revoked, not expired), and of those of the profiles inheriting from it, are re-computed in the same transaction as the save, so if the re-compute fails the profile is not changed either; the CertProfileUpdated audit entry records how many as ExpiryWarningsRecomputed.',
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
