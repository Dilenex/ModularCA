import type { ApiEndpoint } from '../../types';

export const adminCertPermissions: ApiEndpoint[] = [
    {
        method: 'POST',
        path: '/api/v1/admin/manage/cert-permissions/allow/view',
        summary: 'Grant view-level access to a certificate for a user.',
        auth: 'Authorize (CaOperator)',
        category: 'Admin Certificate Permissions',
        headers: [
            { name: 'Authorization', type: 'Bearer token', required: true, description: 'JWT access token from /api/v1/auth/login' },
            { name: 'X-MFA-Token', type: 'string', required: false, description: 'Step-up MFA token from /api/v1/auth/mfa/verify-stepup for UpdateCertAcl, issued for the certificate id. Required for this operation.' },
        ],
        responseDescription: 'Confirmation of view permission grant.',
    },
    {
        method: 'POST',
        path: '/api/v1/admin/manage/cert-permissions/allow/manage',
        summary: 'Grant manage-level access to a certificate for a user.',
        auth: 'Authorize (CaOperator)',
        category: 'Admin Certificate Permissions',
        headers: [
            { name: 'Authorization', type: 'Bearer token', required: true, description: 'JWT access token from /api/v1/auth/login' },
            { name: 'X-MFA-Token', type: 'string', required: false, description: 'Step-up MFA token from /api/v1/auth/mfa/verify-stepup for UpdateCertAcl, issued for the certificate id. Required for this operation.' },
        ],
        responseDescription: 'Confirmation of manage permission grant.',
    },
    {
        method: 'POST',
        path: '/api/v1/admin/manage/cert-permissions/downgrade',
        summary: 'Downgrade a user\'s certificate access from manage to view.',
        auth: 'Authorize (CaOperator)',
        category: 'Admin Certificate Permissions',
        headers: [
            { name: 'Authorization', type: 'Bearer token', required: true, description: 'JWT access token from /api/v1/auth/login' },
            { name: 'X-MFA-Token', type: 'string', required: false, description: 'Step-up MFA token from /api/v1/auth/mfa/verify-stepup for UpdateCertAcl, issued for the certificate id. Required for this operation.' },
        ],
        responseDescription: 'Confirmation of permission downgrade.',
    },
    {
        method: 'POST',
        path: '/api/v1/admin/manage/cert-permissions/revoke',
        summary: 'Revoke all access to a certificate for a user.',
        auth: 'Authorize (CaOperator)',
        category: 'Admin Certificate Permissions',
        headers: [
            { name: 'Authorization', type: 'Bearer token', required: true, description: 'JWT access token from /api/v1/auth/login' },
            { name: 'X-MFA-Token', type: 'string', required: false, description: 'Step-up MFA token from /api/v1/auth/mfa/verify-stepup for UpdateCertAcl, issued for the certificate id. Required for this operation.' },
        ],
        responseDescription: 'Confirmation of permission revocation.',
    },
];
