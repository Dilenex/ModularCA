import type { ApiEndpoint } from '../../types';

export const adminTrustAnchors: ApiEndpoint[] = [
    {
        method: 'GET',
        path: '/api/v1/admin/trust-anchors',
        summary: 'List all trust anchors (external CA certificates).',
        auth: 'Authorize (SystemOperator)',
        category: 'Admin Trust Anchors',
        headers: [
            { name: 'Authorization', type: 'Bearer token', required: true, description: 'JWT access token from /api/v1/auth/login' },
        ],
        responseDescription: 'Array of trust anchor entries.',
    },
    {
        method: 'GET',
        path: '/api/v1/admin/trust-anchors/{id}',
        summary: 'Get a trust anchor by ID.',
        auth: 'Authorize (SystemOperator)',
        category: 'Admin Trust Anchors',
        headers: [
            { name: 'Authorization', type: 'Bearer token', required: true, description: 'JWT access token from /api/v1/auth/login' },
        ],
        responseDescription: 'Trust anchor details.',
    },
    {
        method: 'POST',
        path: '/api/v1/admin/trust-anchors',
        summary: 'Import an external CA certificate as a trust anchor.',
        auth: 'Authorize (SystemOperator)',
        category: 'Admin Trust Anchors',
        headers: [
            { name: 'Authorization', type: 'Bearer token', required: true, description: 'JWT access token from /api/v1/auth/login' },
            { name: 'X-MFA-Token', type: 'string', required: false, description: 'Step-up MFA token from /api/v1/auth/mfa/verify-stepup for manage-trust-anchor. Required for this operation.' },
        ],
        responseDescription: 'Created trust anchor.',
    },
    {
        method: 'DELETE',
        path: '/api/v1/admin/trust-anchors/{id}',
        summary: 'Remove a trust anchor.',
        auth: 'Authorize (SystemOperator)',
        category: 'Admin Trust Anchors',
        headers: [
            { name: 'Authorization', type: 'Bearer token', required: true, description: 'JWT access token from /api/v1/auth/login' },
            { name: 'X-MFA-Token', type: 'string', required: false, description: 'Step-up MFA token from /api/v1/auth/mfa/verify-stepup for manage-trust-anchor, issued for the anchor id. Required for this operation.' },
        ],
        responseDescription: 'Deletion confirmation.',
    },
    {
        method: 'PUT',
        path: '/api/v1/admin/trust-anchors/{id}/toggle',
        summary: 'Enable or disable a trust anchor.',
        auth: 'Authorize (SystemOperator)',
        category: 'Admin Trust Anchors',
        headers: [
            { name: 'Authorization', type: 'Bearer token', required: true, description: 'JWT access token from /api/v1/auth/login' },
            { name: 'X-MFA-Token', type: 'string', required: false, description: 'Step-up MFA token from /api/v1/auth/mfa/verify-stepup for manage-trust-anchor, issued for the anchor id. Required for this operation.' },
        ],
        responseDescription: 'Toggle confirmation.',
    },
];
