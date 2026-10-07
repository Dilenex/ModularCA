import type { ApiEndpoint } from '../../types';

export const adminQuotas: ApiEndpoint[] = [
    {
        method: 'GET',
        path: '/api/v1/admin/quotas',
        summary: 'Returns quota usage summaries for all enabled CAs, including issued counts, remaining capacity, and warning/exceeded status. Non-system-admins see only CAs belonging to their accessible spaces.',
        auth: 'Authorize (SystemOperator)',
        category: 'Admin Quotas',
        headers: [
            { name: 'Authorization', type: 'Bearer token', required: true, description: 'JWT access token from /api/v1/auth/login' },
        ],
        responseDescription: 'Summary object with totalIssuedCertificates, exceededCount, warningCount, and caQuotas array (each with caId, caName, issuedCount, maxCertificates, usagePercent, isExceeded).',
    },
    {
        method: 'GET',
        path: '/api/v1/admin/quotas/{caId}',
        summary: 'Returns detailed quota status for a single CA identified by its ID.',
        auth: 'Authorize (SystemOperator)',
        category: 'Admin Quotas',
        headers: [
            { name: 'Authorization', type: 'Bearer token', required: true, description: 'JWT access token from /api/v1/auth/login' },
        ],
        responseDescription: 'Quota status including issued count, max certificates, usage percent, and exceeded/warning flags.',
    },
    {
        method: 'PUT',
        path: '/api/v1/admin/quotas/{groupId}',
        summary: 'Update certificate quota limits on a CA admin group. Only admin-level groups can have quotas configured. Use 0 for unlimited.',
        auth: 'Authorize (SystemOperator)',
        category: 'Admin Quotas',
        requestBody: [
            { name: 'maxCertificates', type: 'int', required: true, description: 'Maximum certificates that can be issued (0 = unlimited)' },
            { name: 'maxPendingRequests', type: 'int', required: true, description: 'Maximum pending CSRs allowed (0 = unlimited)' },
        ],
        headers: [
            { name: 'Authorization', type: 'Bearer token', required: true, description: 'JWT access token from /api/v1/auth/login' },
        ],
        responseDescription: 'Updated group with id, name, maxCertificates, and maxPendingRequests.',
        notes: 'Only admin-level groups (template=Administrator or with CaManage capability) can have quotas. Returns 400 for non-admin groups or negative values.',
    },
];
