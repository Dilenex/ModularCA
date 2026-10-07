import type { ApiEndpoint } from '../../types';

export const adminSshTemplates: ApiEndpoint[] = [
    {
        method: 'GET',
        path: '/api/v1/admin/ssh/templates',
        summary: 'List all SSH certificate templates.',
        auth: 'Authorize (CaOperator)',
        category: 'Admin SSH Templates',
        headers: [
            { name: 'Authorization', type: 'Bearer token', required: true, description: 'JWT access token from /api/v1/auth/login' },
        ],
        responseDescription: 'Array of SSH certificate templates.',
    },
    {
        method: 'GET',
        path: '/api/v1/admin/ssh/templates/{id}',
        summary: 'Get an SSH certificate template by ID.',
        auth: 'Authorize (CaOperator)',
        category: 'Admin SSH Templates',
        headers: [
            { name: 'Authorization', type: 'Bearer token', required: true, description: 'JWT access token from /api/v1/auth/login' },
        ],
        responseDescription: 'SSH certificate template details.',
    },
    {
        method: 'POST',
        path: '/api/v1/admin/ssh/templates',
        summary: 'Create a new SSH certificate template.',
        auth: 'Authorize (CaOperator)',
        category: 'Admin SSH Templates',
        headers: [
            { name: 'Authorization', type: 'Bearer token', required: true, description: 'JWT access token from /api/v1/auth/login' },
            { name: 'X-MFA-Token', type: 'string', required: false, description: 'Step-up MFA token from /api/v1/auth/mfa/verify-stepup for manage-ssh-template. Required for this operation.' },
        ],
        responseDescription: 'Created SSH certificate template.',
    },
    {
        method: 'PUT',
        path: '/api/v1/admin/ssh/templates/{id}',
        summary: 'Update an SSH certificate template.',
        auth: 'Authorize (CaOperator)',
        category: 'Admin SSH Templates',
        headers: [
            { name: 'Authorization', type: 'Bearer token', required: true, description: 'JWT access token from /api/v1/auth/login' },
            { name: 'X-MFA-Token', type: 'string', required: false, description: 'Step-up MFA token from /api/v1/auth/mfa/verify-stepup for manage-ssh-template, issued for the template id. Required for this operation.' },
        ],
        responseDescription: 'Updated SSH certificate template.',
    },
    {
        method: 'DELETE',
        path: '/api/v1/admin/ssh/templates/{id}',
        summary: 'Delete an SSH certificate template.',
        auth: 'Authorize (CaOperator)',
        category: 'Admin SSH Templates',
        headers: [
            { name: 'Authorization', type: 'Bearer token', required: true, description: 'JWT access token from /api/v1/auth/login' },
            { name: 'X-MFA-Token', type: 'string', required: false, description: 'Step-up MFA token from /api/v1/auth/mfa/verify-stepup for manage-ssh-template, issued for the template id. Required for this operation.' },
        ],
        responseDescription: 'Deletion confirmation.',
    },
];
