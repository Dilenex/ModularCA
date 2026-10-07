import type { ApiEndpoint } from '../../types';

export const adminPasswordPolicy: ApiEndpoint[] = [
    {
        method: 'GET',
        path: '/api/v1/admin/password-policy',
        summary: 'Get the current password policy configuration.',
        auth: 'Authorize (SystemAdmin)',
        category: 'Admin Password Policy',
        headers: [
            { name: 'Authorization', type: 'Bearer token', required: true, description: 'JWT access token from /api/v1/auth/login' },
        ],
        responseDescription: 'Password policy settings.',
    },
    {
        method: 'PUT',
        path: '/api/v1/admin/password-policy',
        summary: 'Update the password policy. MinLength must be at least 8 and at most MaxLength (0 = no maximum), counts must not be negative, and HistoryCount must not exceed 24. DictionaryPath names a file in config/password-dictionaries by its file name; empty clears it.',
        auth: 'Authorize (SystemAdmin)',
        category: 'Admin Password Policy',
        headers: [
            { name: 'Authorization', type: 'Bearer token', required: true, description: 'JWT access token from /api/v1/auth/login' },
            { name: 'X-MFA-Token', type: 'string', required: true, description: 'Step-up MFA token scoped to update-config.' },
        ],
        responseDescription: 'Updated password policy.',
    },
];
