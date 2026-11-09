import type { ApiEndpoint } from '../../types';

export const adminPolicy: ApiEndpoint[] = [
    {
        method: 'POST',
        path: '/api/v1/admin/policy/check',
        summary: 'Check a certificate request against the configured policy engine.',
        auth: 'Authorize (CaOperator)',
        category: 'Admin Policy',
        headers: [
            { name: 'Authorization', type: 'Bearer token', required: true, description: 'JWT access token from /api/v1/auth/login' },
        ],
        responseDescription: 'Policy check result with any violations.',
    },
    {
        method: 'POST',
        path: '/api/v1/admin/policy/sync',
        summary: 'Sync policies from an external source.',
        auth: 'Authorize (SystemAdmin)',
        category: 'Admin Policy',
        headers: [
            { name: 'Authorization', type: 'Bearer token', required: true, description: 'JWT access token from /api/v1/auth/login' },
        ],
        responseDescription: 'Sync result.',
        notes: 'In cert-profiles.yaml the expiry warning keys (expiryWarningPercent, expiryWarningMaxWindow, expiryAlertPercent, expiryAlertMaxWindow, expiryNeverWarn, expiryWarningOverridesParent) are optional: a key an entry leaves out keeps the profile\'s current value, so a file written before 0.4.3 leaves the settings made in the console alone. A percent or window given as null (~), or a window given as an empty string, clears it.',
    },
];
