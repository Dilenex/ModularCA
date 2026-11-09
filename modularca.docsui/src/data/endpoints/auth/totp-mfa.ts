import type { ApiEndpoint } from '../types';

export const totpMfa: ApiEndpoint[] = [
    {
        method: 'POST',
        path: '/api/v1/auth/totp/setup',
        summary: 'Generate a new TOTP secret and provisioning URI for authenticator app enrollment.',
        auth: 'Authorize',
        category: 'TOTP MFA',
        requestBody: [
            { name: 'deviceName', type: 'string', required: false, description: 'Optional friendly name for the authenticator device' },
        ],
        headers: [
            { name: 'Authorization', type: 'Bearer token', required: true, description: 'JWT access token from /api/v1/auth/login' },
        ],
        responseDescription: 'Base32-encoded secret, provisioning URI for QR code, and setup instructions.',
    },
    {
        method: 'POST',
        path: '/api/v1/auth/totp/verify-setup',
        summary: 'Verify the first TOTP code after setup to confirm authenticator app enrollment.',
        auth: 'Authorize',
        category: 'TOTP MFA',
        requestBody: [
            { name: 'code', type: 'string', required: true, description: 'The 6-digit TOTP code from the authenticator app' },
        ],
        headers: [
            { name: 'Authorization', type: 'Bearer token', required: true, description: 'JWT access token from /api/v1/auth/login' },
        ],
        responseDescription: 'Confirmation that TOTP setup is verified and active.',
    },
    {
        method: 'POST',
        path: '/api/v1/auth/totp/verify',
        summary: 'Verify a TOTP code during the login MFA flow. Issues full JWT on success.',
        auth: 'Anonymous',
        category: 'TOTP MFA',
        requestBody: [
            { name: 'mfaToken', type: 'string', required: true, description: 'Temporary MFA token from the login endpoint' },
            { name: 'code', type: 'string', required: true, description: 'The 6-digit TOTP code from the authenticator app' },
        ],
        responseDescription: 'JWT token pair on successful TOTP verification.',
    },
    {
        method: 'DELETE',
        path: '/api/v1/auth/totp',
        summary: 'Remove TOTP from the authenticated user\'s account. Requires step-up MFA.',
        auth: 'Authorize',
        category: 'TOTP MFA',
        headers: [
            { name: 'Authorization', type: 'Bearer token', required: true, description: 'JWT access token from /api/v1/auth/login' },
            { name: 'X-MFA-Token', type: 'string', required: false, description: 'Step-up MFA token from /api/v1/auth/mfa/verify-stepup. Required for this operation.' },
        ],
        responseDescription: 'Confirmation that TOTP has been removed.',
        notes: 'Blocked if TOTP is the user\'s only remaining MFA method.',
    },
    {
        method: 'POST',
        path: '/api/v1/auth/totp/recovery',
        summary: 'Exchange a one-time recovery code to reset TOTP enrollment. Clears the existing TOTP secret.',
        auth: 'Anonymous',
        category: 'TOTP MFA',
        requestBody: [
            { name: 'username', type: 'string', required: true, description: 'Username of the account whose TOTP is being recovered' },
            { name: 'recoveryCode', type: 'string', required: true, description: 'Plaintext recovery code issued at TOTP enrollment (case- and dash-insensitive)' },
        ],
        responseDescription: 'Success message confirming TOTP has been reset. User must re-enroll via /auth/totp/setup.',
        notes: 'Recovery codes are single-use and stored as per-user salted PBKDF2 hashes. Codes issued before 0.4.3 stay in the old unsalted SHA-256 form until they are used or TOTP is enrolled again, which replaces them. A wrong code counts as a failed sign-in and locks the account at the security policy\'s failed-attempt threshold, and administrators are notified of the lockout as for a wrong password. Every refusal costs the same hashing and is held to the security policy\'s login response delay, so its timing does not show whether the account exists or can sign in. After success the user\'s security stamp is rotated and every refresh token revoked, so outstanding tokens stop working at once. Rate limited per IP (5 requests per 15 minutes).',
    },
];
