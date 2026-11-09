import type { ApiEndpoint } from '../types';

export const authentication: ApiEndpoint[] = [
    {
        method: 'GET',
        path: '/api/v1/auth/login-banner',
        summary: 'Returns the system use notification banner for display on login pages.',
        auth: 'Anonymous',
        category: 'Authentication',
        responseDescription: 'Object with banner (string or null). Returns null when no banner is configured.',
    },
    {
        method: 'POST',
        path: '/api/v1/auth/login',
        summary: 'Authenticate with username and password. Returns JWT tokens or MFA challenge.',
        auth: 'Anonymous',
        category: 'Authentication',
        requestBody: [
            { name: 'username', type: 'string', required: true, description: 'The user\'s login name' },
            { name: 'password', type: 'string', required: true, description: 'The user\'s password' },
        ],
        headers: [
            { name: 'X-CSRF-Token', type: 'string', required: true, description: 'Anti-CSRF token: the value of the __Host-CSRF-TOKEN cookie (CSRF-TOKEN over plain HTTP)' },
            { name: 'DPoP', type: 'string', required: false, description: 'DPoP proof (ES256, RFC 9449) for POST to this URL. Binds the session\'s refresh token to the proving key.' },
        ],
        responseDescription: 'JWT token pair on success, or MFA challenge with temporary mfaToken if MFA is configured.',
        notes: 'CSRF validation required. The server sets the CSRF cookie on any response: __Host-CSRF-TOKEN over HTTPS, CSRF-TOKEN over plain HTTP; over HTTPS an unprefixed CSRF-TOKEN is not accepted. If MFA is configured, returns requiresMfa: true with an mfaToken and available methods. Rate limited per IP (10 requests per 5 minutes).',
    },
    {
        method: 'POST',
        path: '/api/v1/auth/refresh',
        summary: 'Refresh an expired JWT access token using a valid refresh token.',
        auth: 'Anonymous',
        category: 'Authentication',
        requestBody: [
            { name: 'refreshToken', type: 'string', required: true, description: 'The refresh token from a previous login or refresh' },
        ],
        headers: [
            { name: 'DPoP', type: 'string', required: false, description: 'DPoP proof signed by the key the session was bound to. Required when the session is bound.' },
        ],
        responseDescription: 'New JWT access token and refresh token pair.',
        notes: 'A session bound to a DPoP key at sign-in (any sign-in that carried a proof) is refused with 401 REFRESH_POP_INVALID unless the refresh carries a proof from that key; this is enforced by default from 0.4.3 (Security.EnforceRefreshTokenPoP). A session that was never bound is not checked. Rate limited per IP (120 requests per 5 minutes).',
    },
    {
        method: 'POST',
        path: '/api/v1/auth/change-password',
        summary: 'Pre-JWT password change for users with forced password reset on first login.',
        auth: 'Anonymous',
        category: 'Authentication',
        requestBody: [
            { name: 'username', type: 'string', required: true, description: 'The user\'s login name' },
            { name: 'oldPassword', type: 'string', required: true, description: 'Current password' },
            { name: 'newPassword', type: 'string', required: true, description: 'New password' },
            { name: 'confirmNewPassword', type: 'string', required: true, description: 'New password confirmation' },
        ],
        responseDescription: 'Success message; user must log in again with the new password.',
    },
    {
        method: 'POST',
        path: '/api/v1/auth/logout',
        summary: 'Revoke JWT and all refresh tokens for the current user.',
        auth: 'Authorize',
        category: 'Authentication',
        headers: [
            { name: 'Authorization', type: 'Bearer token', required: true, description: 'JWT access token from /api/v1/auth/login' },
        ],
        responseDescription: 'Confirmation that all sessions have been revoked.',
    },
    {
        method: 'POST',
        path: '/api/v1/auth/cert-login',
        summary: 'Authenticate using a client TLS certificate (certificate-based login).',
        auth: 'Anonymous',
        category: 'Authentication',
        headers: [
            { name: 'X-CSRF-Token', type: 'string', required: true, description: 'Anti-CSRF token: the value of the __Host-CSRF-TOKEN cookie (CSRF-TOKEN over plain HTTP)' },
            { name: 'DPoP', type: 'string', required: false, description: 'DPoP proof for POST to this URL. Binds the session\'s refresh token to the proving key.' },
        ],
        responseDescription: 'JWT token pair if the certificate matches an active mTLS credential, or an MFA challenge when the user also has TOTP or WebAuthn.',
        notes: 'Client certificate must be presented at the TLS layer. A certificate that is revoked or on hold is refused with 401 and the attempt is audited, whatever the credential row says. Rate limited per IP (10 requests per 5 minutes).',
    },
];
