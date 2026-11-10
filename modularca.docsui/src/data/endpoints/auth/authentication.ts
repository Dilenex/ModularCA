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
        notes: 'The password is checked by the account\'s password source: Local against the local hash only; Directory against LDAP only; Inherit by the instance LDAP setting (with LDAP on: directory first, a refused bind is final, the local hash only for an account the directory has no entry for). An unreachable directory refuses without counting a failed attempt. An Inherit account the directory accepts becomes Directory. The forced password change and expiry apply only when the local hash answered. CSRF validation required. The server sets the CSRF cookie on any response: __Host-CSRF-TOKEN over HTTPS, CSRF-TOKEN over plain HTTP; over HTTPS an unprefixed CSRF-TOKEN is not accepted. If MFA is configured, returns requiresMfa: true with an mfaToken and available methods. Rate limited per IP (10 requests per 5 minutes).',
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
        notes: 'A Directory account keeps no local password: it is answered with the generic 401, without consulting the local hash or counting a failed attempt. When the replaced password is the one the headless bootstrap left in config/initial-admin-password, that file is deleted.',
    },
    {
        method: 'POST',
        path: '/api/v1/auth/claim',
        summary: 'Claim an account with a one-time claim token: set its password without a session or an old password.',
        auth: 'Anonymous',
        category: 'Authentication',
        requestBody: [
            { name: 'token', type: 'string', required: true, description: 'The claim token (43 characters of base64url from --new-claim-token or --issue-claim-token). Surrounding whitespace is ignored.' },
            { name: 'newPassword', type: 'string', required: true, description: 'The password to set; must meet the password policy' },
            { name: 'confirmNewPassword', type: 'string', required: true, description: 'New password confirmation' },
        ],
        responseDescription: '200 with { message, username } when the account is claimed; sign in with the new password. 400 with { error, details } when the password fails the policy, and 400 with one fixed error for every refused token.',
        notes: 'The instance keeps only the token\'s SHA-256 (of its UTF-8 text), recorded by the headless bootstrap from bootstrap.yaml\'s Administration.ClaimTokenSha256 or on the host by --issue-claim-token, which replaces any earlier claim. The password policy is checked before the token, so a policy refusal says nothing about the claim. The token is compared with every claim in constant time. A token that matches nothing, a claim that has expired (Administration.ClaimTokenLifetimeHours, seven days by default) or was already used, and an account that is disabled, a service identity or a Directory account all get the same 400 error, after the login response delay, and are audited as UserLoginFailed with source "claim". A claim works once: it sets the password, records it in the password history, clears any lockout and the forced change at next sign-in, leaves the password source as it is, ends the account\'s sessions, and is audited as UserAccountClaimed. Rate limited per IP (10 requests per 15 minutes).',
    },
    {
        method: 'POST',
        path: '/api/v1/auth/logout',
        summary: 'Sign the current user out of every session of the account.',
        auth: 'Authorize',
        category: 'Authentication',
        headers: [
            { name: 'Authorization', type: 'Bearer token', required: true, description: 'JWT access token from /api/v1/auth/login' },
        ],
        responseDescription: 'Confirmation that all sessions have been revoked.',
        notes: 'There is no per-device sign-out: logging out ends every session of the account, on this device and every other. Every refresh token is revoked and the security stamp rotates, so access tokens held elsewhere are refused on their next request with 401 instead of running until they expire. Audited as UserLogout with the number of refresh tokens revoked.',
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
