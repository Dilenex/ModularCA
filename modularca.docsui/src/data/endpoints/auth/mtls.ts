import type { ApiEndpoint } from '../types';

export const mtls: ApiEndpoint[] = [
    {
        method: 'GET',
        path: '/api/v1/auth/mtls/auth-info',
        summary: 'Returns the current mTLS authentication configuration (auth subdomain, auth port).',
        auth: 'Anonymous',
        category: 'mTLS Authentication',
        responseDescription: 'Whether mTLS is enabled, subdomain URL, and auth port URL.',
    },
    {
        method: 'GET',
        path: '/api/v1/auth/mtls/allowed-cas',
        summary: 'List CAs the user is allowed to obtain mTLS certificates from, based on group memberships.',
        auth: 'Authorize',
        category: 'mTLS Authentication',
        headers: [
            { name: 'Authorization', type: 'Bearer token', required: true, description: 'JWT access token from /api/v1/auth/login' },
        ],
        responseDescription: 'Array of allowed CAs with ID, name, and label.',
    },
    {
        method: 'POST',
        path: '/api/v1/auth/mtls/enroll',
        summary: 'Enroll a new mTLS client certificate. Returns PKCS#12 with the cert and private key.',
        auth: 'Authorize',
        category: 'mTLS Authentication',
        requestBody: [
            { name: 'caId', type: 'guid', required: true, description: 'The CA to use for signing the mTLS client certificate' },
            { name: 'deviceName', type: 'string', required: false, description: 'Optional friendly name for the credential' },
        ],
        headers: [
            { name: 'Authorization', type: 'Bearer token', required: true, description: 'JWT access token from /api/v1/auth/login' },
        ],
        responseDescription: 'PKCS#12 file download. Password returned in X-Pkcs12-Password response header.',
    },
    {
        method: 'GET',
        path: '/api/v1/auth/mtls/credentials',
        summary: 'List all mTLS credentials for the authenticated user.',
        auth: 'Authorize',
        category: 'mTLS Authentication',
        headers: [
            { name: 'Authorization', type: 'Bearer token', required: true, description: 'JWT access token from /api/v1/auth/login' },
        ],
        responseDescription: 'Array of credentials with device name, serial, issuance/expiration dates, revocation status, and signing CA.',
    },
    {
        method: 'DELETE',
        path: '/api/v1/auth/mtls/credentials/{id}',
        summary: 'Revoke an mTLS credential. Requires step-up MFA.',
        auth: 'Authorize',
        category: 'mTLS Authentication',
        headers: [
            { name: 'Authorization', type: 'Bearer token', required: true, description: 'JWT access token from /api/v1/auth/login' },
            { name: 'X-MFA-Token', type: 'string', required: false, description: 'Step-up MFA token from /api/v1/auth/mfa/verify-stepup. Required for this operation.' },
        ],
        responseDescription: 'Confirmation that the mTLS credential was revoked.',
        notes: 'Also revokes the underlying certificate and signs the account out of every session, this one included, since a session does not record which credential opened it. Blocked if this is the user\'s only remaining MFA method.',
    },
    {
        method: 'POST',
        path: '/api/v1/auth/mtls/verify',
        summary: 'Verify mTLS during the login MFA flow. Reads client cert from TLS connection and issues JWT.',
        auth: 'Anonymous',
        category: 'mTLS Authentication',
        requestBody: [
            { name: 'mfaToken', type: 'string', required: true, description: 'Temporary MFA token from the login endpoint' },
        ],
        headers: [
            { name: 'DPoP', type: 'string', required: false, description: 'DPoP proof for POST to this URL. Binds the session\'s refresh token to the proving key.' },
        ],
        responseDescription: 'JWT token pair on successful mTLS verification.',
        notes: 'Client certificate must be presented at the TLS layer. A certificate that is revoked or on hold is refused with 401 and audited.',
    },
    {
        method: 'GET',
        path: '/api/v1/auth/mtls/verify-redirect',
        summary: 'Browser-navigation mTLS verification. Triggers TLS renegotiation and redirects with auth code.',
        auth: 'Anonymous',
        category: 'mTLS Authentication',
        queryParams: [
            { name: 'mfaToken', type: 'string', required: true, description: 'Temporary MFA token from the login endpoint' },
        ],
        responseDescription: 'Redirect to the admin UI with a one-time authorization code in the URL.',
        notes: 'Designed for browser navigation to trigger the certificate picker dialog. A revoked or held certificate redirects to /login?error=cert_revoked. Rate limited per IP (25 requests per 5 minutes).',
    },
    {
        method: 'GET',
        path: '/api/v1/auth/mtls/login-redirect',
        summary: 'Browser-navigation mTLS login. Issues JWT or redirects to MFA verification.',
        auth: 'Anonymous',
        category: 'mTLS Authentication',
        responseDescription: 'Redirect to admin UI with auth code (if sole factor) or to MFA verify page.',
        notes: 'Client certificate must be presented at the TLS layer. Generates one-time auth code for token exchange. A revoked or held certificate redirects to /login?error=cert_revoked. Rate limited per IP (10 requests per 5 minutes).',
    },
    {
        method: 'POST',
        path: '/api/v1/auth/mtls/exchange',
        summary: 'Exchange a one-time authorization code (from verify-redirect or login-redirect) for JWT tokens.',
        auth: 'Anonymous',
        category: 'mTLS Authentication',
        requestBody: [
            { name: 'code', type: 'string', required: true, description: 'The one-time authorization code received from the mTLS redirect' },
        ],
        headers: [
            { name: 'DPoP', type: 'string', required: false, description: 'DPoP proof for POST to this URL. Binds the session\'s refresh token to the proving key; the redirect itself cannot carry one.' },
        ],
        responseDescription: 'JWT access token, expiration, and refresh token.',
        notes: 'Code is single-use and expires after 30 seconds. Send a DPoP proof here: the redirect sign-in is a browser navigation, so this is where the session is bound to the client\'s key. Rate limited per IP (20 requests per 5 minutes).',
    },
];
