import type { ApiEndpoint } from '../types';

export const webauthnMfa: ApiEndpoint[] = [
    {
        method: 'POST',
        path: '/api/v1/auth/webauthn/register-options',
        summary: 'Get credential creation options (challenge) to begin registering a FIDO2 security key.',
        auth: 'Authorize',
        category: 'WebAuthn MFA',
        headers: [
            { name: 'Authorization', type: 'Bearer token', required: true, description: 'JWT access token from /api/v1/auth/login' },
        ],
        responseDescription: 'PublicKeyCredentialCreationOptions for the browser WebAuthn API.',
    },
    {
        method: 'POST',
        path: '/api/v1/auth/webauthn/register',
        summary: 'Complete security key registration by verifying the authenticator attestation response.',
        auth: 'Authorize',
        category: 'WebAuthn MFA',
        queryParams: [
            { name: 'deviceName', type: 'string', required: false, description: 'Optional friendly name for the security key' },
        ],
        headers: [
            { name: 'Authorization', type: 'Bearer token', required: true, description: 'JWT access token from /api/v1/auth/login' },
        ],
        responseDescription: 'Credential ID and success confirmation.',
    },
    {
        method: 'POST',
        path: '/api/v1/auth/webauthn/assertion-options',
        summary: 'Get assertion options (challenge) for second-factor verification during login.',
        auth: 'Anonymous',
        category: 'WebAuthn MFA',
        requestBody: [
            { name: 'mfaToken', type: 'string', required: true, description: 'Temporary MFA token from the login endpoint' },
        ],
        responseDescription: 'PublicKeyCredentialRequestOptions for the browser WebAuthn API.',
        notes: 'Requires mfaToken (not username) to identify the user without exposing usernames.',
    },
    {
        method: 'POST',
        path: '/api/v1/auth/webauthn/assertion',
        summary: 'Verify WebAuthn assertion response. Issues JWT on success completing 2FA login.',
        auth: 'Anonymous',
        category: 'WebAuthn MFA',
        requestBody: [
            { name: 'mfaToken', type: 'string', required: true, description: 'Temporary MFA token from the login endpoint. Required to prove prior password authentication.' },
            { name: 'assertionResponse', type: 'AuthenticatorAssertionRawResponse', required: true, description: 'Raw authenticator assertion response from the browser' },
        ],
        responseDescription: 'JWT token pair on successful WebAuthn verification.',
        notes: 'Per-user failure counter enforced. After too many failed attempts, the MFA token is consumed and the user must log in again.',
    },
    {
        method: 'GET',
        path: '/api/v1/auth/webauthn/credentials',
        summary: 'List all registered FIDO2 credentials for the authenticated user.',
        auth: 'Authorize',
        category: 'WebAuthn MFA',
        headers: [
            { name: 'Authorization', type: 'Bearer token', required: true, description: 'JWT access token from /api/v1/auth/login' },
        ],
        responseDescription: 'Array of credentials with ID, device name, registration date, and last used date.',
    },
    {
        method: 'DELETE',
        path: '/api/v1/auth/webauthn/credentials/{id}',
        summary: 'Remove a registered FIDO2 credential. Requires step-up MFA.',
        auth: 'Authorize',
        category: 'WebAuthn MFA',
        headers: [
            { name: 'Authorization', type: 'Bearer token', required: true, description: 'JWT access token from /api/v1/auth/login' },
            { name: 'X-MFA-Token', type: 'string', required: false, description: 'Step-up MFA token from /api/v1/auth/mfa/verify-stepup. Required for this operation.' },
        ],
        responseDescription: 'Confirmation that the credential was removed.',
        notes: 'Signs the account out of every session, this one included, since a session does not record which credential opened it. Blocked if this is the user\'s only remaining MFA method.',
    },
];
