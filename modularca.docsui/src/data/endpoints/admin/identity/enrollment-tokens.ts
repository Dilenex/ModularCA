import type { ApiEndpoint } from '../../types';

export const adminEnrollmentTokens: ApiEndpoint[] = [
    {
        method: 'GET',
        path: '/api/v1/admin/enrollment-tokens',
        summary: 'List all active enrollment tokens, filtered by tenant access for non-system-admins. CMP PBMAC tokens omit the plaintext secret.',
        auth: 'Authorize (CaOperator)',
        category: 'Admin Enrollment Tokens',
        headers: [
            { name: 'Authorization', type: 'Bearer token', required: true, description: 'JWT access token from /api/v1/auth/login' },
        ],
        responseDescription: 'Array of enrollment tokens with id, token (always null), lastFourOfToken (CMP only), usedForCmp, cmpReferenceValue, createdAt, expiresAt, maxUses, usesRemaining, subjectRestriction, sanRestriction, protocol, isRevoked, requestProfileId, certProfileId, signingProfileId, certificateAuthorityId, and tenantId.',
        notes: 'Only a SHA-256 hash of a token is stored, so token is always null here — the value is returned exactly once, by the call that created it. CMP rows additionally expose lastFourOfToken and cmpReferenceValue so an operator can identify a credential.',
    },
    {
        method: 'POST',
        path: '/api/v1/admin/enrollment-tokens',
        summary: 'Generate a new enrollment token for protocol enrollment (EST, SCEP, ACME, etc.).',
        auth: 'Authorize (CaOperator)',
        category: 'Admin Enrollment Tokens',
        requestBody: [
            { name: 'expiresInHours', type: 'number', required: false, description: 'Token lifetime in hours (default: 24)' },
            { name: 'maxUses', type: 'int', required: false, description: 'Maximum number of uses (default: 1)' },
            { name: 'subjectRestriction', type: 'string', required: false, description: 'Optional subject DN restriction pattern' },
            { name: 'sanRestriction', type: 'string', required: false, description: 'Optional SAN restriction pattern' },
            { name: 'protocol', type: 'string', required: false, description: 'Protocol this token is for (e.g., EST, SCEP, ACME)' },
            { name: 'requestProfileId', type: 'guid', required: false, description: 'Pre-selected request profile' },
            { name: 'certProfileId', type: 'guid', required: false, description: 'Pre-selected certificate profile' },
            { name: 'signingProfileId', type: 'guid', required: false, description: 'Pre-selected signing profile' },
        ],
        headers: [
            { name: 'Authorization', type: 'Bearer token', required: true, description: 'JWT access token from /api/v1/auth/login' },
        ],
        responseDescription: 'Object with token (plaintext) and expiresIn (hours).',
        notes: 'Enforces tenant isolation via the selected profiles. System-wide tokens require SystemOperator/SystemAdmin.',
    },
    {
        method: 'POST',
        path: '/api/v1/admin/enrollment-tokens/cmp-secret',
        summary: 'Provision a CMP PBMAC shared-secret credential bound to a specific senderKID (referenceValue). The plaintext secret is returned exactly once.',
        auth: 'Authorize (CaOperator)',
        category: 'Admin Enrollment Tokens',
        requestBody: [
            { name: 'referenceValue', type: 'string', required: true, description: 'The CMP senderKID / referenceValue the client will present' },
            { name: 'expiresInHours', type: 'number', required: false, description: 'Secret lifetime in hours (default: 720 / 30 days)' },
            { name: 'maxUses', type: 'int', required: false, description: 'Maximum number of uses (default: 0 = unlimited)' },
            { name: 'signingProfileId', type: 'guid', required: false, description: 'Signing profile used to resolve the target CA for tenant enforcement' },
        ],
        headers: [
            { name: 'Authorization', type: 'Bearer token', required: true, description: 'JWT access token from /api/v1/auth/login' },
        ],
        responseDescription: 'Object with id, cmpReferenceValue, sharedSecret (plaintext, shown once), expiresAt, maxUses, and a warning to record the secret.',
        notes: 'The plaintext secret is returned exactly once and never stored in the clear. Subsequent admin views show only the last 4 digits. Returns 409 if the referenceValue already exists.',
    },
    {
        method: 'DELETE',
        path: '/api/v1/admin/enrollment-tokens/{id}',
        summary: 'Revoke an enrollment token.',
        auth: 'Authorize (CaOperator)',
        category: 'Admin Enrollment Tokens',
        headers: [
            { name: 'Authorization', type: 'Bearer token', required: true, description: 'JWT access token from /api/v1/auth/login' },
        ],
        responseDescription: 'Confirmation that the token was revoked.',
        notes: 'Enforces tenant isolation; non-system-admins can only revoke tokens belonging to their accessible tenants.',
    },
];
