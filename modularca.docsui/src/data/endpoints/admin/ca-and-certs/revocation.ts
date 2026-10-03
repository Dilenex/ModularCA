import type { ApiEndpoint } from '../../types';

export const adminRevocation: ApiEndpoint[] = [
    {
        method: 'POST',
        path: '/api/v1/admin/certificates/{certId}/revoke',
        summary: 'Revoke a certificate by its entity ID. Requires step-up MFA. CA certificate revocation may trigger a key ceremony.',
        auth: 'Authorize (CaOperator)',
        category: 'Admin Revocation',
        requestBody: [
            { name: 'certificateId', type: 'guid', required: true, description: 'The certificate entity ID to revoke' },
            { name: 'reason', type: 'RevocationReason', required: true, description: 'Revocation reason (e.g., Unspecified, KeyCompromise, CaCompromise, AffiliationChanged, Superseded, CessationOfOperation)' },
            { name: 'invalidityDate', type: 'datetime', required: false, description: 'Optional date when the key was known or suspected to be compromised' },
        ],
        headers: [
            { name: 'Authorization', type: 'Bearer token', required: true, description: 'JWT access token from /api/v1/auth/login' },
            { name: 'X-MFA-Token', type: 'string', required: true, description: 'Step-up MFA token (operation: RevokeCert or RevokeCa)' },
        ],
        responseDescription: 'Revocation details including certificateId, serialNumber, newStatus, reason, crlNumber, and effectiveAt. CA cert revocation may return ceremonyId when key ceremony is required.',
        notes: 'KC-06: CA certificate revocation is ceremony-gated when the space RequireKeyCeremony flag is set. Enforces space isolation.',
    },
    {
        method: 'POST',
        path: '/api/v1/admin/certificates/serial/{serial}/revoke',
        summary: 'Revoke a certificate by serial number. Requires step-up MFA. CA certificate revocation may trigger a key ceremony.',
        auth: 'Authorize (CaOperator)',
        category: 'Admin Revocation',
        requestBody: [
            { name: 'serialNumber', type: 'string', required: true, description: 'The certificate serial number to revoke' },
            { name: 'reason', type: 'RevocationReason', required: true, description: 'Revocation reason (e.g., Unspecified, KeyCompromise, CaCompromise, AffiliationChanged, Superseded, CessationOfOperation)' },
            { name: 'invalidityDate', type: 'datetime', required: false, description: 'Optional date when the key was known or suspected to be compromised' },
        ],
        headers: [
            { name: 'Authorization', type: 'Bearer token', required: true, description: 'JWT access token from /api/v1/auth/login' },
            { name: 'X-MFA-Token', type: 'string', required: true, description: 'Step-up MFA token (operation: RevokeCert or RevokeCa)' },
        ],
        responseDescription: 'Revocation details including certificateId, serialNumber, newStatus, reason, crlNumber, and effectiveAt. CA cert revocation may return ceremonyId when key ceremony is required.',
        notes: 'KC-06: CA certificate revocation is ceremony-gated when the space RequireKeyCeremony flag is set. Enforces space isolation.',
    },
    {
        method: 'POST',
        path: '/api/v1/admin/certificates/{certId}/hold',
        summary: 'Place a certificate on hold (temporary revocation) by entity ID. Requires step-up MFA.',
        auth: 'Authorize (CaOperator)',
        category: 'Admin Revocation',
        requestBody: [
            { name: 'certificateId', type: 'guid', required: true, description: 'The certificate entity ID to place on hold' },
        ],
        headers: [
            { name: 'Authorization', type: 'Bearer token', required: true, description: 'JWT access token from /api/v1/auth/login' },
            { name: 'X-MFA-Token', type: 'string', required: true, description: 'Step-up MFA token (operation: HoldCert)' },
        ],
        responseDescription: 'Hold details including certificateId, serialNumber, newStatus, crlNumber, and effectiveAt.',
        notes: 'Enforces space isolation via the certificate signing profile linkage.',
    },
    {
        method: 'POST',
        path: '/api/v1/admin/certificates/serial/{serial}/hold',
        summary: 'Place a certificate on hold by serial number. Requires step-up MFA.',
        auth: 'Authorize (CaOperator)',
        category: 'Admin Revocation',
        requestBody: [
            { name: 'serialNumber', type: 'string', required: true, description: 'The certificate serial number to place on hold' },
        ],
        headers: [
            { name: 'Authorization', type: 'Bearer token', required: true, description: 'JWT access token from /api/v1/auth/login' },
            { name: 'X-MFA-Token', type: 'string', required: true, description: 'Step-up MFA token (operation: HoldCert)' },
        ],
        responseDescription: 'Hold details including certificateId, serialNumber, newStatus, crlNumber, and effectiveAt.',
        notes: 'Enforces space isolation via the certificate signing profile linkage.',
    },
    {
        method: 'POST',
        path: '/api/v1/admin/certificates/{certId}/unhold',
        summary: 'Release a certificate from hold (reinstate) by entity ID. Requires step-up MFA.',
        auth: 'Authorize (CaOperator)',
        category: 'Admin Revocation',
        requestBody: [
            { name: 'certificateId', type: 'guid', required: true, description: 'The certificate entity ID to release from hold' },
        ],
        headers: [
            { name: 'Authorization', type: 'Bearer token', required: true, description: 'JWT access token from /api/v1/auth/login' },
            { name: 'X-MFA-Token', type: 'string', required: true, description: 'Step-up MFA token (operation: UnholdCert)' },
        ],
        responseDescription: 'Reinstatement details including certificateId, serialNumber, newStatus, crlNumber, and effectiveAt.',
        notes: 'Enforces space isolation via the certificate signing profile linkage.',
    },
    {
        method: 'POST',
        path: '/api/v1/admin/certificates/serial/{serial}/unhold',
        summary: 'Release a certificate from hold (reinstate) by serial number. Requires step-up MFA.',
        auth: 'Authorize (CaOperator)',
        category: 'Admin Revocation',
        requestBody: [
            { name: 'serialNumber', type: 'string', required: true, description: 'The certificate serial number to release from hold' },
        ],
        headers: [
            { name: 'Authorization', type: 'Bearer token', required: true, description: 'JWT access token from /api/v1/auth/login' },
            { name: 'X-MFA-Token', type: 'string', required: true, description: 'Step-up MFA token (operation: UnholdCert)' },
        ],
        responseDescription: 'Reinstatement details including certificateId, serialNumber, newStatus, crlNumber, and effectiveAt.',
        notes: 'Enforces space isolation via the certificate signing profile linkage.',
    },
];
