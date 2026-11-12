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
        responseDescription: 'Revocation details including certificateId, serialNumber, newStatus, reason, previousReason (CertificateHold when a hold was made permanent, otherwise null), crlNumber, and effectiveAt. CA cert revocation may return ceremonyId when key ceremony is required.',
        notes: 'A certificate on hold is revoked permanently in place, without a release first (RFC 5280 5.3.1): the reason changes, the revocation date becomes now so the next delta CRL carries the change, and the hold date becomes the invalidity date unless invalidityDate is given. A permanently revoked certificate is refused with 409 (code MCA-RES-009), here and by the hold endpoints, as is a held certificate asked to be held again. KC-06: CA certificate revocation is ceremony-gated when the space RequireKeyCeremony flag is set. Enforces space isolation. When the ceremony could never reach its quorum, because too few accounts other than the caller can approve it, nothing is opened and the answer is 409 (code MCA-CFG-020 when nobody else can approve, MCA-CFG-021 when some can but too few); the key ceremony endpoints describe the body.',
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
        responseDescription: 'Revocation details including certificateId, serialNumber, newStatus, reason, previousReason (CertificateHold when a hold was made permanent, otherwise null), crlNumber, and effectiveAt. CA cert revocation may return ceremonyId when key ceremony is required.',
        notes: 'A certificate on hold is revoked permanently in place, without a release first (RFC 5280 5.3.1): the reason changes, the revocation date becomes now so the next delta CRL carries the change, and the hold date becomes the invalidity date unless invalidityDate is given. A permanently revoked certificate is refused with 409 (code MCA-RES-009), here and by the hold endpoints, as is a held certificate asked to be held again. KC-06: CA certificate revocation is ceremony-gated when the space RequireKeyCeremony flag is set. Enforces space isolation. A serial that matches certificates of more than one issuer is refused with 409 (code MCA-RES-010); retry by certificate ID. When the ceremony could never reach its quorum, because too few accounts other than the caller can approve it, nothing is opened and the answer is 409 (code MCA-CFG-020 when nobody else can approve, MCA-CFG-021 when some can but too few); the key ceremony endpoints describe the body.',
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
        notes: 'Enforces space isolation via the certificate signing profile linkage. A serial that matches certificates of more than one issuer is refused with 409 (code MCA-RES-010); retry by certificate ID.',
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
        notes: 'Enforces space isolation via the certificate signing profile linkage. A serial that matches certificates of more than one issuer is refused with 409 (code MCA-RES-010); retry by certificate ID.',
    },
];
