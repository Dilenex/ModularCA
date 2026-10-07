import type { ApiEndpoint } from '../../types';

export const adminIssuance: ApiEndpoint[] = [
    {
        method: 'POST',
        path: '/api/v1/admin/certificates/issue',
        summary: 'Issue a certificate from a CSR (PEM). Server-side key generation not included.',
        auth: 'Authorize (CaOperator)',
        category: 'Admin Issuance',
        headers: [
            { name: 'Authorization', type: 'Bearer token', required: true, description: 'JWT access token from /api/v1/auth/login' },
        ],
        responseDescription: 'Issued certificate details.',
    },
    {
        method: 'POST',
        path: '/api/v1/admin/certificates/issue-with-key',
        summary: 'Issue a certificate with server-side key generation. Returns cert + encrypted private key.',
        auth: 'Authorize (CaOperator)',
        category: 'Admin Issuance',
        headers: [
            { name: 'Authorization', type: 'Bearer token', required: true, description: 'JWT access token from /api/v1/auth/login' },
        ],
        responseDescription: 'Issued certificate with encrypted private key.',
    },
    {
        method: 'POST',
        path: '/api/v1/admin/certificates/{certId}/reissue',
        summary: 'Reissue a certificate by its certificate entity ID.',
        auth: 'Authorize (CaOperator)',
        category: 'Admin Issuance',
        headers: [
            { name: 'Authorization', type: 'Bearer token', required: true, description: 'JWT access token from /api/v1/auth/login' },
        ],
        responseDescription: 'Reissued certificate details.',
        notes: 'newSans: absent or null keeps the current SANs; an empty array removes them all. Removing every SAN is refused with 400 (MCA-REQ-004) for a TLS server certificate (serverAuth EKU) or a certificate with an empty subject, before the predecessor is revoked.',
    },
    {
        method: 'POST',
        path: '/api/v1/admin/certificates/serial/{serial}/reissue',
        summary: 'Reissue a certificate by its serial number.',
        auth: 'Authorize (CaOperator)',
        category: 'Admin Issuance',
        headers: [
            { name: 'Authorization', type: 'Bearer token', required: true, description: 'JWT access token from /api/v1/auth/login' },
        ],
        responseDescription: 'Reissued certificate details.',
        notes: 'newSans: absent or null keeps the current SANs; an empty array removes them all. Removing every SAN is refused with 400 (MCA-REQ-004) for a TLS server certificate (serverAuth EKU) or a certificate with an empty subject, before the predecessor is revoked.',
    },
    {
        method: 'POST',
        path: '/api/v1/admin/certificates/csr/{csrId}/reissue',
        summary: 'Reissue a certificate from an existing CSR request.',
        auth: 'Authorize (CaOperator)',
        category: 'Admin Issuance',
        headers: [
            { name: 'Authorization', type: 'Bearer token', required: true, description: 'JWT access token from /api/v1/auth/login' },
        ],
        responseDescription: 'Reissued certificate details.',
        notes: 'newSans: absent or null keeps the current SANs; an empty array removes them all. Removing every SAN is refused with 400 (MCA-REQ-004) for a TLS server certificate (serverAuth EKU) or a certificate with an empty subject, before the predecessor is revoked.',
    },
];
