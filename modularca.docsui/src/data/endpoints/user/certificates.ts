import type { ApiEndpoint } from '../types';

export const userCertificates: ApiEndpoint[] = [
    {
        method: 'GET',
        path: '/api/v1/user/certificates',
        summary: 'List the non-CA certificates the user has view access to. With ?mine=true, only the caller\'s own: those issued from a request the caller made, and those an access entry names the caller on.',
        auth: 'Authorize (CaUser)',
        category: 'User Certificates',
        headers: [
            { name: 'Authorization', type: 'Bearer token', required: true, description: 'JWT access token from /api/v1/auth/login' },
        ],
        responseDescription: 'Array of certificate info models with subject, serial, validity, and status.',
    },
    {
        method: 'GET',
        path: '/api/v1/user/certificates/{serial}',
        summary: 'Get detailed certificate information by serial number.',
        auth: 'Authorize (CaUser)',
        category: 'User Certificates',
        headers: [
            { name: 'Authorization', type: 'Bearer token', required: true, description: 'JWT access token from /api/v1/auth/login' },
        ],
        responseDescription: 'Full certificate info including subject, issuer, validity, SANs, key usage, and thumbprints.',
    },
    {
        method: 'GET',
        path: '/api/v1/user/certificates/{serial}/file',
        summary: 'Download a certificate file in PEM or DER format based on Accept header.',
        auth: 'Authorize (CaUser)',
        category: 'User Certificates',
        headers: [
            { name: 'Authorization', type: 'Bearer token', required: true, description: 'JWT access token from /api/v1/auth/login' },
            { name: 'Accept', type: 'string', required: false, description: 'Content type preference (e.g., application/x-pem-file or application/pkix-cert)' },
        ],
        responseDescription: 'Certificate file download (PEM or DER based on Accept header).',
    },
    {
        method: 'POST',
        path: '/api/v1/user/certificates/{serial}/export',
        summary: 'Export a certificate as PKCS#12 (PFX) with the private key. Requires Manage-level access and step-up MFA.',
        auth: 'Authorize (CaUser)',
        category: 'User Certificates',
        requestBody: [
            { name: 'password', type: 'string', required: true, description: 'Password to protect the exported PFX file' },
        ],
        headers: [
            { name: 'Authorization', type: 'Bearer token', required: true, description: 'JWT access token from /api/v1/auth/login' },
            { name: 'X-MFA-Token', type: 'string', required: false, description: 'Step-up MFA token from /api/v1/auth/mfa/verify-stepup. Required for this operation.' },
        ],
        responseDescription: 'PKCS#12 file download.',
    },
    {
        method: 'GET',
        path: '/api/v1/user/certificates/{serial}/chain',
        summary: 'Download the PEM trust chain for a certificate (leaf + intermediates, root excluded per RFC 8446).',
        auth: 'Authorize (CaUser)',
        category: 'User Certificates',
        headers: [
            { name: 'Authorization', type: 'Bearer token', required: true, description: 'JWT access token from /api/v1/auth/login' },
        ],
        responseDescription: 'PEM bundle file download containing the certificate and its issuer chain.',
    },
    {
        method: 'POST',
        path: '/api/v1/user/certificates/{serial}/renew',
        summary: 'Submit a renewal request for an existing certificate, pre-filled with the same subject and profiles.',
        auth: 'Authorize (CaUser)',
        category: 'User Certificates',
        headers: [
            { name: 'Authorization', type: 'Bearer token', required: true, description: 'JWT access token from /api/v1/auth/login' },
        ],
        responseDescription: 'Renewal request ID and confirmation message.',
    },
];
