import type { ApiEndpoint } from '../types';

export const userCaCertificates: ApiEndpoint[] = [
    {
        method: 'GET',
        path: '/api/v1/user/authorities',
        summary: 'List all CA certificates available to the authenticated user.',
        auth: 'Authorize (CaUser)',
        category: 'User CA Certificates',
        headers: [
            { name: 'Authorization', type: 'Bearer token', required: true, description: 'JWT access token from /api/v1/auth/login' },
        ],
        responseDescription: 'Array of CA certificate info models.',
    },
    {
        method: 'GET',
        path: '/api/v1/user/authorities/{serial}',
        summary: 'Get detailed CA certificate information by serial number.',
        auth: 'Authorize (CaUser)',
        category: 'User CA Certificates',
        headers: [
            { name: 'Authorization', type: 'Bearer token', required: true, description: 'JWT access token from /api/v1/auth/login' },
        ],
        responseDescription: 'Full CA certificate info.',
        notes: 'Serves CA certificates only. 404 for a certificate that is not a CA certificate, for the System Signing CA, and for a CA outside the spaces of the caller; a caller with certificate-request rights instance-wide sees every CA certificate.',
    },
    {
        method: 'GET',
        path: '/api/v1/user/authorities/{serial}/file',
        summary: 'Download a CA certificate file in PEM or DER format.',
        auth: 'Authorize (CaUser)',
        category: 'User CA Certificates',
        headers: [
            { name: 'Authorization', type: 'Bearer token', required: true, description: 'JWT access token from /api/v1/auth/login' },
            { name: 'Accept', type: 'string', required: true, description: 'application/x-pem-file (or any type naming pem) for PEM; application/pkix-cert, application/x-x509-ca-cert or application/octet-stream for DER. Any other value gets 404.' },
        ],
        responseDescription: 'CA certificate file download.',
        notes: 'Serves the same certificates as GET /api/v1/user/authorities/{serial}: CA certificates only, and only those of CAs the caller can see. A leaf certificate, the System Signing CA and a CA of another space all get 404.',
    },
    {
        method: 'GET',
        path: '/api/v1/user/authorities/{serial}/chain',
        summary: 'Download the full trust chain for a CA certificate.',
        auth: 'Authorize (CaUser)',
        category: 'User CA Certificates',
        headers: [
            { name: 'Authorization', type: 'Bearer token', required: true, description: 'JWT access token from /api/v1/auth/login' },
        ],
        responseDescription: 'PEM bundle file with the CA certificate and its issuer chain.',
    },
    {
        method: 'GET',
        path: '/api/v1/user/authorities/{serial}/crl',
        summary: 'Download the CRL for a specific CA by certificate serial number.',
        auth: 'Authorize (CaUser)',
        category: 'User CA Certificates',
        headers: [
            { name: 'Authorization', type: 'Bearer token', required: true, description: 'JWT access token from /api/v1/auth/login' },
        ],
        responseDescription: 'CRL file download in DER format.',
    },
];
