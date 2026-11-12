import type { ApiEndpoint } from '../types';

export const userSigningProfiles: ApiEndpoint[] = [
    {
        method: 'GET',
        path: '/api/v1/user/signing-profiles',
        summary: 'List the signing profiles the caller can submit a certificate request against: those of the CAs they hold cert.request on.',
        auth: 'Authorize (CaUser)',
        category: 'User Signing Profiles',
        headers: [
            { name: 'Authorization', type: 'Bearer token', required: true, description: 'JWT access token from /api/v1/auth/login' },
        ],
        responseDescription: 'Array of signing profiles with ID, name, description, and default status, each with the CA it issues from: caId, caName and caSpaceId.',
        notes: 'caId is the CA\'s own id (not its certificate\'s), caName its name and caSpaceId its space, null for an instance CA. All three are null for a signing profile with no issuer, which is listed only at system scope. The request form builds its CA picker from these fields and offers the signing profiles of the chosen CA.',
    },
];
