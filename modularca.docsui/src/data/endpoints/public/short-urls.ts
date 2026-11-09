import type { ApiEndpoint } from '../types';

export const publicShortUrls: ApiEndpoint[] = [
    {
        method: 'GET',
        path: '/ca/{serial}',
        summary: 'Short URL: download a CA certificate by serial.',
        auth: 'Anonymous',
        category: 'Public Short URLs',
        responseDescription: 'CA certificate file.',
    },
    {
        method: 'GET',
        path: '/crl/{serial}',
        summary: 'Short URL: download a CRL by CA serial.',
        auth: 'Anonymous',
        category: 'Public Short URLs',
        responseDescription: 'CRL file.',
    },
    {
        method: 'GET',
        path: '/crl/{serial}/delta',
        summary: 'Short URL: download a delta CRL by CA serial.',
        auth: 'Anonymous',
        category: 'Public Short URLs',
        responseDescription: 'Delta CRL file.',
    },
    {
        method: 'POST',
        path: '/ocsp',
        summary: 'Short URL: submit an OCSP request (POST).',
        auth: 'Anonymous',
        category: 'Public Short URLs',
        responseDescription: 'OCSP response.',
        notes: 'Switching OCSP off answers 503 here as on /ocsp/... and /api/v1/public/ocsp. A delegated responder certificate is used only if the CA signed it, carries the OCSP signing usage and is within its dates.',
    },
    {
        method: 'GET',
        path: '/ocsp/{encodedRequest}',
        summary: 'Short URL: submit an OCSP request (GET).',
        auth: 'Anonymous',
        category: 'Public Short URLs',
        responseDescription: 'OCSP response.',
    },
    {
        method: 'POST',
        path: '/tsa',
        summary: 'Short URL: submit a TSA request.',
        auth: 'Anonymous',
        category: 'Public Short URLs',
        responseDescription: 'TSA response.',
        notes: 'The message imprint must be SHA-256, SHA-384 or SHA-512; from 0.4.3 a SHA-1 imprint is answered with status rejection and failInfo badAlg. Tokens name the policy in Tsa.PolicyOid (default 1.3.6.1.4.1.66874.1.5.1 from 0.4.3, 1.2.3.4.1 before), and a reqPolicy naming another is refused with failInfo unacceptedPolicy.',
    },
];
