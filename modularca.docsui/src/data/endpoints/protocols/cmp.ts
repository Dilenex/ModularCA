import type { ApiEndpoint } from '../types';

export const cmp: ApiEndpoint[] = [
    {
        method: 'POST',
        path: '/api/v1/cmp/{caLabel}',
        summary: 'CMP POST handler for certificate management operations (RFC 4210).',
        auth: 'CMP Auth',
        category: 'CMP',
        responseDescription: 'CMP response message.',
        notes: 'Every message must be protected, by a signature or by a password-based MAC (PBMAC) over a shared secret issued for this CA. From 0.4.3 PBMAC is accepted only with SHA-224, SHA-256, SHA-384 or SHA-512 as the one-way function, HMAC with SHA-1 or SHA-2 as the MAC, and 1 to 10,000 iterations; anything else is answered with failInfo badAlg. openssl cmp -secret sends SHA-256, HMAC-SHA1 and 500 iterations, which is accepted. On a CA set to require signature protection, PBMAC is refused (badMessageCheck) before the shared secret is looked up. A revocation (rr) the caller may not make is refused with failInfo notAuthorized (bit 23). Every error answer is recorded on the CMP tab of the audit log as an Error row naming the request type and the failInfo.',
    },
];
