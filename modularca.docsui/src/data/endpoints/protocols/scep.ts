import type { ApiEndpoint } from '../types';

export const scep: ApiEndpoint[] = [
    {
        method: 'GET',
        path: '/api/v1/scep/{caLabel}',
        summary: 'SCEP GET handler for GetCACaps, GetCACert, and GetNextCACert operations.',
        auth: 'Anonymous',
        category: 'SCEP',
        responseDescription: 'Depends on operation: capabilities, CA cert, or next CA cert.',
        notes: 'SCEP needs a CA whose key is RSA. On any other CA, GetCACert and PKIOperation answer 409 { error, reason: "ScepRequiresRsaKey" }, with the reason in error, and write an unsuccessful SCEP audit entry that says why. GetCACaps is answered as before.',
    },
    {
        method: 'POST',
        path: '/api/v1/scep/{caLabel}',
        summary: 'SCEP POST handler for PKIOperation (certificate enrollment/renewal).',
        auth: 'SCEP Challenge',
        category: 'SCEP',
        responseDescription: 'SCEP response message.',
        notes: 'On a CA whose key is not RSA: 409 { error, reason: "ScepRequiresRsaKey" } and an unsuccessful SCEP audit entry (operation PKIOperation) that says why, before the message is read.',
    },
];
