import type { ApiEndpoint } from '../types';

export const scep: ApiEndpoint[] = [
    {
        method: 'GET',
        path: '/api/v1/scep/{caLabel}',
        summary: 'SCEP GET handler for GetCACaps, GetCACert, and GetNextCACert operations.',
        auth: 'Anonymous',
        category: 'SCEP',
        responseDescription: 'Depends on operation: capabilities, CA cert, or next CA cert.',
        notes: 'SCEP needs a CA whose key is RSA. On any other CA, GetCACaps, GetCACert and PKIOperation answer 409 { error, reason: "ScepRequiresRsaKey" }, with the reason in error; where SCEP is enabled on that CA they also write an unsuccessful SCEP audit entry that says why. GetCACaps is answered for the addressed CA: 400 for an unknown CA or one with SCEP switched off.',
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
