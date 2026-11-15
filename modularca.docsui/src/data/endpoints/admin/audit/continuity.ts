import type { ApiEndpoint } from '../../types';

export const adminContinuity: ApiEndpoint[] = [
    {
        method: 'GET',
        path: '/api/v1/admin/continuity/notice',
        summary: 'The standing notice that this instance runs from an earlier or copied state: a snapshot rollback, a restore, a clone or a move the product was not told about.',
        auth: 'Authorize (SystemAuditor)',
        category: 'Admin Continuity',
        headers: [
            { name: 'Authorization', type: 'Bearer token', required: true, description: 'JWT access token from /api/v1/auth/login' },
        ],
        responseDescription: 'applies (true while any event is unacknowledged), events (each with id, kind, detectedAt, oldTag, newTag, edgeOfMemoryUtc, auditNewestUtc, crlNumberFloor, crlCountersRaised and message), and incarnation (the source and short tag the database holds, when it was stored and by what; never the value).',
        notes: 'An event has one of three kinds. IncarnationChanged: the incarnation the machine reports at start (the environment variable MODULARCA__INSTANCE__INCARNATION, set by whatever restores or promotes the instance) differs from the one the database last saw. PublishedCrlAhead: a CRL this instance published to an LDAP directory carries a higher number than the database knows. For both, every CRL number counter was raised so no published number is used again, and edgeOfMemoryUtc is the newest certificate, request or revocation the database holds: certificates issued and revocations made after it on the earlier timeline are not known here. Nothing is replayed, because there is no signer journal in this version; record what is found with the revoked-serials and adopted-certificates endpoints. IncarnationSourceLost: the machine stopped reporting an incarnation; nothing was raised. auditNewestUtc is the newest row of the audit trail, which is a separate database: when it is later than edgeOfMemoryUtc the audit trail was not taken back, and it lists what the lost time did. The same events are in /health/ready under checks.continuity, which stays healthy.',
    },
    {
        method: 'GET',
        path: '/api/v1/admin/continuity/events',
        summary: 'Every continuity event, acknowledged or not, newest first.',
        auth: 'Authorize (SystemAuditor)',
        category: 'Admin Continuity',
        queryParams: [
            { name: 'limit', type: 'int', required: false, description: 'How many to return (default 100, at most 500)' },
        ],
        headers: [
            { name: 'Authorization', type: 'Bearer token', required: true, description: 'JWT access token from /api/v1/auth/login' },
        ],
        responseDescription: 'An array of events as in the notice, each also with acknowledgedAt and acknowledgedBy.',
    },
    {
        method: 'POST',
        path: '/api/v1/admin/continuity/events/{id}/acknowledge',
        summary: 'Acknowledge a continuity event, which takes it out of the notice in the console and in /health/ready. Requires step-up MFA.',
        auth: 'Authorize (SystemAdmin)',
        category: 'Admin Continuity',
        headers: [
            { name: 'Authorization', type: 'Bearer token', required: true, description: 'JWT access token from /api/v1/auth/login' },
            { name: 'X-MFA-Token', type: 'string', required: true, description: 'Step-up MFA token (operation: acknowledge-continuity-event, target: the event id)' },
        ],
        responseDescription: 'The event, with acknowledgedAt and acknowledgedBy.',
        notes: 'Acknowledging records that an administrator has read the notice. It changes nothing else: the CRL numbers stay raised and the event stays in the list. 404 for an event that does not exist; an event already acknowledged is returned as it is. Audited as InstanceContinuityAcknowledged.',
    },
];
