import type { ApiEndpoint } from '../../types';

export const adminAudit: ApiEndpoint[] = [
    {
        method: 'GET',
        path: '/api/v1/admin/audit',
        summary: 'Query audit log entries with filtering and pagination.',
        auth: 'Authorize (SystemAuditor)',
        category: 'Admin Audit',
        queryParams: [
            { name: 'from', type: 'datetime', required: false, description: 'Earliest timestamp to include' },
            { name: 'to', type: 'datetime', required: false, description: 'Latest timestamp to include' },
            { name: 'actionType', type: 'string', required: false, description: 'Action type; pre-0.4.0 names of the same action match too' },
            { name: 'actorUsername', type: 'string', required: false, description: 'Exact actor username' },
            { name: 'caId', type: 'guid', required: false, description: 'Records about one CA' },
            { name: 'spaceId', type: 'guid', required: false, description: 'Records about one space: its CAs, the space itself and its groups, or records stamped with it before 0.4.0. Replaces tenantId, which is refused with 400' },
            { name: 'targetEntityType', type: 'string', required: false, description: 'Target type of one entity\'s activity' },
            { name: 'targetEntityId', type: 'string', required: false, description: 'Target id of one entity\'s activity' },
            { name: 'sort', type: 'string', required: false, description: 'Sort column and direction' },
            { name: 'page', type: 'int', required: false, description: 'Page number (default 1)' },
            { name: 'pageSize', type: 'int', required: false, description: 'Page size (default 50)' },
        ],
        headers: [
            { name: 'Authorization', type: 'Bearer token', required: true, description: 'JWT access token from /api/v1/auth/login' },
        ],
        responseDescription: 'Paginated array of audit log entries.',
        notes: 'A caller with audit.view on some CAs only sees the records of those CAs.',
    },
    {
        method: 'GET',
        path: '/api/v1/admin/audit/verify',
        summary: 'Verify one audit hash chain: the instance chain, or a retired per-space chain named by chainId, whose sealed tail is also checked against the instance chain\'s succession record.',
        auth: 'Authorize (SystemAdmin)',
        category: 'Admin Audit',
        queryParams: [
            { name: 'chainId', type: 'guid', required: false, description: 'A retired chain, keyed by the id its space had; omit for the instance chain. Replaces tenantId, which is refused with 400' },
            { name: 'limit', type: 'int', required: false, description: 'Most records to examine (default 10000, at most 100000)' },
        ],
        headers: [
            { name: 'Authorization', type: 'Bearer token', required: true, description: 'JWT access token from /api/v1/auth/login' },
        ],
        responseDescription: 'The chain\'s report: chain ("instance" or "retired"), chainId, spaceName, sealed, tailState, tailIssue, recordsVerified, unverifiableRecords, totalRecords, truncated, recordsNotExamined, epochs, pruned, breakCount, breaks and integrity ("Valid", "PartiallyVerifiable", "PartiallyChecked" or "TAMPERED").',
        notes: 'A run that stops at limit before the end of the chain reports PartiallyChecked, never Valid.',
    },
    {
        method: 'GET',
        path: '/api/v1/admin/audit/verify/chains',
        summary: 'Verify every audit chain: the live instance chain, then each per-space chain retired and sealed in 0.4.0, with the state of its sealed tail.',
        auth: 'Authorize (SystemAdmin)',
        category: 'Admin Audit',
        queryParams: [
            { name: 'limit', type: 'int', required: false, description: 'Most records to examine per chain (default 10000)' },
        ],
        headers: [
            { name: 'Authorization', type: 'Bearer token', required: true, description: 'JWT access token from /api/v1/auth/login' },
        ],
        responseDescription: 'Array of chain reports, the instance chain first, each shaped as GET /api/v1/admin/audit/verify returns.',
        notes: 'A retired chain is listed when it has records or the instance chain\'s succession record names it, so a chain deleted outright still reports, as broken.',
    },
    {
        method: 'GET',
        path: '/api/v1/admin/audit/{id}',
        summary: 'Get a specific audit log entry by ID.',
        auth: 'Authorize (SystemAuditor)',
        category: 'Admin Audit',
        headers: [
            { name: 'Authorization', type: 'Bearer token', required: true, description: 'JWT access token from /api/v1/auth/login' },
        ],
        responseDescription: 'Audit log entry details.',
    },
    {
        method: 'GET',
        path: '/api/v1/admin/audit/est',
        summary: 'Query EST protocol audit logs.',
        auth: 'Authorize (SystemAuditor)',
        category: 'Admin Audit',
        headers: [
            { name: 'Authorization', type: 'Bearer token', required: true, description: 'JWT access token from /api/v1/auth/login' },
        ],
        responseDescription: 'EST audit entries.',
    },
    {
        method: 'GET',
        path: '/api/v1/admin/audit/scep',
        summary: 'Query SCEP protocol audit logs.',
        auth: 'Authorize (SystemAuditor)',
        category: 'Admin Audit',
        headers: [
            { name: 'Authorization', type: 'Bearer token', required: true, description: 'JWT access token from /api/v1/auth/login' },
        ],
        responseDescription: 'SCEP audit entries.',
    },
    {
        method: 'GET',
        path: '/api/v1/admin/audit/cmp',
        summary: 'Query CMP protocol audit logs.',
        auth: 'Authorize (SystemAuditor)',
        category: 'Admin Audit',
        headers: [
            { name: 'Authorization', type: 'Bearer token', required: true, description: 'JWT access token from /api/v1/auth/login' },
        ],
        responseDescription: 'CMP audit entries.',
    },
    {
        method: 'GET',
        path: '/api/v1/admin/audit/acme',
        summary: 'Query ACME protocol audit logs.',
        auth: 'Authorize (SystemAuditor)',
        category: 'Admin Audit',
        headers: [
            { name: 'Authorization', type: 'Bearer token', required: true, description: 'JWT access token from /api/v1/auth/login' },
        ],
        responseDescription: 'ACME audit entries.',
    },
    {
        method: 'GET',
        path: '/api/v1/admin/audit/network',
        summary: 'Query network-level audit logs.',
        auth: 'Authorize (SystemAuditor)',
        category: 'Admin Audit',
        headers: [
            { name: 'Authorization', type: 'Bearer token', required: true, description: 'JWT access token from /api/v1/auth/login' },
        ],
        responseDescription: 'Network audit entries.',
    },
];
