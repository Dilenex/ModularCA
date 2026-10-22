import type { ApiEndpoint } from '../../types';

export const adminCsr: ApiEndpoint[] = [
    {
        method: 'GET',
        path: '/api/v1/admin/requests',
        summary: 'List all pending certificate signing requests, filtered by accessible CAs for non-system-admins.',
        auth: 'Authorize (CaAuditor)',
        category: 'Admin CSR',
        headers: [
            { name: 'Authorization', type: 'Bearer token', required: true, description: 'JWT access token from /api/v1/auth/login' },
        ],
        responseDescription: 'Array of CSR requests with subject, status, and submission date.',
    },
    {
        method: 'POST',
        path: '/api/v1/admin/requests',
        summary: 'Generate a new certificate signing request from the provided parameters.',
        auth: 'Authorize (CaAuditor)',
        category: 'Admin CSR',
        headers: [
            { name: 'Authorization', type: 'Bearer token', required: true, description: 'JWT access token from /api/v1/auth/login' },
        ],
        responseDescription: 'Object with csrId (GUID) and csr (PEM-encoded CSR string).',
    },
    {
        method: 'POST',
        path: '/api/v1/admin/requests/parse-csr',
        summary: 'Parse a PEM-encoded CSR and return structured data including subject DN, SANs, key info, extensions, and signature validation. Read-only, does not store anything.',
        auth: 'Authorize (CaAuditor)',
        category: 'Admin CSR',
        requestBody: [
            { name: 'pem', type: 'string', required: true, description: 'PEM-encoded CSR string to parse' },
        ],
        headers: [
            { name: 'Authorization', type: 'Bearer token', required: true, description: 'JWT access token from /api/v1/auth/login' },
        ],
        responseDescription: 'Parsed CSR details including subject DN components, SANs, key algorithm, requested extensions, and signature validation status.',
    },
    {
        method: 'POST',
        path: '/api/v1/admin/requests/validate-against-profile',
        summary: 'Validate parsed CSR subject and SAN fields against a request profile SubjectDnRules and SanRules. Returns per-field validation results without storing anything.',
        auth: 'Authorize (CaAuditor)',
        category: 'Admin CSR',
        requestBody: [
            { name: 'requestProfileId', type: 'guid', required: true, description: 'Request profile ID to validate against' },
            { name: 'subject', type: 'object', required: true, description: 'Dictionary of subject DN field name to value (e.g., { "CN": "example.com", "O": "Acme" })' },
            { name: 'sans', type: 'array', required: true, description: 'Array of SAN entries, each with type (e.g., DNS, IP, Email) and value' },
        ],
        headers: [
            { name: 'Authorization', type: 'Bearer token', required: true, description: 'JWT access token from /api/v1/auth/login' },
        ],
        responseDescription: 'Object with valid (bool), fieldResults (array of per-field status/message), and sanResults (array of per-SAN status/message).',
    },
    {
        method: 'POST',
        path: '/api/v1/admin/requests/upload',
        summary: 'Upload an externally-generated PEM-encoded CSR for processing, with optional subject and SAN overrides.',
        auth: 'Authorize (CaAuditor)',
        category: 'Admin CSR',
        requestBody: [
            { name: 'pem', type: 'string', required: true, description: 'PEM-encoded CSR' },
            { name: 'certificateProfileId', type: 'guid', required: true, description: 'Certificate profile to apply' },
            { name: 'signingProfileId', type: 'guid', required: true, description: 'Signing profile to use' },
            { name: 'subjectOverrides', type: 'object', required: false, description: 'Optional subject DN overrides that replace the CSR original values during issuance' },
            { name: 'sanOverrides', type: 'array', required: false, description: 'Optional SAN overrides that replace the CSR original values during issuance' },
        ],
        headers: [
            { name: 'Authorization', type: 'Bearer token', required: true, description: 'JWT access token from /api/v1/auth/login' },
        ],
        responseDescription: 'Success confirmation.',
    },
    {
        method: 'POST',
        path: '/api/v1/admin/requests/{id}/approve',
        summary: 'Record an approval for a pending CSR. When the required approval count is met, the CSR transitions to Approved.',
        auth: 'Authorize (CaOperator)',
        category: 'Admin CSR',
        requestBody: [
            { name: 'comment', type: 'string', required: false, description: 'Optional comment explaining the approval decision' },
        ],
        headers: [
            { name: 'Authorization', type: 'Bearer token', required: true, description: 'JWT access token from /api/v1/auth/login' },
            { name: 'X-MFA-Token', type: 'string', required: false, description: 'Step-up MFA token from /api/v1/auth/mfa/verify-stepup for approve-request, issued for the request id. Required for this operation.' },
        ],
        responseDescription: 'Approval status including message, status (Approved or PartiallyApproved), approvalCount, requiredCount, and selfApproved.',
        notes: 'Prevents self-approval of own requests unless the caller is a system-super and AllowSystemSuperSelfApproval is on; such a self-approval completes the request whatever its count, and is audited as SelfApproved. Prevents duplicate approvals. Enforces profile.use capability and space isolation.',
    },
    {
        method: 'GET',
        path: '/api/v1/admin/requests/{id}/approvals',
        summary: 'Returns all approval records for a given certificate signing request.',
        auth: 'Authorize (CaAuditor)',
        category: 'Admin CSR',
        headers: [
            { name: 'Authorization', type: 'Bearer token', required: true, description: 'JWT access token from /api/v1/auth/login' },
        ],
        responseDescription: 'Array of approval records with id, approverId, approverUsername, decision, comment, and timestamp.',
        notes: 'Enforces space isolation via the CSR signing profile.',
    },
    {
        method: 'GET',
        path: '/api/v1/admin/requests/{id}/approval-outlook',
        summary: 'How the request’s approval stands, and whether the people who can approve it are enough to complete it.',
        auth: 'Authorize (CaAuditor)',
        category: 'Admin CSR',
        headers: [
            { name: 'Authorization', type: 'Bearer token', required: true, description: 'JWT access token from /api/v1/auth/login' },
        ],
        responseDescription: 'requiredCount, approvalCount, othersWhoCanApprove (active accounts other than the requester with cert.revoke on the CA and profile.use on its profiles, that have not approved yet), requesterMaySelfApprove, canComplete, and selfApproved.',
        notes: 'Enforces space isolation via the CSR signing profile.',
    },
    {
        method: 'GET',
        path: '/api/v1/admin/requests/approval-outlook',
        summary: 'How a request the caller is about to make would be approved, so a request nobody could approve is known before it is made.',
        auth: 'Authorize, plus cert.revoke on the signing profile’s CA',
        category: 'Admin CSR',
        queryParams: [
            { name: 'requestProfileId', type: 'guid', required: true, description: 'The request profile the request would be made under' },
            { name: 'signingProfileId', type: 'guid', required: true, description: 'The signing profile it would name' },
            { name: 'certProfileId', type: 'guid', required: false, description: 'The certificate profile it would name' },
        ],
        headers: [
            { name: 'Authorization', type: 'Bearer token', required: true, description: 'JWT access token from /api/v1/auth/login' },
        ],
        responseDescription: 'requiresApproval, requiredCount, othersWhoCanApprove, requesterMaySelfApprove (the caller), and canComplete.',
    },
    {
        method: 'POST',
        path: '/api/v1/admin/requests/{id}/reject',
        summary: 'Reject a pending certificate signing request with a reason.',
        auth: 'Authorize (CaOperator)',
        category: 'Admin CSR',
        requestBody: [
            { name: 'reason', type: 'string', required: false, description: 'Reason for the rejection (defaults to Unspecified)' },
        ],
        headers: [
            { name: 'Authorization', type: 'Bearer token', required: true, description: 'JWT access token from /api/v1/auth/login' },
            { name: 'X-MFA-Token', type: 'string', required: false, description: 'Step-up MFA token from /api/v1/auth/mfa/verify-stepup for reject-request, issued for the request id. Required for this operation.' },
        ],
        responseDescription: 'Object with message, id, and reason.',
        notes: 'Only Pending requests can be rejected. Enforces space isolation.',
    },
    {
        method: 'POST',
        path: '/api/v1/admin/requests/{id}/cancel',
        summary: 'Cancel an approved (but not yet issued) or pending certificate signing request.',
        auth: 'Authorize (CaOperator)',
        category: 'Admin CSR',
        requestBody: [
            { name: 'reason', type: 'string', required: true, description: 'Reason for cancellation' },
        ],
        headers: [
            { name: 'Authorization', type: 'Bearer token', required: true, description: 'JWT access token from /api/v1/auth/login' },
        ],
        responseDescription: 'Object with message, id, and reason.',
        notes: 'Only Pending or Approved requests that have not yet been issued can be cancelled. Enforces space isolation.',
    },
];
