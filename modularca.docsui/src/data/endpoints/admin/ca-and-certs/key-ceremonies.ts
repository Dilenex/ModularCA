import type { ApiEndpoint } from '../../types';

export const adminKeyCeremonies: ApiEndpoint[] = [
    {
        method: 'POST',
        path: '/api/v1/admin/ceremonies',
        summary: 'Initiate a key ceremony to create a root or intermediate CA. CA revocation, SSH CA, space policy and controlled-user ceremonies are opened by their own endpoints. Requires step-up MFA.',
        auth: 'Authorize (CaAdmin)',
        category: 'Admin Key Ceremonies',
        requestBody: [
            { name: 'operationType', type: 'string', required: true, description: 'Operation type: CreateRootCA or CreateIntermediateCA. Any other value returns 400' },
            { name: 'description', type: 'string', required: false, description: 'Human-readable description of the ceremony\'s purpose (max 1000 chars)' },
            { name: 'targetEntityId', type: 'string', required: false, description: 'Target entity ID (e.g., CA ID for revocation). Empty for new entity creation' },
            { name: 'parameters', type: 'KeyCeremonyParameters', required: true, description: 'Structured CA creation parameters. Locked at initiation and cannot be modified after. Approvers review these parameters. They name the CA\'s scope: spaceId, or scope "instance" for an instance CA; neither (or both) is refused with 400' },
        ],
        headers: [
            { name: 'Authorization', type: 'Bearer token', required: true, description: 'JWT access token from /api/v1/auth/login' },
            { name: 'X-MFA-Token', type: 'string', required: true, description: 'Step-up MFA token from /api/v1/auth/mfa/verify-stepup' },
        ],
        responseDescription: 'Created ceremony with ID, operationType, description, requiredApprovals, currentApprovals, status, createdAt, expiresAt. If quorum is 1, ceremony is auto-approved.',
        notes: 'Self-approval is forbidden. Parameters are locked at initiation time. Stale ceremonies auto-expire. Triggers a security alert.',
    },
    {
        method: 'GET',
        path: '/api/v1/admin/ceremonies',
        summary: 'List key ceremonies scoped by space. System admins see all; space-level CA admins see only their space ceremonies.',
        auth: 'Authorize (per-ceremony access check)',
        category: 'Admin Key Ceremonies',
        queryParams: [
            { name: 'status', type: 'string', required: false, description: 'Filter by status: Pending, Approved, Rejected, Executed, Cancelled, Expired' },
        ],
        headers: [
            { name: 'Authorization', type: 'Bearer token', required: true, description: 'JWT access token from /api/v1/auth/login' },
        ],
        responseDescription: 'Array of key ceremony records with ID, operationType, description, targetEntityId, initiatedBy, approvals, status, timestamps, canApprove for the caller, and approvalRefusal: why the caller may not approve a pending controlled-user ceremony, or null.',
        notes: 'Automatically expires stale ceremonies before listing. CA-scoped admins (without space-wide CaManage) cannot see ceremonies.',
    },
    {
        method: 'GET',
        path: '/api/v1/admin/ceremonies/{id}',
        summary: 'Get full detail for a single key ceremony, including approval records and locked parameters.',
        auth: 'Authorize (per-ceremony access check)',
        category: 'Admin Key Ceremonies',
        headers: [
            { name: 'Authorization', type: 'Bearer token', required: true, description: 'JWT access token from /api/v1/auth/login' },
        ],
        responseDescription: 'Full ceremony detail including parametersJson, approvalsJson, canApprove and approvalRefusal.',
        notes: 'Returns 403 if the caller does not have access to the ceremony\'s space.',
    },
    {
        method: 'POST',
        path: '/api/v1/admin/ceremonies/{id}/approve',
        summary: 'Approve a pending key ceremony. Self-approval is forbidden. When approvals reach quorum, status transitions to Approved. Requires step-up MFA.',
        auth: 'Authorize (per-ceremony access check)',
        category: 'Admin Key Ceremonies',
        headers: [
            { name: 'Authorization', type: 'Bearer token', required: true, description: 'JWT access token from /api/v1/auth/login' },
            { name: 'X-MFA-Token', type: 'string', required: true, description: 'Step-up MFA token from /api/v1/auth/mfa/verify-stepup' },
        ],
        responseDescription: 'Approval status with currentApprovals, requiredApprovals, and status. Message indicates if quorum is reached.',
        notes: 'The initiator cannot approve their own ceremony. Returns 403 for self-approval attempts. A controlled-user ceremony returns 403 with the reason when the caller holds no tier that covers it, or when it is a promotion and the caller, not being system-super, reset the password or MFA of an account it promotes in the 30 days before it was opened or since.',
    },
    {
        method: 'POST',
        path: '/api/v1/admin/ceremonies/{id}/reject',
        summary: 'Reject a pending key ceremony, immediately setting its status to Rejected. Requires step-up MFA.',
        auth: 'Authorize (per-ceremony access check)',
        category: 'Admin Key Ceremonies',
        headers: [
            { name: 'Authorization', type: 'Bearer token', required: true, description: 'JWT access token from /api/v1/auth/login' },
            { name: 'X-MFA-Token', type: 'string', required: true, description: 'Step-up MFA token from /api/v1/auth/mfa/verify-stepup' },
        ],
        responseDescription: 'Rejection confirmation with ceremony ID and status.',
    },
    {
        method: 'DELETE',
        path: '/api/v1/admin/ceremonies/{id}',
        summary: 'Cancel a pending key ceremony. Only the original initiator may cancel. Requires step-up MFA.',
        auth: 'Authorize (per-ceremony access check)',
        category: 'Admin Key Ceremonies',
        headers: [
            { name: 'Authorization', type: 'Bearer token', required: true, description: 'JWT access token from /api/v1/auth/login' },
            { name: 'X-MFA-Token', type: 'string', required: true, description: 'Step-up MFA token from /api/v1/auth/mfa/verify-stepup' },
        ],
        responseDescription: 'Cancellation confirmation with ceremony ID and status.',
        notes: 'Returns 403 if the caller is not the original initiator.',
    },
    {
        method: 'POST',
        path: '/api/v1/admin/ceremonies/{id}/execute',
        summary: 'Execute an approved key ceremony, triggering the actual CA/SSH CA creation or revocation. Only the initiator or an approver may execute. Requires step-up MFA.',
        auth: 'Authorize (per-ceremony access check)',
        category: 'Admin Key Ceremonies',
        headers: [
            { name: 'Authorization', type: 'Bearer token', required: true, description: 'JWT access token from /api/v1/auth/login' },
            { name: 'X-MFA-Token', type: 'string', required: true, description: 'Step-up MFA token from /api/v1/auth/mfa/verify-stepup' },
        ],
        responseDescription: 'Execution result varies by operation type. For CA creation: { id, status, newCa: { id, name, label, type } }. For SSH CA: { id, status, newSshCaKey }. For revocation: { id, status, certificateId, serialNumber, newStatus, reason, crlNumber }. For a controlled-user change: { id, status, message, result, temporaryPassword }, where temporaryPassword is set only for a password reset: generated now, returned in this response only, never stored or audited.',
        notes: 'Parameters are locked from initiation; the ceremony uses the parameters approved by the quorum. Supported operations: CreateRootCA, CreateIntermediateCA, CreateSshCa, DeleteSshCa, RevokeCa, ControlledUserChange. A controlled-user promotion is marked Expired and refused (409) when the password, MFA, username or email of an account it promotes changed after it was opened; an account change is refused the same way when the account\'s username, email, enabled or locked state changed. A promotion or account change opened before that state was recorded is expired the same way ("This ceremony predates the credential check; open it again.").',
    },
];
