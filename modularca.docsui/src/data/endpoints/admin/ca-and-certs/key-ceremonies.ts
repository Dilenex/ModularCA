import type { ApiEndpoint } from '../../types';

export const adminKeyCeremonies: ApiEndpoint[] = [
    {
        method: 'POST',
        path: '/api/v1/admin/ceremonies',
        summary: 'Initiate a key ceremony to create a root or intermediate CA. CA revocation, SSH CA, tenant policy and controlled-user ceremonies are opened by their own endpoints. Requires step-up MFA.',
        auth: 'Authorize (CaAdmin)',
        category: 'Admin Key Ceremonies',
        requestBody: [
            { name: 'operationType', type: 'string', required: true, description: 'Operation type: CreateRootCA or CreateIntermediateCA. Any other value returns 400' },
            { name: 'description', type: 'string', required: false, description: 'Human-readable description of the ceremony\'s purpose (max 1000 chars)' },
            { name: 'targetEntityId', type: 'string', required: false, description: 'Target entity ID (e.g., CA ID for revocation). Empty for new entity creation' },
            { name: 'parameters', type: 'KeyCeremonyParameters', required: false, description: 'Structured CA creation parameters. Locked at initiation and cannot be modified after. Approvers review these parameters' },
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
        summary: 'List key ceremonies scoped by tenant. System admins see all; tenant-level CA admins see only their tenant ceremonies.',
        auth: 'Authorize (per-ceremony access check)',
        category: 'Admin Key Ceremonies',
        queryParams: [
            { name: 'status', type: 'string', required: false, description: 'Filter by status: Pending, Approved, Rejected, Executed, Cancelled, Expired' },
        ],
        headers: [
            { name: 'Authorization', type: 'Bearer token', required: true, description: 'JWT access token from /api/v1/auth/login' },
        ],
        responseDescription: 'Array of key ceremony records with ID, operationType, description, targetEntityId, initiatedBy, approvals, status, and timestamps.',
        notes: 'Automatically expires stale ceremonies before listing. CA-scoped admins (without tenant-wide CaManage) cannot see ceremonies.',
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
        responseDescription: 'Full ceremony detail including parametersJson and approvalsJson.',
        notes: 'Returns 403 if the caller does not have access to the ceremony\'s tenant.',
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
        notes: 'The initiator cannot approve their own ceremony. Returns 403 for self-approval attempts.',
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
        responseDescription: 'Execution result varies by operation type. For CA creation: { id, status, newCa: { id, name, label, type } }. For SSH CA: { id, status, newSshCaKey }. For revocation: { id, status, certificateId, serialNumber, newStatus, reason, crlNumber }.',
        notes: 'Parameters are locked from initiation; the ceremony uses the parameters approved by the quorum. Supported operations: CreateRootCA, CreateIntermediateCA, CreateSshCa, DeleteSshCa, RevokeCa.',
    },
];
