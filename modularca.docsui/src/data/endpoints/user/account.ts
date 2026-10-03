import type { ApiEndpoint } from '../types';

export const account: ApiEndpoint[] = [
    {
        method: 'GET',
        path: '/api/v1/account',
        summary: 'Get the authenticated user\'s account information.',
        auth: 'Authorize',
        category: 'Account',
        headers: [
            { name: 'Authorization', type: 'Bearer token', required: true, description: 'JWT access token from /api/v1/auth/login' },
        ],
        responseDescription: 'User profile including username, display name, email, and account status.',
    },
    {
        method: 'PUT',
        path: '/api/v1/account/password',
        summary: 'Change the authenticated user\'s password. Requires step-up MFA.',
        auth: 'Authorize',
        category: 'Account',
        requestBody: [
            { name: 'currentPassword', type: 'string', required: true, description: 'Current password' },
            { name: 'newPassword', type: 'string', required: true, description: 'New password' },
            { name: 'confirmNewPassword', type: 'string', required: true, description: 'New password confirmation' },
        ],
        headers: [
            { name: 'Authorization', type: 'Bearer token', required: true, description: 'JWT access token from /api/v1/auth/login' },
            { name: 'X-MFA-Token', type: 'string', required: false, description: 'Step-up MFA token from /api/v1/auth/mfa/verify-stepup. Required for this operation.' },
        ],
        responseDescription: 'Success confirmation.',
    },
    {
        method: 'GET',
        path: '/api/v1/account/mfa',
        summary: 'Returns the authenticated user\'s MFA enrollment status and configured methods.',
        auth: 'Authorize',
        category: 'Account',
        headers: [
            { name: 'Authorization', type: 'Bearer token', required: true, description: 'JWT access token from /api/v1/auth/login' },
        ],
        responseDescription: 'Object with totp, webauthn, and mtls enrollment details and hasStepUpCapability flag.',
    },
    {
        method: 'GET',
        path: '/api/v1/me',
        summary: 'Lightweight whoami endpoint. Returns the caller\'s id, username, email, group memberships (with role levels and CA scope), flat scope list, MFA enrollment flags, and primary space. SPAs use this to populate an AuthContext instead of decoding the JWT body client-side.',
        auth: 'Authorize',
        category: 'Account',
        headers: [
            { name: 'Authorization', type: 'Bearer token', required: true, description: 'JWT access token from /api/v1/auth/login' },
        ],
        responseDescription: 'Identity payload: { id, username, email, displayName, firstName, lastName, isActive, groups (each with spaceId), scopes, capabilities: { system, cas (each with spaceId, spaceName, spaceSlug), spaces }, badge, badges, mfa: { configured, totp, webauthn, mtls }, spaceId }.',
    },
    {
        method: 'GET',
        path: '/api/v1/me/effective-permissions',
        summary: 'Returns the calling user\'s effective permissions aggregated from all sources: direct capability grants, direct role assignments, group memberships with their capability grants, and group role assignments.',
        auth: 'Authorize',
        category: 'Account',
        headers: [
            { name: 'Authorization', type: 'Bearer token', required: true, description: 'JWT access token from /api/v1/auth/login' },
        ],
        responseDescription: 'Permissions payload: { UserId, DirectGrants[], RoleAssignments[], GroupMemberships[] } where each entry enumerates the underlying capabilities and scope (space, CA, resource).',
    },
];
