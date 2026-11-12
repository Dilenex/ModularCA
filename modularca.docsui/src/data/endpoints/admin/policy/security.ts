import type { ApiEndpoint } from '../../types';

export const adminSecurityPolicy: ApiEndpoint[] = [
    {
        method: 'GET',
        path: '/api/v1/admin/security-policy',
        summary: 'Get the current runtime-tunable security policy (session lockout, MFA TTLs, OCSP posture, login banner).',
        auth: 'Authorize (SystemAdmin)',
        category: 'Admin Security Policy',
        headers: [
            { name: 'Authorization', type: 'Bearer token', required: true, description: 'JWT access token from /api/v1/auth/login' },
        ],
        responseDescription: 'Security policy row with 21 knobs across session, MFA, and OCSP domains.',
    },
    {
        method: 'GET',
        path: '/api/v1/admin/security-policy/administrators',
        summary: 'Whether the instance is still set up for a single administrator while it has more than one.',
        auth: 'Authorize (SystemAdmin)',
        category: 'Admin Security Policy',
        headers: [
            { name: 'Authorization', type: 'Bearer token', required: true, description: 'JWT access token from /api/v1/auth/login' },
        ],
        responseDescription: 'systemSuperCount (active system super-administrators), selfApprovalAllowed, keyCeremonyRequired, and outgrown: true when there are several supers and self-approval is still allowed or key ceremonies are still off.',
    },
    {
        method: 'PUT',
        path: '/api/v1/admin/security-policy',
        summary: 'Update the runtime-tunable security policy. Partial update — null fields are left unchanged. TTL fields are clamped to their documented ranges on write; an unusable keystore scrypt cost is refused with 400.',
        auth: 'Authorize (SystemAdmin)',
        category: 'Admin Security Policy',
        headers: [
            { name: 'Authorization', type: 'Bearer token', required: true, description: 'JWT access token from /api/v1/auth/login' },
            { name: 'X-MFA-Token', type: 'string', required: true, description: 'Step-up MFA token scoped to update-config; scoped to disable-ceremony-requirement instead when a system super-administrator turns the instance\'s key ceremony requirement off' },
        ],
        responseDescription: 'Updated security policy row, or 202 with a ceremonyId when a non-super change to the instance\'s ceremony requirement or approvals opens an InstancePolicyChange ceremony.',
        notes: 'Changes take effect on the next request scope (cache invalidated on PUT, no restart required). The whole endpoint needs a system administrator; system operators can neither read nor change it. A change to userQuorum needs a system super-administrator (403 otherwise). requireKeyCeremony and ceremonyRequiredApprovals are the instance’s key ceremony policy; a change to either by anyone but a system super-administrator opens an InstancePolicyChange ceremony (202). A change that needs a policy-change ceremony nobody else could approve is refused with 409 (code MCA-CFG-020 or MCA-CFG-021) before anything is saved; a system super-administrator applies the change directly instead. The keystore scrypt cost is not clamped: when keystoreScryptN, keystoreScryptR or keystoreScryptP changes, N must be a power of two from 16384 (2^14) to 1048576 (2^20), r from 1 to 32 and p from 1 to 16, and one derivation may need at most 1 GiB (128 × N × r bytes; at r = 8, N up to 2^20), or the request is refused with 400 and nothing is saved. Values sent back unchanged are not checked, so a cost saved above 1 GiB before the limit existed is kept until it is changed; keystore files written with it still open.',
    },
];
