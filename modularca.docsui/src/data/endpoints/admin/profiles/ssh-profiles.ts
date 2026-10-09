import type { ApiEndpoint } from '../../types';

export const adminSshProfiles: ApiEndpoint[] = [
    {
        method: 'GET',
        path: '/api/v1/admin/ssh/profiles/signing',
        summary: 'List all SSH signing profiles.',
        auth: 'Authorize (CaOperator)',
        category: 'Admin SSH Profiles',
        headers: [
            { name: 'Authorization', type: 'Bearer token', required: true, description: 'JWT access token from /api/v1/auth/login' },
        ],
        responseDescription: 'Array of SSH signing profiles.',
    },
    {
        method: 'GET',
        path: '/api/v1/admin/ssh/profiles/signing/{id}',
        summary: 'Get an SSH signing profile by ID.',
        auth: 'Authorize (CaOperator)',
        category: 'Admin SSH Profiles',
        headers: [
            { name: 'Authorization', type: 'Bearer token', required: true, description: 'JWT access token from /api/v1/auth/login' },
        ],
        responseDescription: 'SSH signing profile details.',
    },
    {
        method: 'POST',
        path: '/api/v1/admin/ssh/profiles/signing',
        summary: 'Create a new SSH signing profile.',
        auth: 'Authorize (CaOperator)',
        category: 'Admin SSH Profiles',
        headers: [
            { name: 'Authorization', type: 'Bearer token', required: true, description: 'JWT access token from /api/v1/auth/login' },
        ],
        responseDescription: 'Created SSH signing profile.',
        notes: 'defaultExtensions are the extensions of a user certificate whose request names none; a request that names any replaces the set. A certificate carries exactly the extensions that result, with the profile\'s force-command and source-address and the cert profile\'s required extensions. None is added by default: before 0.4.2 every user certificate also carried permit-X11-forwarding, permit-agent-forwarding, permit-port-forwarding, permit-pty and permit-user-rc by default. A no-* name adds nothing and withholds the matching permit-*.',
    },
    {
        method: 'PUT',
        path: '/api/v1/admin/ssh/profiles/signing/{id}',
        summary: 'Update an SSH signing profile.',
        auth: 'Authorize (CaOperator)',
        category: 'Admin SSH Profiles',
        headers: [
            { name: 'Authorization', type: 'Bearer token', required: true, description: 'JWT access token from /api/v1/auth/login' },
        ],
        responseDescription: 'Updated SSH signing profile.',
    },
    {
        method: 'DELETE',
        path: '/api/v1/admin/ssh/profiles/signing/{id}',
        summary: 'Delete an SSH signing profile.',
        auth: 'Authorize (CaOperator)',
        category: 'Admin SSH Profiles',
        headers: [
            { name: 'Authorization', type: 'Bearer token', required: true, description: 'JWT access token from /api/v1/auth/login' },
        ],
        responseDescription: 'Deletion confirmation.',
    },
    {
        method: 'GET',
        path: '/api/v1/admin/ssh/profiles/cert',
        summary: 'List all SSH certificate profiles.',
        auth: 'Authorize (CaOperator)',
        category: 'Admin SSH Profiles',
        headers: [
            { name: 'Authorization', type: 'Bearer token', required: true, description: 'JWT access token from /api/v1/auth/login' },
        ],
        responseDescription: 'Array of SSH certificate profiles. Each carries certificateType: user, host, or null for a profile that serves either.',
    },
    {
        method: 'GET',
        path: '/api/v1/admin/ssh/profiles/cert/{id}',
        summary: 'Get an SSH certificate profile by ID.',
        auth: 'Authorize (CaOperator)',
        category: 'Admin SSH Profiles',
        headers: [
            { name: 'Authorization', type: 'Bearer token', required: true, description: 'JWT access token from /api/v1/auth/login' },
        ],
        responseDescription: 'SSH certificate profile details.',
    },
    {
        method: 'POST',
        path: '/api/v1/admin/ssh/profiles/cert',
        summary: 'Create a new SSH certificate profile.',
        auth: 'Authorize (CaOperator)',
        category: 'Admin SSH Profiles',
        headers: [
            { name: 'Authorization', type: 'Bearer token', required: true, description: 'JWT access token from /api/v1/auth/login' },
        ],
        responseDescription: 'Created SSH certificate profile.',
        notes: 'allowedExtensions is a ceiling on the extensions a request may name; empty means unrestricted. requiredExtensions are added to every certificate. A certificate carries exactly the extensions its profiles and request name, and none by default. A no-* name adds nothing and withholds the matching permit-*, so a required no-pty keeps permit-pty out of every certificate. certificateType is user, host or either; omitted, either. Any other value is 400. A profile of type user is refused by the sign routes for a host certificate, and one of type host for a user certificate; one that serves either is accepted for both.',
    },
    {
        method: 'PUT',
        path: '/api/v1/admin/ssh/profiles/cert/{id}',
        summary: 'Update an SSH certificate profile.',
        auth: 'Authorize (CaOperator)',
        category: 'Admin SSH Profiles',
        headers: [
            { name: 'Authorization', type: 'Bearer token', required: true, description: 'JWT access token from /api/v1/auth/login' },
        ],
        responseDescription: 'Updated SSH certificate profile.',
        notes: 'Every member is optional and an omitted one is left as it is. certificateType, when sent, is user, host, or either, which clears the type; any other value is 400.',
    },
    {
        method: 'DELETE',
        path: '/api/v1/admin/ssh/profiles/cert/{id}',
        summary: 'Delete an SSH certificate profile.',
        auth: 'Authorize (CaOperator)',
        category: 'Admin SSH Profiles',
        headers: [
            { name: 'Authorization', type: 'Bearer token', required: true, description: 'JWT access token from /api/v1/auth/login' },
        ],
        responseDescription: 'Deletion confirmation.',
    },
    {
        method: 'GET',
        path: '/api/v1/admin/ssh/profiles/request',
        summary: 'List all SSH request profiles.',
        auth: 'Authorize (CaOperator)',
        category: 'Admin SSH Profiles',
        headers: [
            { name: 'Authorization', type: 'Bearer token', required: true, description: 'JWT access token from /api/v1/auth/login' },
        ],
        responseDescription: 'Array of SSH request profiles. Each carries certificateType: user, host, or null for a profile that serves either.',
    },
    {
        method: 'GET',
        path: '/api/v1/admin/ssh/profiles/request/{id}',
        summary: 'Get an SSH request profile by ID.',
        auth: 'Authorize (CaOperator)',
        category: 'Admin SSH Profiles',
        headers: [
            { name: 'Authorization', type: 'Bearer token', required: true, description: 'JWT access token from /api/v1/auth/login' },
        ],
        responseDescription: 'SSH request profile details.',
    },
    {
        method: 'POST',
        path: '/api/v1/admin/ssh/profiles/request',
        summary: 'Create a new SSH request profile.',
        auth: 'Authorize (CaOperator)',
        category: 'Admin SSH Profiles',
        headers: [
            { name: 'Authorization', type: 'Bearer token', required: true, description: 'JWT access token from /api/v1/auth/login' },
        ],
        responseDescription: 'Created SSH request profile.',
        notes: 'certificateType is user, host or either; omitted, either. Any other value is 400. The self-service request options and the self-service sign route take a request profile only when its type is user or it has none; the administration console offers a request profile only for a certificate of its type.',
    },
    {
        method: 'PUT',
        path: '/api/v1/admin/ssh/profiles/request/{id}',
        summary: 'Update an SSH request profile.',
        auth: 'Authorize (CaOperator)',
        category: 'Admin SSH Profiles',
        headers: [
            { name: 'Authorization', type: 'Bearer token', required: true, description: 'JWT access token from /api/v1/auth/login' },
        ],
        responseDescription: 'Updated SSH request profile.',
        notes: 'Every member is optional and an omitted one is left as it is. certificateType, when sent, is user, host, or either, which clears the type; any other value is 400.',
    },
    {
        method: 'DELETE',
        path: '/api/v1/admin/ssh/profiles/request/{id}',
        summary: 'Delete an SSH request profile.',
        auth: 'Authorize (CaOperator)',
        category: 'Admin SSH Profiles',
        headers: [
            { name: 'Authorization', type: 'Bearer token', required: true, description: 'JWT access token from /api/v1/auth/login' },
        ],
        responseDescription: 'Deletion confirmation.',
    },
];
