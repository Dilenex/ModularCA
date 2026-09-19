import type { ApiEndpoint } from '../../types';

export const adminProtocolConfigs: ApiEndpoint[] = [
    {
        method: 'GET',
        path: '/api/v1/admin/protocol-configs/{caId}',
        summary: 'Get protocol configurations for a specific CA.',
        auth: 'Authorize (CaOperator)',
        category: 'Admin Protocol Configs',
        headers: [
            { name: 'Authorization', type: 'Bearer token', required: true, description: 'JWT access token from /api/v1/auth/login' },
        ],
        responseDescription: 'Protocol configurations with signing/cert profile assignments. Protocols disabled system-wide by their feature flag are omitted (the stored row is kept), and each row carries an advisories array: a reason code and sentence for a configuration that cannot work on this CA, such as SCEP on a non-RSA authority.',
    },
    {
        method: 'PUT',
        path: '/api/v1/admin/protocol-configs/{caId}/{protocol}',
        summary: 'Update a protocol configuration for a CA.',
        auth: 'Authorize (CaOperator)',
        category: 'Admin Protocol Configs',
        headers: [
            { name: 'Authorization', type: 'Bearer token', required: true, description: 'JWT access token from /api/v1/auth/login' },
        ],
        responseDescription: 'Updated protocol configuration. Enabling SCEP on a CA whose key is not RSA is refused with 400: SCEP encrypts the request to the CA certificate using RSA key transport.',
    },
];
