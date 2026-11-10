import type { ApiEndpoint } from '../../types';

export const adminCtLogs: ApiEndpoint[] = [
    {
        method: 'GET',
        path: '/api/v1/admin/ct-logs',
        summary: 'List all Certificate Transparency log configurations.',
        auth: 'Authorize (SystemOperator)',
        category: 'Admin CT Logs',
        headers: [
            { name: 'Authorization', type: 'Bearer token', required: true, description: 'JWT access token from /api/v1/auth/login' },
        ],
        responseDescription: 'Array of CT log entries.',
    },
    {
        method: 'GET',
        path: '/api/v1/admin/ct-logs/options',
        summary: 'List the CT logs a certificate profile can submit to, for choosing them by name.',
        auth: 'Authorize (CaOperator)',
        category: 'Admin CT Logs',
        headers: [
            { name: 'Authorization', type: 'Bearer token', required: true, description: 'JWT access token from /api/v1/auth/login' },
        ],
        responseDescription: 'Array of { id, name, url, enabled }, ordered by name; no public keys.',
        notes: 'Open to anyone who may edit a certificate profile. A certificate profile stores these ids in CtLogIds (a JSON array); blank means every enabled log. Create and update refuse ids that name no log.',
    },
    {
        method: 'GET',
        path: '/api/v1/admin/ct-logs/{id}',
        summary: 'Get a CT log configuration by ID.',
        auth: 'Authorize (SystemOperator)',
        category: 'Admin CT Logs',
        headers: [
            { name: 'Authorization', type: 'Bearer token', required: true, description: 'JWT access token from /api/v1/auth/login' },
        ],
        responseDescription: 'CT log details.',
    },
    {
        method: 'POST',
        path: '/api/v1/admin/ct-logs',
        summary: 'Create a new CT log configuration.',
        auth: 'Authorize (SystemOperator)',
        category: 'Admin CT Logs',
        headers: [
            { name: 'Authorization', type: 'Bearer token', required: true, description: 'JWT access token from /api/v1/auth/login' },
        ],
        responseDescription: 'Created CT log entry.',
        notes: 'publicKeyBase64 is the DER SubjectPublicKeyInfo of the log in base64 (ECDSA P-256 or RSA of 2048 bits or more), as the log lists publish it; PEM is accepted. Any other value is refused with 400. From 0.4.4 every SCT the log returns is verified against this key and discarded if it does not verify; a log with no key has its SCTs discarded.',
    },
    {
        method: 'PUT',
        path: '/api/v1/admin/ct-logs/{id}',
        summary: 'Update a CT log configuration.',
        auth: 'Authorize (SystemOperator)',
        category: 'Admin CT Logs',
        headers: [
            { name: 'Authorization', type: 'Bearer token', required: true, description: 'JWT access token from /api/v1/auth/login' },
        ],
        responseDescription: 'Updated CT log entry.',
        notes: 'A publicKeyBase64 is checked as on create (400); an empty one removes the key, after which SCTs from the log are discarded.',
    },
    {
        method: 'DELETE',
        path: '/api/v1/admin/ct-logs/{id}',
        summary: 'Delete a CT log configuration.',
        auth: 'Authorize (SystemOperator)',
        category: 'Admin CT Logs',
        headers: [
            { name: 'Authorization', type: 'Bearer token', required: true, description: 'JWT access token from /api/v1/auth/login' },
        ],
        responseDescription: 'Deletion confirmation.',
    },
];
