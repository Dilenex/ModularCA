import type { ApiEndpoint } from './types';

export const setup: ApiEndpoint[] = [
    {
        method: 'GET',
        path: '/api/v1/setup/status',
        summary: 'Returns the current setup status including database connectivity and configuration state.',
        auth: 'Anonymous',
        category: 'Setup',
        responseDescription: 'Object with configured, databaseConnected, and needsDbConfig flags.',
        notes: 'Returns 404 once the system is configured (at least one CA exists).',
    },
    {
        method: 'POST',
        path: '/api/v1/setup/database/test',
        summary: 'Test a database connection with the provided credentials.',
        auth: 'Anonymous',
        category: 'Setup',
        requestBody: [
            { name: 'rootHost', type: 'string', required: true, description: 'Database server hostname' },
            { name: 'rootPort', type: 'int', required: true, description: 'Database server port' },
            { name: 'rootUsername', type: 'string', required: true, description: 'Root database username' },
            { name: 'rootPassword', type: 'string', required: true, description: 'Root database password' },
            { name: 'appDatabase', type: 'string', required: true, description: 'Application database name to check' },
        ],
        headers: [
            { name: 'X-CSRF-Token', type: 'string', required: true, description: 'Anti-CSRF token for state-changing anonymous requests' },
        ],
        responseDescription: 'Object with connected (bool) and databaseExists (bool), or error message.',
    },
    {
        method: 'GET',
        path: '/api/v1/setup/defaults',
        summary: 'Returns available algorithms, key sizes, and default values for the setup wizard UI.',
        auth: 'Anonymous',
        category: 'Setup',
        responseDescription: 'Available algorithms, key sizes, signature algorithms, and default root CA/feature/API cert settings.',
    },
    {
        method: 'POST',
        path: '/api/v1/setup/initialize',
        summary: 'Run the full bootstrap procedure with the provided configuration. Returns admin credentials.',
        auth: 'Anonymous',
        category: 'Setup',
        headers: [
            { name: 'X-CSRF-Token', type: 'string', required: true, description: 'Anti-CSRF token for state-changing anonymous requests' },
        ],
        responseDescription: 'Bootstrap result including generated admin username and password on success.',
        notes: 'Returns 404 once the system is configured. Invalidates setup middleware cache on success. Each webTlsCertificate.sans entry must be DNS:name or IP:address; any other type, an untyped entry or an invalid IP is refused with 400 before any setup work.',
    },
];
