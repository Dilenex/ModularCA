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
        requestBody: [
            { name: 'admin.multipleAdministrators', type: 'bool', required: true, description: 'The answer to “Will more than one person administer this CA?”. false starts key ceremonies off for the instance policy and the first space, because a lone administrator could never get one approved, and allows system-supers to approve their own certificate requests; true starts ceremonies on and self-approval off. A request without it is refused with 400. The rest of the body is the wizard’s configuration (organization, rootCa, admin, features, webTlsCertificate, database, security, network)' },
            { name: 'features.acmeAllowPrivateAddressValidation', type: 'bool', required: false, description: 'The answer to “Will ACME clients be on a private network?”. true lets the root CA’s http-01 validation fetch challenges from private, loopback and link-local addresses and resolve names through the host’s hosts file; false, the default, refuses them. Ignored unless features.enableAcme is true. true is written to the audit log' },
        ],
        headers: [
            { name: 'X-CSRF-Token', type: 'string', required: true, description: 'Anti-CSRF token for state-changing anonymous requests' },
        ],
        responseDescription: 'Bootstrap result including generated admin username and password on success.',
        notes: 'Returns 404 once the system is configured. Invalidates setup middleware cache on success. Each webTlsCertificate.sans entry must be DNS:name or IP:address; any other type, an untyped entry or an invalid IP is refused with 400 before any setup work. admin.multipleAdministrators is required and decides whether key ceremonies start on; the choice is written to the audit log, and the requirement can be changed afterwards through the security policy (instance) and the space (first space). The unattended equivalent is Administration.MultipleAdministrators in bootstrap.yaml, which may be left out to keep them on. features.acmeAllowPrivateAddressValidation has the unattended equivalent Acme.AllowPrivateAddressValidation, and is changed afterwards per CA through the protocol configuration.',
    },
];
