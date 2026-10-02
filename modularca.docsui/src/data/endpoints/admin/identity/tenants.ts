import type { ApiEndpoint } from '../../types';

export const adminTenants: ApiEndpoint[] = [
    {
        method: 'GET',
        path: '/api/v1/admin/tenants',
        summary: 'List all tenants with summary counts for CAs, users, and certificates.',
        auth: 'Authorize (SystemAdmin)',
        category: 'Admin Tenants',
        headers: [
            { name: 'Authorization', type: 'Bearer token', required: true, description: 'JWT access token from /api/v1/auth/login' },
        ],
        responseDescription: 'Array of tenants with name, slug, description, status, policy, and counts.',
    },
    {
        method: 'GET',
        path: '/api/v1/admin/tenants/{id}',
        summary: 'Get detailed tenant information including CA, user, and certificate counts.',
        auth: 'Authorize (SystemAdmin)',
        category: 'Admin Tenants',
        headers: [
            { name: 'Authorization', type: 'Bearer token', required: true, description: 'JWT access token from /api/v1/auth/login' },
        ],
        responseDescription: 'Tenant details with policy and count fields. Tenant quotas were removed in 0.4.0.',
    },
    {
        method: 'POST',
        path: '/api/v1/admin/tenants',
        summary: 'Create a new tenant. Auto-generates {slug}-admin/operator/auditor/user groups.',
        auth: 'Authorize (SystemAdmin)',
        category: 'Admin Tenants',
        requestBody: [
            { name: 'name', type: 'string', required: true, description: 'Human-readable tenant name (must be unique)' },
            { name: 'slug', type: 'string', required: false, description: 'URL-safe slug (auto-generated from name if not provided)' },
            { name: 'description', type: 'string', required: false, description: 'Tenant description' },
        ],
        headers: [
            { name: 'Authorization', type: 'Bearer token', required: true, description: 'JWT access token from /api/v1/auth/login' },
        ],
        responseDescription: 'Created tenant details.',
        notes: 'Auto-generates {tenant-slug}-admin, {tenant-slug}-operator, {tenant-slug}-auditor, and {tenant-slug}-user groups.',
    },
    {
        method: 'PUT',
        path: '/api/v1/admin/tenants/{id}',
        summary: 'Update a tenant\'s name, slug, description, or enabled status.',
        auth: 'Authorize (SystemAdmin)',
        category: 'Admin Tenants',
        requestBody: [
            { name: 'name', type: 'string', required: false, description: 'New tenant name' },
            { name: 'slug', type: 'string', required: false, description: 'New URL-safe slug' },
            { name: 'description', type: 'string', required: false, description: 'New description' },
            { name: 'isEnabled', type: 'bool', required: false, description: 'Enable or disable the tenant' },
        ],
        headers: [
            { name: 'Authorization', type: 'Bearer token', required: true, description: 'JWT access token from /api/v1/auth/login' },
        ],
        responseDescription: 'Updated tenant details.',
    },
    {
        method: 'DELETE',
        path: '/api/v1/admin/tenants/{id}',
        summary: 'Disable a tenant (soft delete). Data is preserved but the tenant is marked disabled.',
        auth: 'Authorize (SystemAdmin)',
        category: 'Admin Tenants',
        headers: [
            { name: 'Authorization', type: 'Bearer token', required: true, description: 'JWT access token from /api/v1/auth/login' },
        ],
        responseDescription: 'Confirmation that the tenant has been disabled.',
    },
];
