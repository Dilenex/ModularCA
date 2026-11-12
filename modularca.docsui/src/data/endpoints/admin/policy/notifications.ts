import type { ApiEndpoint } from '../../types';

export const adminNotifications: ApiEndpoint[] = [
    {
        method: 'GET',
        path: '/api/v1/admin/notifications/delivery',
        summary: 'The outbound email settings the notification page shows (enabled, SMTP host and port, TLS, sender, admin recipients). No credentials are returned.',
        auth: 'Authorize (SystemOperator)',
        category: 'Admin Notifications',
        headers: [
            { name: 'Authorization', type: 'Bearer token', required: true, description: 'JWT access token from /api/v1/auth/login' },
        ],
        responseDescription: 'An object with an email section.',
    },
    {
        method: 'GET',
        path: '/api/v1/admin/notifications',
        summary: 'List all notification preference configurations, ordered by event type.',
        auth: 'Authorize (SystemOperator)',
        category: 'Admin Notifications',
        headers: [
            { name: 'Authorization', type: 'Bearer token', required: true, description: 'JWT access token from /api/v1/auth/login' },
        ],
        responseDescription: 'Array of notification preferences, each with id, eventType, enabled, recipients and description.',
    },
    {
        method: 'PUT',
        path: '/api/v1/admin/notifications/{eventType}',
        summary: 'Update notification settings for a specific event type. Only provided fields are modified.',
        auth: 'Authorize (SystemOperator)',
        category: 'Admin Notifications',
        requestBody: [
            { name: 'enabled', type: 'bool', required: false, description: 'Enable or disable notifications for this event type' },
            { name: 'recipients', type: 'string', required: false, description: 'Comma-separated list of email recipients' },
        ],
        headers: [
            { name: 'Authorization', type: 'Bearer token', required: true, description: 'JWT access token from /api/v1/auth/login' },
        ],
        responseDescription: 'The updated notification preference, in the shape the list returns.',
        notes: 'From 0.4.4 a daysBeforeExpiry field, which was stored and never read, is ignored.',
    },
    {
        method: 'POST',
        path: '/api/v1/admin/notifications/test',
        summary: 'Send a test email to all admin recipients to verify SMTP configuration.',
        auth: 'Authorize (SystemOperator)',
        category: 'Admin Notifications',
        headers: [
            { name: 'Authorization', type: 'Bearer token', required: true, description: 'JWT access token from /api/v1/auth/login' },
        ],
        responseDescription: 'Confirmation that the test email was sent to admin recipients.',
        notes: 'Returns 500 if SMTP is misconfigured or the send fails.',
    },
    {
        method: 'POST',
        path: '/api/v1/admin/notifications/test-webhook',
        summary: 'Send a test webhook event to all configured webhook endpoints. Validates endpoints against SSRF before dispatching.',
        auth: 'Authorize (SystemOperator)',
        category: 'Admin Notifications',
        headers: [
            { name: 'Authorization', type: 'Bearer token', required: true, description: 'JWT access token from /api/v1/auth/login' },
        ],
        responseDescription: 'Object with message, endpointCount, and endpoints array (each with url and events).',
        notes: 'Returns 400 if webhooks are not enabled, no endpoints are configured, or any endpoint fails SSRF validation.',
    },
];
