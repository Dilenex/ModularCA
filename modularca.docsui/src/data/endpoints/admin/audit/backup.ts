import type { ApiEndpoint } from '../../types';

export const adminBackup: ApiEndpoint[] = [
    {
        method: 'POST',
        path: '/api/v1/admin/backup',
        summary: 'Create a new encrypted backup. Requires step-up MFA.',
        auth: 'Authorize (SystemAdmin)',
        category: 'Admin Backup',
        headers: [
            { name: 'Authorization', type: 'Bearer token', required: true, description: 'JWT access token from /api/v1/auth/login' },
            { name: 'X-MFA-Token', type: 'string', required: false, description: 'Step-up MFA token from /api/v1/auth/mfa/verify-stepup. Required for this operation.' },
        ],
        responseDescription: 'Backup creation confirmation with file path.',
    },
    {
        method: 'GET',
        path: '/api/v1/admin/backup',
        summary: 'List available backup files.',
        auth: 'Authorize (SystemAdmin)',
        category: 'Admin Backup',
        headers: [
            { name: 'Authorization', type: 'Bearer token', required: true, description: 'JWT access token from /api/v1/auth/login' },
        ],
        responseDescription: 'Array of backup file entries.',
    },
    {
        method: 'POST',
        path: '/api/v1/admin/backup/preview-restore',
        summary: 'Inspect a backup archive and issue a single-use confirmation token required by the subsequent restore call. Requires step-up MFA.',
        auth: 'Authorize (SystemAdmin)',
        category: 'Admin Backup',
        requestBody: [
            { name: 'fileName', type: 'string', required: true, description: 'Filename of the backup archive to preview (sanitized; must live in the backup directory).' },
        ],
        headers: [
            { name: 'Authorization', type: 'Bearer token', required: true, description: 'JWT access token from /api/v1/auth/login' },
            { name: 'X-MFA-Token', type: 'string', required: true, description: 'Step-up MFA token scoped to restore-backup.' },
        ],
        responseDescription: 'One-time confirmationToken (5-minute TTL), manifest summary, and archive metadata. The token is bound to (user, filename) and consumed by /restore.',
    },
    {
        method: 'POST',
        path: '/api/v1/admin/backup/restore',
        summary: 'Restore from an encrypted backup. Requires the confirmationToken from /preview-restore and step-up MFA.',
        auth: 'Authorize (SystemAdmin)',
        category: 'Admin Backup',
        requestBody: [
            { name: 'fileName', type: 'string', required: true, description: 'Filename of the backup archive to restore. Must match the token.' },
            { name: 'confirmationToken', type: 'string', required: true, description: 'Single-use token from /preview-restore, bound to (user, fileName).' },
            { name: 'restoreAudit', type: 'boolean', required: false, description: "Replace this instance's audit database with the archive's audit trail. Default false: the live audit history is kept and the restore is recorded in it." },
            { name: 'password', type: 'string', required: false, description: 'Optional DR password for StoredPassword-mode archives when the on-disk key file is missing or rotated.' },
        ],
        headers: [
            { name: 'Authorization', type: 'Bearer token', required: true, description: 'JWT access token from /api/v1/auth/login' },
            { name: 'X-MFA-Token', type: 'string', required: true, description: 'Step-up MFA token scoped to restore-backup.' },
        ],
        responseDescription: 'Success message; an application restart is required to apply changes.',
    },
    {
        method: 'GET',
        path: '/api/v1/admin/backup/dr-status',
        summary: 'Get disaster recovery status including last backup time and health.',
        auth: 'Authorize (SystemAdmin)',
        category: 'Admin Backup',
        headers: [
            { name: 'Authorization', type: 'Bearer token', required: true, description: 'JWT access token from /api/v1/auth/login' },
        ],
        responseDescription: 'DR status with backup health indicators.',
    },
    {
        method: 'GET',
        path: '/api/v1/admin/backup/encryption',
        summary: 'Get the current backup encryption configuration: mode (RandomKey or StoredPassword), key-file presence, and configured paths.',
        auth: 'Authorize (SystemAdmin)',
        category: 'Admin Backup',
        headers: [
            { name: 'Authorization', type: 'Bearer token', required: true, description: 'JWT access token from /api/v1/auth/login' },
        ],
        responseDescription: 'BackupEncryptionStatusResponse with mode, passwordSet, randomKeySet, passwordFilePath, randomKeyFilePath.',
    },
    {
        method: 'POST',
        path: '/api/v1/admin/backup/encryption/set-password',
        summary: 'Set a stored backup password and switch into StoredPassword mode. Derives a KEK via scrypt; the password is never persisted, logged, or echoed back. Requires step-up MFA.',
        auth: 'Authorize (SystemAdmin)',
        category: 'Admin Backup',
        requestBody: [
            { name: 'password', type: 'string', required: true, description: 'Plaintext password used to derive the backup KEK. Validated by BackupKeyManager.ValidatePassword.' },
        ],
        headers: [
            { name: 'Authorization', type: 'Bearer token', required: true, description: 'JWT access token from /api/v1/auth/login' },
            { name: 'X-MFA-Token', type: 'string', required: true, description: 'Step-up MFA token scoped to set-backup-password.' },
        ],
        responseDescription: 'Confirmation message with the new mode ("StoredPassword"). New backups will use this mode.',
    },
    {
        method: 'POST',
        path: '/api/v1/admin/backup/encryption/revert-to-random-key',
        summary: 'Revert backup encryption from StoredPassword back to RandomKey mode. The random key file must already exist on disk. Deletes the password key file on success. Requires step-up MFA.',
        auth: 'Authorize (SystemAdmin)',
        category: 'Admin Backup',
        headers: [
            { name: 'Authorization', type: 'Bearer token', required: true, description: 'JWT access token from /api/v1/auth/login' },
            { name: 'X-MFA-Token', type: 'string', required: true, description: 'Step-up MFA token scoped to change-backup-encryption-mode.' },
        ],
        responseDescription: 'Confirmation message with the new mode ("RandomKey"). Returns 400 if backup.key is missing.',
    },
];
