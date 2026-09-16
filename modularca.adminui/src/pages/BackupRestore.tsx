import React, { useState, useEffect, useCallback } from 'react';
import type { NoticeInput } from '@shared/notifications/notice';
import { InlineNotice } from '@shared/components/InlineNotice';
import { errorNotice } from '@shared-auth/api/notices';
import { Link } from 'react-router-dom';
import { apiGet, apiPostWithMfa, API_BASE } from '../api/client';
import { DataTable, type DataTableColumn } from '@shared/components/DataTable';
import { useStepUp } from '../components/StepUpMfaContext';
import { StepUpOps } from '@shared/generated';
import ConfirmModal from '../components/ConfirmModal';

/** The Restart card on Settings → General (id set in Settings.tsx). */
const RESTART_PATH = '/settings#restart-application';
const RestartLink: React.FC<{ children?: React.ReactNode }> = ({ children }) => (
    <Link to={RESTART_PATH} className="underline hover:text-gray-900 dark:hover:text-white">{children ?? 'Settings → General → Restart Application'}</Link>
);

function formatDate(d: string | null) {
    if (!d) return '-';
    return new Date(d).toLocaleDateString('en-US', { year: 'numeric', month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' });
}

function formatSize(bytes: number): string {
    if (bytes < 1024) return `${bytes} B`;
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
    if (bytes < 1024 * 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
    return `${(bytes / (1024 * 1024 * 1024)).toFixed(2)} GB`;
}

interface BackupEntry {
    fileName: string;
    sizeBytes: number;
    createdUtc: string;
}

/* ─── Create Backup Section ─── */
const CreateBackupSection: React.FC<{ onBackupCreated: () => void }> = ({ onBackupCreated }) => {
    const { requireStepUp } = useStepUp();
    const [creating, setCreating] = useState(false);
    const [status, setStatus] = useState<string | null>(null);
    const [error, setError] = useState<NoticeInput | null>(null);

    const handleCreateBackup = async () => {
        setCreating(true);
        setStatus('Creating backup... This may take a moment.');
        setError(null);
        try {
            const result = await apiPostWithMfa<any>(
                '/api/v1/admin/backup',
                {},
                requireStepUp,
                StepUpOps.CreateBackup,
            );
            setStatus(`Backup created successfully: ${result.fileName}`);
            onBackupCreated();
        } catch (err: any) {
            if (err.message === 'Step-up MFA cancelled') {
                setStatus(null);
                setCreating(false);
                return;
            }
            setError(errorNotice(err, 'The request failed.'));
            setStatus(null);
        } finally {
            setCreating(false);
        }
    };

    return (
        <div className="bg-gray-100 dark:bg-gray-800 border border-gray-300 dark:border-gray-700 rounded-lg p-6 space-y-4">
            <div className="flex items-center justify-between">
                <h3 className="text-gray-900 dark:text-white font-semibold">Create Backup</h3>
                <button
                    onClick={handleCreateBackup}
                    disabled={creating}
                    className="px-4 py-2 bg-blue-600 hover:bg-blue-700 disabled:bg-gray-600 text-gray-900 dark:text-white text-sm font-medium rounded transition-colors"
                >
                    {creating ? 'Creating...' : 'Create Backup Now'}
                </button>
            </div>
            <p className="text-gray-600 dark:text-gray-400 text-sm">
                Creates a full backup archive containing the application database, audit database,
                keystores, configuration files, and SSH CA keys.
            </p>

            <div className="bg-gray-50 dark:bg-gray-900 border border-gray-300 dark:border-gray-700 rounded p-4 text-sm text-gray-700 dark:text-gray-300">
                <p className="font-medium text-gray-900 dark:text-white mb-2">Backup includes:</p>
                <ul className="space-y-1 list-disc list-inside text-gray-600 dark:text-gray-400">
                    <li>Application database (certificates, profiles, users, feature flags)</li>
                    <li>Audit database (all audit logs)</li>
                    <li>Keystores (CA private keys -- encrypted)</li>
                    <li>Configuration files (config.yaml, keystore.yaml)</li>
                    <li>SSH CA keys (if configured)</li>
                    <li>API TLS certificate (api-tls.pfx)</li>
                </ul>
            </div>

            {status && (
                <div className="p-3 bg-blue-50 dark:bg-blue-900/30 border border-blue-300 dark:border-blue-700 rounded text-blue-800 dark:text-blue-300 text-sm">
                    {status}
                </div>
            )}
            {error && (
                <InlineNotice notice={error} />
            )}
        </div>
    );
};

/* ─── Backup Encryption Section ─── */
interface EncryptionStatus {
    mode: 'RandomKey' | 'StoredPassword';
    passwordSet: boolean;
    randomKeySet: boolean;
    passwordFilePath: string;
    randomKeyFilePath: string;
}

const BackupEncryptionSection: React.FC = () => {
    const { requireStepUp } = useStepUp();
    const [status, setStatus] = useState<EncryptionStatus | null>(null);
    const [loading, setLoading] = useState(true);
    const [newPassword, setNewPassword] = useState('');
    const [confirmPassword, setConfirmPassword] = useState('');
    const [actionError, setActionError] = useState<string | null>(null);
    const [actionSuccess, setActionSuccess] = useState<string | null>(null);
    const [submitting, setSubmitting] = useState(false);
    // Reverting to RandomKey was the last native confirm() in this console; ConfirmModal is used
    // everywhere else, and a native dialog cannot show the consequence with any emphasis.
    const [confirmRevert, setConfirmRevert] = useState(false);

    useEffect(() => {
        apiGet<EncryptionStatus>('/api/v1/admin/backup/encryption')
            .then(setStatus)
            .catch((err) => setActionError(err.message || 'Failed to load encryption status'))
            .finally(() => setLoading(false));
    }, []);

    const handleSetPassword = async () => {
        setActionError(null);
        setActionSuccess(null);
        if (newPassword.length < 12) {
            setActionError('Password must be at least 12 characters.');
            return;
        }
        if (newPassword !== confirmPassword) {
            setActionError('Passwords do not match.');
            return;
        }
        setSubmitting(true);
        try {
            await apiPostWithMfa(
                '/api/v1/admin/backup/encryption/set-password',
                { password: newPassword },
                requireStepUp,
                StepUpOps.SetBackupPassword,
                undefined,
            );
            setActionSuccess('Backup encryption switched to StoredPassword mode. The derived KEK has been written to the password file. New backups will use the new password.');
            setNewPassword('');
            setConfirmPassword('');
            const fresh = await apiGet<EncryptionStatus>('/api/v1/admin/backup/encryption');
            setStatus(fresh);
        } catch (err: any) {
            if (err.message === 'Step-up MFA cancelled') {
                setSubmitting(false);
                return;
            }
            setActionError(err.message || 'Failed to set backup password');
        } finally {
            setSubmitting(false);
        }
    };

    const handleRevertToRandomKey = async () => {
        setConfirmRevert(false);
        setActionError(null);
        setActionSuccess(null);
        setSubmitting(true);
        try {
            await apiPostWithMfa(
                '/api/v1/admin/backup/encryption/revert-to-random-key',
                {},
                requireStepUp,
                StepUpOps.ChangeBackupEncryptionMode,
                undefined,
            );
            setActionSuccess('Reverted to RandomKey mode. Password file deleted.');
            const fresh = await apiGet<EncryptionStatus>('/api/v1/admin/backup/encryption');
            setStatus(fresh);
        } catch (err: any) {
            if (err.message === 'Step-up MFA cancelled') {
                setSubmitting(false);
                return;
            }
            setActionError(err.message || 'Failed to revert to RandomKey mode');
        } finally {
            setSubmitting(false);
        }
    };

    const isStoredPassword = status?.mode === 'StoredPassword';
    const formInvalid = newPassword.length < 12 || newPassword !== confirmPassword;

    return (
        <div className="bg-gray-100 dark:bg-gray-800 border border-gray-300 dark:border-gray-700 rounded-lg p-6 space-y-4">
            <div>
                <h3 className="text-gray-900 dark:text-white font-semibold">Backup Encryption</h3>
                <p className="text-gray-600 dark:text-gray-400 text-sm mt-1">
                    Choose how backup archives are encrypted. RandomKey uses a 32-byte random key file.
                    StoredPassword derives the key from an admin-supplied password via scrypt, enabling
                    password-only disaster recovery if the key file is lost.
                </p>
            </div>

            {loading && (
                <div className="p-4 text-sm text-gray-600 dark:text-gray-400 text-center">Loading encryption status...</div>
            )}

            {!loading && status && (
                <>
                    <div className="bg-gray-50 dark:bg-gray-900 border border-gray-300 dark:border-gray-700 rounded p-4 space-y-2">
                        <div className="flex items-center gap-2">
                            <span className="text-xs text-gray-600 dark:text-gray-400">Current mode:</span>
                            <span
                                className={
                                    isStoredPassword
                                        ? 'inline-block px-2 py-0.5 rounded text-xs font-semibold bg-green-50 dark:bg-green-900/40 border border-green-300 dark:border-green-700 text-green-800 dark:text-green-300'
                                        : 'inline-block px-2 py-0.5 rounded text-xs font-semibold bg-blue-50 dark:bg-blue-900/40 border border-blue-300 dark:border-blue-700 text-blue-800 dark:text-blue-300'
                                }
                            >
                                {status.mode}
                            </span>
                        </div>
                        <div className="text-xs text-gray-600 dark:text-gray-400">
                            {isStoredPassword ? 'Password file: ' : 'Key file: '}
                            <span className="font-mono text-gray-800 dark:text-gray-200">
                                {isStoredPassword ? status.passwordFilePath : status.randomKeyFilePath}
                            </span>
                        </div>
                        {isStoredPassword && !status.passwordSet && (
                            <div className="p-2 bg-yellow-50 dark:bg-yellow-900/20 border border-yellow-300 dark:border-yellow-700 rounded text-xs text-yellow-800 dark:text-yellow-300">
                                ⚠ Password file missing — restore will require the password you set previously.
                            </div>
                        )}
                    </div>

                    {actionError && (
                        <div className="p-3 bg-red-50 dark:bg-red-900/30 border border-red-300 dark:border-red-700 rounded text-red-800 dark:text-red-300 text-sm">
                            {actionError}
                        </div>
                    )}
                    {actionSuccess && (
                        <div className="p-3 bg-green-50 dark:bg-green-900/30 border border-green-300 dark:border-green-700 rounded text-green-800 dark:text-green-300 text-sm">
                            {actionSuccess}
                        </div>
                    )}

                    <div className="space-y-3">
                        <h4 className="text-sm font-semibold text-gray-900 dark:text-white">
                            {isStoredPassword ? 'Rotate backup password' : 'Set backup password'}
                        </h4>
                        <div>
                            <label className="block text-xs text-gray-600 dark:text-gray-400 mb-1">Password</label>
                            <input
                                type="password"
                                value={newPassword}
                                onChange={(e) => setNewPassword(e.target.value)}
                                disabled={submitting}
                                className="w-full px-3 py-2 bg-gray-50 dark:bg-gray-900 border border-gray-400 dark:border-gray-600 rounded text-sm text-gray-900 dark:text-white focus:outline-none focus:border-blue-500"
                                autoComplete="new-password"
                            />
                        </div>
                        <div>
                            <label className="block text-xs text-gray-600 dark:text-gray-400 mb-1">Confirm password</label>
                            <input
                                type="password"
                                value={confirmPassword}
                                onChange={(e) => setConfirmPassword(e.target.value)}
                                disabled={submitting}
                                className="w-full px-3 py-2 bg-gray-50 dark:bg-gray-900 border border-gray-400 dark:border-gray-600 rounded text-sm text-gray-900 dark:text-white focus:outline-none focus:border-blue-500"
                                autoComplete="new-password"
                            />
                        </div>
                        <p className="text-xs text-gray-600 dark:text-gray-400">
                            Minimum 12 characters. Must include a letter and a digit or symbol. Store this
                            password in a secure location — if lost, any backups created in this mode become
                            unrecoverable unless you also have the password file.
                        </p>
                        <button
                            onClick={handleSetPassword}
                            disabled={submitting || formInvalid}
                            className="px-4 py-2 bg-blue-600 hover:bg-blue-700 disabled:bg-gray-600 text-gray-900 dark:text-white text-sm font-medium rounded transition-colors"
                        >
                            {submitting
                                ? 'Working...'
                                : isStoredPassword
                                    ? 'Rotate Password'
                                    : 'Set Password & Enable StoredPassword Mode'}
                        </button>
                    </div>

                    {isStoredPassword && (
                        <div className="pt-4 border-t border-gray-300 dark:border-gray-700 space-y-2">
                            <button
                                onClick={() => setConfirmRevert(true)}
                                disabled={submitting}
                                className="px-4 py-2 bg-gray-200 dark:bg-gray-700 hover:bg-gray-300 dark:hover:bg-gray-600 disabled:bg-gray-600 text-gray-700 dark:text-gray-300 text-sm font-medium rounded transition-colors"
                            >
                                Revert to RandomKey mode
                            </button>
                            <p className="text-xs text-gray-600 dark:text-gray-400">
                                Deletes the password file. Existing archives remain restorable via the password.
                            </p>
                            <ConfirmModal
                                isOpen={confirmRevert}
                                title="Revert to RandomKey mode?"
                                message={
                                    <>
                                        <p>This deletes the password-derived KEK file and switches future backups to the random-key file.</p>
                                        <p className="mt-2">
                                            Archives already created in StoredPassword mode stay decryptable only with the password
                                            (if you remember it) or with a copy of the password file (if you saved one). Without either,
                                            they are lost.
                                        </p>
                                    </>
                                }
                                confirmLabel="Revert"
                                confirmClass="px-4 py-2 text-sm bg-yellow-600 text-white rounded hover:bg-yellow-700 transition-colors"
                                loading={submitting}
                                onConfirm={handleRevertToRandomKey}
                                onCancel={() => setConfirmRevert(false)}
                            />
                        </div>
                    )}
                </>
            )}

            {!loading && !status && actionError && (
                <div className="p-3 bg-red-50 dark:bg-red-900/30 border border-red-300 dark:border-red-700 rounded text-red-800 dark:text-red-300 text-sm">
                    {actionError}
                </div>
            )}
        </div>
    );
};

/* ─── Backup History Section ─── */
const BackupHistorySection: React.FC<{ backups: BackupEntry[]; loading: boolean; error: NoticeInput | null; onRefresh: () => void }> = ({ backups, loading, error, onRefresh }) => {
    return (
        <div className="bg-gray-100 dark:bg-gray-800 border border-gray-300 dark:border-gray-700 rounded-lg overflow-hidden">
            <div className="px-4 py-3 border-b border-gray-300 dark:border-gray-700 flex items-center justify-between">
                <h3 className="text-sm font-semibold text-gray-900 dark:text-white">Backup History</h3>
                <button
                    onClick={onRefresh}
                    className="px-3 py-1.5 bg-gray-200 dark:bg-gray-700 hover:bg-gray-300 dark:hover:bg-gray-600 text-gray-700 dark:text-gray-300 text-xs font-medium rounded transition-colors"
                >
                    Refresh
                </button>
            </div>

            {loading && <div className="p-4 text-sm text-gray-600 dark:text-gray-400 text-center">Loading...</div>}
            {error && <InlineNotice notice={error} />}

            {!loading && !error && backups.length === 0 && (
                <div className="p-4 text-sm text-gray-600 text-center">No backups found. Create one to get started.</div>
            )}

            {!loading && !error && backups.length > 0 && (
                <div className="overflow-x-auto">
                    <DataTable<any>
                        tableId="backups"
                        title="Backups"
                        rows={backups}
                        rowKey={(b) => b.fileName}
                        empty="No backups yet"
                        sort={{ key: 'created', dir: 'desc' }}
                        columns={[
                            { key: 'fileName', header: 'Filename', defaultWidth: 320, sortable: true, exportValue: (b) => b.fileName, render: (b) => <span className="font-mono text-xs text-gray-900 dark:text-white truncate">{b.fileName}</span> },
                            { key: 'created', header: 'Created (UTC)', defaultWidth: 180, sortable: true, sortValue: (b) => b.createdUtc ? new Date(b.createdUtc) : null, exportValue: (b) => formatDate(b.createdUtc), render: (b) => <span className="text-xs text-gray-600 dark:text-gray-400">{formatDate(b.createdUtc)}</span> },
                            { key: 'size', header: 'Size', defaultWidth: 110, align: 'right', sortable: true, sortValue: (b) => b.sizeBytes ?? null, exportValue: (b) => b.sizeBytes ?? '', render: (b) => <span className="text-xs text-gray-600 dark:text-gray-400 tabular-nums">{formatSize(b.sizeBytes)}</span> },
                        ] as DataTableColumn<any>[]}
                    />
                </div>
            )}
        </div>
    );
};

/* ─── Restore Section ─── */
const RestoreSection: React.FC<{ backups: BackupEntry[] }> = ({ backups }) => {
    const { requireStepUp } = useStepUp();
    const [selectedFile, setSelectedFile] = useState('');
    const [restoring, setRestoring] = useState(false);
    const [confirmRestore, setConfirmRestore] = useState(false);
    const [status, setStatus] = useState<string | null>(null);
    const [error, setError] = useState<NoticeInput | null>(null);
    const [recoveryPassword, setRecoveryPassword] = useState('');
    // Set once a restore has completed, so the "restart the application" instruction is a link
    // to the restart control rather than a sentence with nowhere to go.
    const [restored, setRestored] = useState(false);

    const handleRestore = async () => {
        if (!selectedFile) return;
        setRestoring(true);
        setStatus('Restoring from backup... This may take a moment.');
        setError(null);
        try {
            const result = await apiPostWithMfa<any>(
                '/api/v1/admin/backup/restore',
                {
                    fileName: selectedFile,
                    password: recoveryPassword ? recoveryPassword : undefined,
                },
                requireStepUp,
                StepUpOps.RestoreBackup,
                selectedFile,
            );
            setStatus(result.message || 'Restore complete. Restart the application to apply changes.');
            setRestored(true);
            setConfirmRestore(false);
            setRecoveryPassword('');
        } catch (err: any) {
            if (err.message === 'Step-up MFA cancelled') {
                setStatus(null);
                setConfirmRestore(false);
                setRestoring(false);
                return;
            }
            setError(errorNotice(err, 'The request failed.'));
            setStatus(null);
        } finally {
            setRestoring(false);
        }
    };

    return (
        <div className="bg-gray-100 dark:bg-gray-800 border border-gray-300 dark:border-gray-700 rounded-lg p-6 space-y-4">
            <h3 className="text-gray-900 dark:text-white font-semibold">Restore from Backup</h3>
            <p className="text-gray-600 dark:text-gray-400 text-sm">
                Restores the CA from a backup archive. This will overwrite the current database,
                keystores, and configuration.
            </p>

            <div className="bg-red-50 dark:bg-red-900/20 border border-red-300 dark:border-red-700 rounded p-3 text-sm text-red-800 dark:text-red-300">
                <strong>WARNING:</strong> Restore is a destructive operation. All current data will be replaced
                with the backup contents. The application will need to be restarted after restore completes
                (<RestartLink>Settings → General → Restart Application</RestartLink>).
                This action requires step-up MFA verification.
            </div>

            {backups.length > 0 ? (
                <div className="space-y-3">
                    <div>
                        <label className="block text-xs text-gray-600 dark:text-gray-400 mb-1">Select backup to restore</label>
                        <select
                            value={selectedFile}
                            onChange={(e) => { setSelectedFile(e.target.value); setConfirmRestore(false); }}
                            className="w-full px-3 py-2 bg-gray-50 dark:bg-gray-900 border border-gray-400 dark:border-gray-600 rounded text-sm text-gray-900 dark:text-white focus:outline-none focus:border-blue-500"
                        >
                            <option value="">-- Select a backup --</option>
                            {backups.map((b) => (
                                <option key={b.fileName} value={b.fileName}>
                                    {b.fileName} ({formatSize(b.sizeBytes)}) - {formatDate(b.createdUtc)}
                                </option>
                            ))}
                        </select>
                    </div>

                    {selectedFile && (
                        <div>
                            <label className="block text-xs text-gray-600 dark:text-gray-400 mb-1">
                                Recovery password <span className="text-gray-600">(optional)</span>
                            </label>
                            <input
                                type="password"
                                value={recoveryPassword}
                                onChange={(e) => setRecoveryPassword(e.target.value)}
                                placeholder="Leave blank unless restoring a StoredPassword archive without the key file"
                                autoComplete="off"
                                className="w-full px-3 py-2 bg-gray-50 dark:bg-gray-900 border border-gray-400 dark:border-gray-600 rounded text-sm text-gray-900 dark:text-white focus:outline-none focus:border-blue-500"
                            />
                            <p className="mt-1 text-xs text-gray-600 dark:text-gray-400">
                                Only needed for disaster recovery: supply the backup password that was set at creation time
                                when <code className="px-1 bg-gray-200 dark:bg-gray-900 rounded">config/backup-password.key</code>
                                is missing or was rotated to a different password. Ignored for RandomKey and legacy archives.
                            </p>
                        </div>
                    )}

                    {selectedFile && !confirmRestore && (
                        <button
                            onClick={() => setConfirmRestore(true)}
                            className="px-4 py-2 bg-red-600 hover:bg-red-700 text-gray-900 dark:text-white text-sm font-medium rounded transition-colors"
                        >
                            Restore from Selected Backup
                        </button>
                    )}

                    {confirmRestore && (
                        <div className="bg-red-50 dark:bg-red-900/30 border border-red-300 dark:border-red-600 rounded p-4 space-y-3">
                            <p className="text-red-800 dark:text-red-200 text-sm font-semibold">
                                Are you sure you want to restore from "{selectedFile}"?
                            </p>
                            <p className="text-red-800 dark:text-red-300 text-xs">
                                This will overwrite the current database, keystores, and configuration.
                                All current data will be permanently replaced. A restart is required afterward
                                (<RestartLink>Settings → General → Restart Application</RestartLink>).
                            </p>
                            <div className="flex gap-2">
                                <button
                                    onClick={handleRestore}
                                    disabled={restoring}
                                    className="px-4 py-2 bg-red-600 hover:bg-red-700 disabled:bg-gray-600 text-gray-900 dark:text-white text-sm font-medium rounded transition-colors"
                                >
                                    {restoring ? 'Restoring...' : 'Yes, Restore Now'}
                                </button>
                                <button
                                    onClick={() => setConfirmRestore(false)}
                                    disabled={restoring}
                                    className="px-4 py-2 bg-gray-200 dark:bg-gray-700 hover:bg-gray-300 dark:hover:bg-gray-600 text-gray-700 dark:text-gray-300 text-sm font-medium rounded transition-colors"
                                >
                                    Cancel
                                </button>
                            </div>
                        </div>
                    )}
                </div>
            ) : (
                <div className="text-sm text-gray-600">No backups available to restore from. Create a backup first.</div>
            )}

            {status && (
                <div className="p-3 bg-green-50 dark:bg-green-900/30 border border-green-300 dark:border-green-700 rounded text-green-800 dark:text-green-300 text-sm space-y-1">
                    <p>{status}</p>
                    {restored && (
                        <p>
                            The restored data is not in use until the service restarts:{' '}
                            <RestartLink>go to Settings → General → Restart Application</RestartLink>.
                        </p>
                    )}
                </div>
            )}
            {error && (
                <InlineNotice notice={error} />
            )}
        </div>
    );
};

/* ─── Backup & Restore Page ─── */
const BackupRestore: React.FC = () => {
    const [backups, setBackups] = useState<BackupEntry[]>([]);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState<NoticeInput | null>(null);

    const loadBackups = useCallback(() => {
        setLoading(true);
        setError(null);
        apiGet<BackupEntry[]>('/api/v1/admin/backup')
            .then((data) => setBackups(Array.isArray(data) ? data : []))
            .catch((err) => setError(errorNotice(err, 'The request failed.')))
            .finally(() => setLoading(false));
    }, []);

    useEffect(() => { loadBackups(); }, [loadBackups]);

    return (
        <div className="p-3 sm:p-6 space-y-4 sm:space-y-6">
            <h1 className="text-2xl font-bold text-gray-900 dark:text-white">Backup & Restore</h1>
            <CreateBackupSection onBackupCreated={loadBackups} />
            <BackupEncryptionSection />
            <BackupHistorySection backups={backups} loading={loading} error={error} onRefresh={loadBackups} />
            <RestoreSection backups={backups} />

            {/* System Info Card */}
            <div className="bg-gray-100 dark:bg-gray-800 border border-gray-300 dark:border-gray-700 rounded-lg p-6 space-y-4">
                <h3 className="text-gray-900 dark:text-white font-semibold">System Information</h3>
                <div className="grid grid-cols-2 gap-4 text-sm">
                    <div>
                        <span className="text-gray-600">API Endpoint</span>
                        <p className="text-gray-800 dark:text-gray-200 font-mono text-xs">{API_BASE}</p>
                    </div>
                    <div>
                        <span className="text-gray-600">Current Time (UTC)</span>
                        <p className="text-gray-800 dark:text-gray-200">{new Date().toUTCString()}</p>
                    </div>
                </div>
                <div className="bg-yellow-50 dark:bg-yellow-900/20 border border-yellow-300 dark:border-yellow-700 rounded p-3 text-sm text-yellow-800 dark:text-yellow-300">
                    <strong>CLI alternative:</strong> Backups can also be managed via the command line:
                    <code className="block mt-1 bg-gray-50 dark:bg-gray-900 p-2 rounded text-xs font-mono">
                        dotnet run --backup [output-path.zip]
                    </code>
                    <code className="block mt-1 bg-gray-50 dark:bg-gray-900 p-2 rounded text-xs font-mono">
                        dotnet run --restore backup-archive.zip
                    </code>
                </div>
            </div>
        </div>
    );
};

export default BackupRestore;
