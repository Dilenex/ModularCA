import React, { useEffect, useState } from 'react';
import { useAutoFocus } from '../hooks/useAutoFocus';

export interface DatabaseData {
    rootHost: string;
    rootPort: number;
    rootUsername: string;
    rootPassword: string;
    appDatabase: string;
    appUsername: string;
    auditDatabase: string;
    auditUsername: string;
    /** MySQL TLS mode. Round-trips to setup-database.yaml then to db.yaml. */
    sslMode: string;
    /**
     * Discard any existing audit history instead of preserving it. Defaults to false: audit
     * rows survive a reinstall, which is what makes them tamper-evidence rather than a log the
     * next install erases. Only has an effect when an audit database already exists on the host.
     */
    wipeAuditDatabase: boolean;
}

interface DatabaseConfigProps {
    data: DatabaseData;
    onChange: (data: DatabaseData) => void;
    setupToken: string;
    /** Whether setup-database.yaml is missing (passed from Welcome result). */
    needsDbConfig: boolean;
    /** Whether the DB has stale data from a previous run. */
    staleDb: boolean;
    onNext: () => void;
}

const inputClass = "w-full px-3 py-2 bg-white dark:bg-gray-900 border border-gray-300 dark:border-gray-700 rounded text-sm text-gray-900 dark:text-white placeholder-gray-400 dark:placeholder-gray-500 focus:outline-none focus:border-blue-500";
const labelClass = "block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1";

/// <summary>
/// Database configuration step. Auto-skips (calls onNext) when setup-database.yaml
/// already exists and the database is connected. Shows the DB form only when creds
/// are needed, and handles stale-DB recovery.
/// </summary>
const DatabaseConfig: React.FC<DatabaseConfigProps> = ({
    data, onChange, setupToken, needsDbConfig, staleDb, onNext,
}) => {
    const autoFocusRef = useAutoFocus<HTMLInputElement>();
    const [testingDb, setTestingDb] = useState(false);
    const [dbTestResult, setDbTestResult] = useState<{ connected: boolean; error?: string; databaseExists?: boolean } | null>(null);
    const [restarting, setRestarting] = useState(false);
    const [restartFailed, setRestartFailed] = useState(false);
    /** Set when the server ANSWERED and refused the save, as opposed to dropping the connection. */
    const [saveRejected, setSaveRejected] = useState<string | null>(null);
    const [droppingDb, setDroppingDb] = useState(false);
    const [dropResult, setDropResult] = useState<{ ok: boolean; message: string } | null>(null);
    const [autoSkipped, setAutoSkipped] = useState(false);
    /** Two-stage in-page confirmation for the destructive DROP. Replaces the prior
     * window.confirm() prompt — native browser dialogs block the event loop, can be
     * dismissed accidentally with the Esc key in some browsers, don't render in dark
     * mode, and aren't reachable from automated UI tests. The in-page flow keeps the
     * destructive action gated behind an explicit deliberate click. */
    const [showDropConfirm, setShowDropConfirm] = useState(false);

    const setupHeaders = (extra?: Record<string, string>): Record<string, string> => {
        const csrfToken = document.cookie.match(/(?:^|;\s*)CSRF-TOKEN=([^;]*)/)?.[1] || '';
        const headers: Record<string, string> = {
            'Content-Type': 'application/json',
            'X-CSRF-Token': decodeURIComponent(csrfToken),
            ...extra,
        };
        if (setupToken) headers['X-Setup-Token'] = setupToken;
        return headers;
    };

    // Auto-skip: if setup-database.yaml exists and DB is connected, advance immediately.
    useEffect(() => {
        if (!needsDbConfig && !staleDb && !autoSkipped) {
            setAutoSkipped(true);
            onNext();
        }
    }, [needsDbConfig, staleDb, autoSkipped, onNext]);

    const handleDropDatabases = async () => {
        setShowDropConfirm(false);
        setDroppingDb(true);
        setDropResult(null);
        try {
            const res = await fetch('/api/v1/setup/database/drop', {
                method: 'POST',
                headers: setupHeaders(),
            });
            const data = await res.json();
            if (res.ok) {
                setDropResult({ ok: true, message: data.message || 'Databases dropped.' });
                // After dropping, stale state is resolved — allow proceeding
            } else {
                setDropResult({ ok: false, message: data.error || `HTTP ${res.status}` });
            }
        } catch (err) {
            setDropResult({ ok: false, message: err instanceof Error ? err.message : 'Drop failed' });
        } finally {
            setDroppingDb(false);
        }
    };

    const handleTestDb = async () => {
        setTestingDb(true);
        setDbTestResult(null);
        try {
            const res = await fetch('/api/v1/setup/database/test', {
                method: 'POST',
                headers: setupHeaders(),
                body: JSON.stringify(data),
            });
            const result = await res.json();
            setDbTestResult(result);
        } catch (err) {
            setDbTestResult({ connected: false, error: err instanceof Error ? err.message : 'Test failed' });
        } finally {
            setTestingDb(false);
        }
    };

    const handleSaveAndRestart = async () => {
        setRestarting(true);
        setRestartFailed(false);
        setSaveRejected(null);

        try {
            // A dropped connection is the expected success path here: the server restarts to
            // pick up the new database configuration and never finishes the response. But a
            // response that ARRIVES and is not ok means the save was refused -- a 403 from CSRF,
            // a 400 from validation -- and the server is very much still running. That case used
            // to be swallowed with the connection drop, the status poll then succeeded
            // immediately because nothing had restarted, and the wizard advanced as though the
            // database had been configured.
            let rejection: string | null = null;
            try {
                const res = await fetch('/api/v1/setup/database/save', {
                    method: 'POST',
                    headers: setupHeaders(),
                    body: JSON.stringify(data),
                });
                if (!res.ok) {
                    let detail = '';
                    try {
                        const body = await res.json();
                        detail = body?.error || body?.detail || body?.message || '';
                    } catch { /* non-JSON body */ }
                    rejection = detail || `The server refused the save (HTTP ${res.status}).`;
                }
            } catch {
                // Connection dropped before a response — the server is restarting, as expected.
            }

            if (rejection !== null) {
                setSaveRejected(rejection);
                return;
            }

            // Poll until the server comes back (or give up after 30s)
            for (let i = 0; i < 15; i++) {
                await new Promise(r => setTimeout(r, 2000));
                try {
                    const res = await fetch('/api/v1/setup/status', { signal: AbortSignal.timeout(3000) });
                    if (res.ok) {
                        onNext();
                        return;
                    }
                } catch { /* server still restarting */ }
            }

            setRestartFailed(true);
        } finally {
            setRestarting(false);
        }
    };

    // If auto-skipping, show nothing (the useEffect will call onNext)
    if (!needsDbConfig && !staleDb) {
        return (
            <div className="flex items-center justify-center py-12">
                <svg className="animate-spin h-6 w-6 text-blue-500" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
                    <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                    <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
                </svg>
            </div>
        );
    }

    const canProceed = staleDb
        ? dropResult?.ok === true   // Must drop stale DBs first
        : dbTestResult?.connected === true;

    return (
        <div className="space-y-6">
            <div>
                <h2 className="text-2xl font-bold text-gray-900 dark:text-white">Database Configuration</h2>
                <p className="text-gray-600 dark:text-gray-400 mt-1">
                    {staleDb
                        ? 'An existing database was detected from a previous installation.'
                        : 'No database configuration was found. Enter your MySQL/MariaDB root credentials.'}
                </p>
            </div>

            {/* Stale DB recovery */}
            {staleDb && (
                <div className="bg-amber-50 dark:bg-amber-900/20 border border-amber-300 dark:border-amber-700 rounded-lg p-4 space-y-3">
                    <div>
                        <h3 className="text-sm font-semibold text-amber-800 dark:text-amber-200">Existing database detected</h3>
                        <p className="text-sm text-amber-700 dark:text-amber-300 mt-1">
                            The application database identified in <code className="bg-amber-100 dark:bg-amber-900/40 px-1 rounded">setup-database.yaml</code> already
                            contains certificate authorities from a previous installation. Drop the existing databases to start fresh,
                            or stop the wizard and back up the data first.
                        </p>
                    </div>
                    {!showDropConfirm && (
                        <div className="flex flex-col sm:flex-row items-start sm:items-center gap-3 sm:gap-4">
                            <button
                                onClick={() => { setDropResult(null); setShowDropConfirm(true); }}
                                disabled={droppingDb}
                                className="px-4 py-2 bg-red-600 hover:bg-red-700 disabled:bg-gray-400 dark:disabled:bg-gray-600 text-white text-sm font-medium rounded transition-colors disabled:cursor-not-allowed"
                            >
                                {droppingDb ? 'Dropping...' : 'Drop existing databases'}
                            </button>
                            {dropResult && (
                                <span className={`text-sm ${dropResult.ok ? 'text-green-600 dark:text-green-400' : 'text-red-600 dark:text-red-400'}`}>
                                    {dropResult.ok ? '\u2713 ' : '\u2717 '}{dropResult.message}
                                </span>
                            )}
                        </div>
                    )}

                    {/* Two-stage confirmation: replaces the prior window.confirm() so the
                        destructive DROP is gated by an explicit, dark-mode-friendly,
                        keyboard-accessible click rather than a native browser dialog. */}
                    {showDropConfirm && (
                        <div className="bg-red-50 dark:bg-red-900/30 border border-red-300 dark:border-red-700 rounded-lg p-4 space-y-3">
                            <div>
                                <h4 className="text-sm font-semibold text-red-800 dark:text-red-200">
                                    Permanently drop existing databases?
                                </h4>
                                <p className="text-sm text-red-700 dark:text-red-300 mt-1">
                                    This will <strong>permanently DROP</strong> the application database
                                    (<code className="bg-red-100 dark:bg-red-900/40 px-1 rounded">{data.appDatabase}</code>)
                                    and the audit database
                                    (<code className="bg-red-100 dark:bg-red-900/40 px-1 rounded">{data.auditDatabase}</code>),
                                    including all certificate authorities, audit logs, and settings from the previous installation.
                                    This action cannot be undone.
                                </p>
                            </div>
                            <div className="flex flex-col sm:flex-row items-start sm:items-center gap-3">
                                <button
                                    onClick={handleDropDatabases}
                                    disabled={droppingDb}
                                    className="px-4 py-2 bg-red-600 hover:bg-red-700 disabled:bg-gray-400 dark:disabled:bg-gray-600 text-white text-sm font-medium rounded transition-colors disabled:cursor-not-allowed"
                                >
                                    {droppingDb ? 'Dropping...' : 'Yes, drop databases permanently'}
                                </button>
                                <button
                                    onClick={() => setShowDropConfirm(false)}
                                    disabled={droppingDb}
                                    className="px-4 py-2 bg-white dark:bg-gray-800 border border-gray-300 dark:border-gray-600 text-gray-700 dark:text-gray-200 text-sm font-medium rounded hover:bg-gray-50 dark:hover:bg-gray-700 transition-colors disabled:cursor-not-allowed"
                                >
                                    Cancel
                                </button>
                            </div>
                        </div>
                    )}
                    {dropResult?.ok && (
                        <div className="text-center pt-2">
                            <button
                                onClick={onNext}
                                className="px-6 py-2 bg-blue-600 hover:bg-blue-700 text-white font-medium rounded-lg transition-colors"
                            >
                                Continue
                            </button>
                        </div>
                    )}
                </div>
            )}

            {/* Database Form — only when creds are needed */}
            {needsDbConfig && !staleDb && (
                <>
                    <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                        <div>
                            <label className={labelClass}>Host</label>
                            <input ref={autoFocusRef} type="text" value={data.rootHost}
                                onChange={e => onChange({ ...data, rootHost: e.target.value })}
                                placeholder="localhost" className={inputClass} />
                        </div>
                        <div>
                            <label className={labelClass}>Port</label>
                            <input type="text" inputMode="numeric" value={data.rootPort}
                                onChange={e => { const v = e.target.value.replace(/\D/g, ''); onChange({ ...data, rootPort: v === '' ? ('' as any) : parseInt(v) }); }}
                                onBlur={() => { if (!data.rootPort) onChange({ ...data, rootPort: 3306 }); }}
                                className={inputClass} />
                        </div>
                        <div>
                            <label className={labelClass}>Root Username</label>
                            <input type="text" value={data.rootUsername}
                                onChange={e => onChange({ ...data, rootUsername: e.target.value })}
                                placeholder="root" className={inputClass} />
                        </div>
                        <div>
                            <label className={labelClass}>Root Password</label>
                            <input type="password" value={data.rootPassword}
                                onChange={e => onChange({ ...data, rootPassword: e.target.value })}
                                placeholder="Enter root password" className={inputClass} />
                        </div>
                    </div>

                    {/* TLS mode — intentionally top-level (not inside Advanced) because
                        FISMA SC-8(1) / SC-28 make this a first-class deployment decision. */}
                    <div>
                        <label className={labelClass}>TLS Mode</label>
                        <select
                            value={data.sslMode}
                            onChange={e => onChange({ ...data, sslMode: e.target.value })}
                            className={inputClass}
                        >
                            <option value="Required">Required (recommended)</option>
                            <option value="Preferred">Preferred (TLS if available, plaintext fallback)</option>
                            <option value="VerifyCA">VerifyCA (TLS + CA chain validation)</option>
                            <option value="VerifyFull">VerifyFull (TLS + chain + hostname)</option>
                            <option value="None">None (unencrypted — not recommended)</option>
                        </select>
                        <p className="text-xs text-gray-500 dark:text-gray-400 mt-1">
                            FISMA SC-8(1) / SC-28 require <code>Required</code> or stronger. Choose
                            <code> None</code> only on a trusted loopback where MySQL is not configured for TLS.
                        </p>
                    </div>

                    {/* Advanced: database names */}
                    <details className="text-sm">
                        <summary className="text-gray-600 cursor-pointer hover:text-gray-700 dark:hover:text-gray-300">
                            Advanced: Database names &amp; app users
                        </summary>
                        <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 mt-3">
                            <div>
                                <label className={labelClass}>App Database Name</label>
                                <input type="text" value={data.appDatabase}
                                    onChange={e => onChange({ ...data, appDatabase: e.target.value })}
                                    className={inputClass} />
                            </div>
                            <div>
                                <label className={labelClass}>App DB Username</label>
                                <input type="text" value={data.appUsername}
                                    onChange={e => onChange({ ...data, appUsername: e.target.value })}
                                    className={inputClass} />
                            </div>
                            <div>
                                <label className={labelClass}>Audit Database Name</label>
                                <input type="text" value={data.auditDatabase}
                                    onChange={e => onChange({ ...data, auditDatabase: e.target.value })}
                                    className={inputClass} />
                            </div>
                            <div>
                                <label className={labelClass}>Audit DB Username</label>
                                <input type="text" value={data.auditUsername}
                                    onChange={e => onChange({ ...data, auditUsername: e.target.value })}
                                    className={inputClass} />
                            </div>
                            <div className="sm:col-span-2">
                                <label className="flex items-start gap-2 cursor-pointer">
                                    <input type="checkbox" checked={data.wipeAuditDatabase}
                                        onChange={e => onChange({ ...data, wipeAuditDatabase: e.target.checked })}
                                        className="mt-1" />
                                    <span>
                                        <span className="text-sm text-gray-900 dark:text-white">Erase existing audit history</span>
                                        <span className="block text-xs text-gray-600 dark:text-gray-400">
                                            Leave unchecked to keep audit records from a previous install on this host.
                                            Preserved history is what makes the audit trail tamper-evident across a
                                            reinstall; checking this destroys it permanently.
                                        </span>
                                    </span>
                                </label>
                            </div>
                        </div>
                    </details>

                    {/* Test Connection */}
                    <div className="flex flex-col sm:flex-row items-start sm:items-center gap-3 sm:gap-4">
                        <button
                            onClick={handleTestDb}
                            disabled={testingDb || !data.rootPassword}
                            className="px-4 py-2 bg-blue-600 hover:bg-blue-700 disabled:bg-gray-400 dark:disabled:bg-gray-600 text-white text-sm font-medium rounded transition-colors disabled:cursor-not-allowed"
                        >
                            {testingDb ? 'Testing...' : 'Test Connection'}
                        </button>
                        {dbTestResult && (
                            dbTestResult.connected ? (
                                <span className="text-sm text-green-600 dark:text-green-400">
                                    &#10003; Connected{dbTestResult.databaseExists ? ' (database exists)' : ' (database will be created)'}
                                </span>
                            ) : (
                                <span className="text-sm text-red-600 dark:text-red-400">
                                    &#10007; {dbTestResult.error || 'Connection failed'}
                                </span>
                            )
                        )}
                    </div>

                    {/* Save & Restart */}
                    {dbTestResult?.connected && (
                        <div className="text-center pt-2">
                            <button
                                onClick={handleSaveAndRestart}
                                disabled={restarting}
                                className="px-6 py-2 bg-blue-600 hover:bg-blue-700 disabled:bg-blue-400 dark:disabled:bg-blue-800 text-white font-medium rounded-lg transition-colors disabled:cursor-not-allowed"
                            >
                                {restarting ? 'Saving & restarting...' : 'Save & Continue'}
                            </button>
                        </div>
                    )}

                    {/* Restart status */}
                    {restarting && (
                        <div className="bg-blue-50 dark:bg-blue-900/20 border border-blue-200 dark:border-blue-800 rounded-lg p-4 text-center">
                            <div className="flex items-center justify-center gap-3">
                                <svg className="animate-spin h-5 w-5 text-blue-500" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
                                    <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                                    <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
                                </svg>
                                <span className="text-blue-700 dark:text-blue-300 font-medium">
                                    Database credentials saved. Server is restarting...
                                </span>
                            </div>
                        </div>
                    )}

                    {saveRejected && (
                        <div className="bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded-lg p-4">
                            <p className="text-red-800 dark:text-red-300 font-medium">Database configuration was not saved.</p>
                            <p className="text-red-700 dark:text-red-400 text-sm mt-1">{saveRejected}</p>
                            <p className="text-red-700 dark:text-red-400 text-sm mt-1">
                                Nothing has changed on the server. Correct the settings above and try again.
                            </p>
                        </div>
                    )}

                    {restartFailed && (
                        <div className="bg-amber-50 dark:bg-amber-900/20 border border-amber-200 dark:border-amber-800 rounded-lg p-4">
                            <p className="text-amber-800 dark:text-amber-300 font-medium">Database credentials saved. Server will restart with new TLS certificate. Please refresh your browser to access the setup page again.</p>
                            <p className="text-amber-700 dark:text-amber-400 text-sm mt-1">
                                If the page is still unavailable, verify the server restarted correctly.
                            </p>
                        </div>
                    )}
                </>
            )}
        </div>
    );
};

export default DatabaseConfig;
