import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { apiLogin, apiChangePassword, apiGet } from '../api/client';
import { setMfaSetupRequired } from '../components/auth';
import { useAuth } from '../context/AuthContext';
import { rememberReturnUrl, consumeReturnUrl, homeFor, type PortalUser } from '../portal';

const Login: React.FC = () => {
    const navigate = useNavigate();
    const { refresh: refreshAuth } = useAuth();

    const [username, setUsername] = useState('');
    const [password, setPassword] = useState('');
    const [error, setError] = useState<string | null>(null);
    const [loading, setLoading] = useState(false);

    // Password change form state
    const [showPasswordChange, setShowPasswordChange] = useState(false);
    const [newPassword, setNewPassword] = useState('');
    const [confirmNewPassword, setConfirmNewPassword] = useState('');
    const [changeSuccess, setChangeSuccess] = useState<string | null>(null);
    const [mtlsInfo, setMtlsInfo] = useState<{ enabled: boolean; subdomain?: string } | null>(null);

    useEffect(() => {
        // A portal page that found no session sends the browser here with returnUrl. Keep it
        // for the end of the flow, which may pass through MFA pages that drop the query.
        rememberReturnUrl(new URLSearchParams(window.location.search).get('returnUrl'));
        apiGet('/auth/mtls/auth-info').then(setMtlsInfo).catch(() => {});
        // Pre-login banner gate: if the server has a banner configured and the user has not
        // acknowledged it in this browser session, bounce to the dedicated consent page.
        // The banner text no longer renders inline on this login form.
        apiGet<{ banner: string | null; title: string | null }>('/auth/login-banner')
            .then(d => {
                if (d.banner && sessionStorage.getItem('loginBannerAcknowledged') !== '1') {
                    navigate('/banner', { replace: true });
                }
            })
            .catch(() => { /* no banner configured or endpoint unreachable — fall through */ });
    }, [navigate]);

    /** Leaves the sign-in pages for a portal: the remembered returnUrl, else the account's home. */
    const finishSignIn = async () => {
        const me = await apiGet<PortalUser>('/api/v1/me').catch(() => null);
        window.location.replace(consumeReturnUrl() ?? homeFor(me));
    };

    const handleCertLogin = () => {
        if (!mtlsInfo?.enabled) return;
        const loginPath = '/auth/mtls/login-redirect';
        if (mtlsInfo.subdomain) {
            window.location.href = `${mtlsInfo.subdomain}${loginPath}`;
        }
    };

    const handleLogin = async (e: React.FormEvent) => {
        e.preventDefault();
        setLoading(true);
        setError(null);
        setChangeSuccess(null);

        try {
            const data = await apiLogin(username, password);

            if (data.requirePasswordChange) {
                // Password change required — show inline form
                setShowPasswordChange(true);
                setError(null);
            } else if (data.requiresMfa) {
                // MFA configured — clear any stale setup flag and redirect to verification
                setMfaSetupRequired(false);
                navigate('/mfa-verify', {
                    state: {
                        mfaToken: data.mfaToken,
                        method: data.method,
                        availableMethods: data.availableMethods,
                    },
                });
            } else if (data.mfaSetupRequired) {
                // First login, MFA not yet configured — redirect to setup
                await refreshAuth();
                navigate('/mfa-setup');
            } else {
                // Normal login. The portals live under their own basenames, so this is a full
                // navigation: back to where the browser was bounced from, or to the portal
                // that fits the account.
                setMfaSetupRequired(false);
                await finishSignIn();
            }
        } catch (err: any) {
            setError(err.message || 'Unexpected error');
        } finally {
            setLoading(false);
        }
    };

    const handlePasswordChange = async (e: React.FormEvent) => {
        e.preventDefault();
        setLoading(true);
        setError(null);
        setChangeSuccess(null);

        if (newPassword !== confirmNewPassword) {
            setError('New password and confirmation do not match');
            setLoading(false);
            return;
        }

        try {
            await apiChangePassword(username, password, newPassword, confirmNewPassword);
            setChangeSuccess('Password changed successfully. Logging in...');
            setShowPasswordChange(false);

            // Update the stored password to the new one and auto-retry login
            setPassword(newPassword);
            setNewPassword('');
            setConfirmNewPassword('');

            // Auto-retry login with the new password
            const data = await apiLogin(username, newPassword);
            if (data.requiresMfa) {
                setMfaSetupRequired(false);
                navigate('/mfa-verify', {
                    state: {
                        mfaToken: data.mfaToken,
                        method: data.method,
                        availableMethods: data.availableMethods,
                    },
                });
            } else if (data.mfaSetupRequired) {
                navigate('/mfa-setup');
            } else {
                setMfaSetupRequired(false);
                await finishSignIn();
            }
        } catch (err: any) {
            setError(err.message || 'Unexpected error');
        } finally {
            setLoading(false);
        }
    };

    return (
        <div className="flex justify-center items-center min-h-screen bg-gray-50 dark:bg-gray-900">
            {!showPasswordChange ? (
                <form
                    onSubmit={handleLogin}
                    className="bg-gray-100 dark:bg-gray-800 p-8 rounded-lg shadow-lg w-full max-w-md space-y-6 border border-gray-300 dark:border-gray-700"
                >
                    <h2 className="text-2xl font-semibold text-center text-gray-900 dark:text-white">ModularCA</h2>

                    {error && <div className="bg-red-50 dark:bg-red-900/50 border border-red-300 dark:border-red-700 text-red-800 dark:text-red-300 text-sm text-center p-2 rounded">{error}</div>}
                    {changeSuccess && <div className="bg-green-50 dark:bg-green-900/50 border border-green-300 dark:border-green-700 text-green-800 dark:text-green-300 text-sm text-center p-2 rounded">{changeSuccess}</div>}

                    <div>
                        <label className="block text-sm font-medium text-gray-700 dark:text-gray-300" htmlFor="login-username">Username</label>
                        <input
                            id="login-username"
                            name="username"
                            type="text"
                            autoComplete="username"
                            className="w-full bg-gray-200 dark:bg-gray-700 border border-gray-400 dark:border-gray-600 text-gray-900 dark:text-white rounded px-3 py-2 mt-1 focus:border-blue-500 focus:outline-none"
                            value={username}
                            onChange={e => setUsername(e.target.value)}
                            required
                        />
                    </div>

                    <div>
                        <label className="block text-sm font-medium text-gray-700 dark:text-gray-300" htmlFor="login-password">Password</label>
                        <input
                            id="login-password"
                            name="password"
                            type="password"
                            className="w-full bg-gray-200 dark:bg-gray-700 border border-gray-400 dark:border-gray-600 text-gray-900 dark:text-white rounded px-3 py-2 mt-1 focus:border-blue-500 focus:outline-none"
                            value={password}
                            onChange={e => setPassword(e.target.value)}
                            required
                            autoComplete="current-password"
                        />
                    </div>

                    <button
                        type="submit"
                        disabled={loading}
                        className="w-full bg-blue-600 text-gray-900 dark:text-white py-2 rounded hover:bg-blue-700 disabled:opacity-50 transition-colors"
                    >
                        {loading ? 'Logging in...' : 'Login'}
                    </button>

                    {mtlsInfo?.enabled && (
                        <>
                            <div className="flex items-center gap-3 my-4">
                                <div className="flex-1 h-px bg-gray-300 dark:bg-gray-700" />
                                <span className="text-xs text-gray-600">or</span>
                                <div className="flex-1 h-px bg-gray-300 dark:bg-gray-700" />
                            </div>
                            <button
                                onClick={handleCertLogin}
                                type="button"
                                className="w-full px-4 py-2 text-sm font-medium border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 text-gray-700 dark:text-gray-300 rounded hover:bg-gray-50 dark:hover:bg-gray-700 transition-colors flex items-center justify-center gap-2"
                            >
                                <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 7a2 2 0 012 2m4 0a6 6 0 01-7.743 5.743L11 17H9v2H7v2H4a1 1 0 01-1-1v-2.586a1 1 0 01.293-.707l5.964-5.964A6 6 0 1121 9z" /></svg>
                                Sign in with Certificate
                            </button>
                        </>
                    )}
                </form>
            ) : (
                <form
                    onSubmit={handlePasswordChange}
                    className="bg-gray-100 dark:bg-gray-800 p-8 rounded-lg shadow-lg w-full max-w-md space-y-6 border border-gray-300 dark:border-gray-700"
                >
                    <h2 className="text-2xl font-semibold text-center text-gray-900 dark:text-white">Password Change Required</h2>
                    <p className="text-sm text-gray-600 dark:text-gray-400 text-center">
                        You must change your password before continuing.
                    </p>

                    {error && <div className="bg-red-50 dark:bg-red-900/50 border border-red-300 dark:border-red-700 text-red-800 dark:text-red-300 text-sm text-center p-2 rounded">{error}</div>}

                    <div>
                        <label className="block text-sm font-medium text-gray-700 dark:text-gray-300">Current Password</label>
                        <input
                            type="password"
                            className="w-full bg-gray-200 dark:bg-gray-700 border border-gray-400 dark:border-gray-600 text-gray-600 dark:text-gray-400 rounded px-3 py-2 mt-1 focus:border-blue-500 focus:outline-none"
                            value={password}
                            readOnly
                            autoComplete="current-password"
                        />
                    </div>

                    <div>
                        <label className="block text-sm font-medium text-gray-700 dark:text-gray-300">New Password</label>
                        <input
                            type="password"
                            className="w-full bg-gray-200 dark:bg-gray-700 border border-gray-400 dark:border-gray-600 text-gray-900 dark:text-white rounded px-3 py-2 mt-1 focus:border-blue-500 focus:outline-none"
                            value={newPassword}
                            onChange={e => setNewPassword(e.target.value)}
                            required
                            autoFocus
                            autoComplete="new-password"
                        />
                    </div>

                    <div>
                        <label className="block text-sm font-medium text-gray-700 dark:text-gray-300">Confirm New Password</label>
                        <input
                            type="password"
                            className="w-full bg-gray-200 dark:bg-gray-700 border border-gray-400 dark:border-gray-600 text-gray-900 dark:text-white rounded px-3 py-2 mt-1 focus:border-blue-500 focus:outline-none"
                            value={confirmNewPassword}
                            onChange={e => setConfirmNewPassword(e.target.value)}
                            required
                            autoComplete="new-password"
                        />
                    </div>

                    <button
                        type="submit"
                        disabled={loading}
                        className="w-full bg-blue-600 text-gray-900 dark:text-white py-2 rounded hover:bg-blue-700 disabled:opacity-50 transition-colors"
                    >
                        {loading ? 'Changing password...' : 'Change Password'}
                    </button>

                    <button
                        type="button"
                        onClick={() => { setShowPasswordChange(false); setError(null); }}
                        className="w-full text-gray-600 dark:text-gray-400 hover:text-gray-900 dark:hover:text-white text-sm transition-colors"
                    >
                        Back to login
                    </button>
                </form>
            )}
        </div>
    );
};

export default Login;
