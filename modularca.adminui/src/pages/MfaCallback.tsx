import React, { useEffect, useState } from 'react';
import { API_BASE } from '../api/client';
import { useNavigate } from 'react-router-dom';

/**
 * Callback page for mTLS MFA verification. The server redirects here with
 * a one-time authorization code in the query string. This page exchanges
 * the code for JWT tokens via a POST request, stores them in localStorage,
 * and shows a disclaimer recommending TOTP/WebAuthn setup if mTLS is the
 * user's only MFA method.
 */
const MfaCallback: React.FC = () => {
    const navigate = useNavigate();
    const [showDisclaimer, setShowDisclaimer] = useState(false);

    useEffect(() => {
        const queryParams = new URLSearchParams(window.location.search);
        const code = queryParams.get('code');

        if (code) {
            // Exchange one-time authorization code for tokens
            const csrfMatch = document.cookie.match(/(?:^|;\s*)CSRF-TOKEN=([^;]*)/);
            const csrfHeaders: Record<string, string> = {};
            if (csrfMatch) csrfHeaders['X-CSRF-Token'] = decodeURIComponent(csrfMatch[1]);
            fetch(`${API_BASE}/auth/mtls/exchange`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json', ...csrfHeaders },
                body: JSON.stringify({ code }),
            })
            .then(r => { if (!r.ok) throw new Error('Exchange failed'); return r.json(); })
            .then(data => {
                localStorage.setItem('authToken', data.token);
                localStorage.setItem('expiresAt', data.expiresAt);
                localStorage.setItem('refreshToken', data.refreshToken);
                localStorage.removeItem('mfaSetupRequired');

                // Clear the code from the URL
                window.history.replaceState(null, '', '/admin/mfa-callback');

                // Show the mTLS-only disclaimer (user logged in with cert only)
                setShowDisclaimer(true);
            })
            .catch(() => navigate('/login?error=exchange_failed', { replace: true }));
            return;
        }

        // No valid code parameter — redirect to login
        navigate('/login?error=mfa_failed', { replace: true });
    }, [navigate]);

    if (showDisclaimer) {
        return (
            <div className="flex justify-center items-center min-h-screen bg-gray-50 dark:bg-gray-900 px-4">
                <div className="bg-gray-100 dark:bg-gray-800 p-8 rounded-lg shadow-lg w-full max-w-md border border-gray-300 dark:border-gray-700 space-y-5">
                    <div className="text-center">
                        <div className="text-green-800 dark:text-green-400 text-lg font-semibold">Authenticated with Client Certificate</div>
                    </div>

                    <div className="bg-yellow-50 dark:bg-yellow-900/30 border border-yellow-300 dark:border-yellow-700 rounded-lg p-4 space-y-2">
                        <p className="text-yellow-800 dark:text-yellow-300 text-sm font-semibold">Recommendation: Set up TOTP or a Security Key</p>
                        <p className="text-yellow-800 dark:text-yellow-200/80 text-xs leading-relaxed">
                            Your account currently uses only a client certificate for MFA.
                            Destructive operations (revoking CAs, deleting users, changing security settings)
                            require active step-up verification via TOTP or a security key —
                            client certificates alone cannot be used for step-up.
                        </p>
                        <p className="text-yellow-800 dark:text-yellow-200/80 text-xs leading-relaxed">
                            Without TOTP or WebAuthn configured, you will be unable to perform
                            sensitive administrative operations.
                        </p>
                    </div>

                    <div className="flex gap-3">
                        <button
                            onClick={() => navigate('/mfa-setup', { replace: true })}
                            className="flex-1 bg-blue-600 text-gray-900 dark:text-white py-2 rounded hover:bg-blue-700 transition-colors text-sm"
                        >
                            Set Up Now
                        </button>
                        <button
                            onClick={() => navigate('/dashboard', { replace: true })}
                            className="flex-1 bg-gray-200 dark:bg-gray-700 text-gray-700 dark:text-gray-300 py-2 rounded hover:bg-gray-300 dark:hover:bg-gray-600 transition-colors text-sm"
                        >
                            Skip for Now
                        </button>
                    </div>
                </div>
            </div>
        );
    }

    return (
        <div className="flex justify-center items-center min-h-screen bg-gray-50 dark:bg-gray-900">
            <div className="text-center space-y-3">
                <div className="text-gray-900 dark:text-white text-lg">Completing authentication...</div>
                <div className="text-gray-600 dark:text-gray-400 text-sm">You will be redirected shortly.</div>
            </div>
        </div>
    );
};

export default MfaCallback;
