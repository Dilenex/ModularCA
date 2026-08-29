import React, { useState, useEffect } from 'react';
import { useNavigate, useLocation, Link } from 'react-router-dom';
import { API_BASE } from '../api/client';
import { createDpopProof } from '@shared-auth/api/dpop';
import { useAuth } from '../context/AuthContext';

interface MfaVerifyState {
    mfaToken: string;
    method: string;
    availableMethods: string[];
}

const MfaVerify: React.FC = () => {
    const navigate = useNavigate();
    const location = useLocation();
    const state = location.state as MfaVerifyState | null;

    const [activeMethod, setActiveMethod] = useState<string>(state?.method || 'totp');
    const [totpCode, setTotpCode] = useState('');
    const [loading, setLoading] = useState(false);
    const [error, setError] = useState<string | null>(null);
    const [mtlsInfo, setMtlsInfo] = useState<{ enabled: boolean; subdomain?: string } | null>(null);

    useEffect(() => {
        fetch(`${API_BASE}/auth/mtls/auth-info`).then(r => r.json()).then(setMtlsInfo).catch(() => {});
    }, []);

    // If there is no MFA state, redirect back to login
    if (!state?.mfaToken) {
        return (
            <div className="flex justify-center items-center min-h-screen bg-gray-50 dark:bg-gray-900">
                <div className="bg-gray-100 dark:bg-gray-800 p-8 rounded-lg shadow-lg w-full max-w-md border border-gray-300 dark:border-gray-700 text-center space-y-4">
                    <p className="text-gray-700 dark:text-gray-300">MFA session expired or missing.</p>
                    <Link
                        to="/login"
                        className="inline-block text-blue-800 dark:text-blue-400 hover:text-blue-300"
                    >
                        Back to Login
                    </Link>
                </div>
            </div>
        );
    }

    const { mfaToken, availableMethods } = state;
    const methods = (availableMethods || [activeMethod]).filter(m => m !== 'mtls' || mtlsInfo?.enabled);

    const { refresh: refreshAuth } = useAuth();

    const storeTokensAndRedirect = async (data: { token: string; expiresAt: string; refreshToken: string }) => {
        localStorage.setItem('authToken', data.token);
        localStorage.setItem('expiresAt', data.expiresAt);
        localStorage.setItem('refreshToken', data.refreshToken);
        await refreshAuth();
        navigate('/dashboard');
    };

    const handleTotpVerify = async (e: React.FormEvent) => {
        e.preventDefault();
        setLoading(true);
        setError(null);
        try {
            const csrfMatch = document.cookie.match(/(?:^|;\s*)CSRF-TOKEN=([^;]*)/);
            const csrfHeaders: Record<string, string> = {};
            if (csrfMatch) csrfHeaders['X-CSRF-Token'] = decodeURIComponent(csrfMatch[1]);
            // Bind the session to this device's PoP key as MFA completes.
            const totpProof = await createDpopProof('POST', `${API_BASE}/auth/totp/verify`);
            if (totpProof) csrfHeaders['DPoP'] = totpProof;
            const resp = await fetch(`${API_BASE}/auth/totp/verify`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json', ...csrfHeaders },
                body: JSON.stringify({ mfaToken, code: totpCode }),
            });

            if (!resp.ok) {
                const err = await resp.json().catch(() => ({ error: `HTTP ${resp.status}` }));
                const msg = err.error || err.message || 'Verification failed';
                // Expired/invalid MFA token — redirect back to login
                if (resp.status === 401 && msg.toLowerCase().includes('mfa token')) {
                    navigate('/login', { replace: true });
                    return;
                }
                throw new Error(msg);
            }

            const data = await resp.json();
            storeTokensAndRedirect(data);
        } catch (err: any) {
            setError(err.message || 'Invalid verification code');
        } finally {
            setLoading(false);
        }
    };

    const handleMtlsVerify = async () => {
        if (!mtlsInfo?.enabled || !mtlsInfo.subdomain) return;
        setLoading(true);
        setError(null);
        try {
            // Hand off the MFA token to the backend via a short-lived cookie scoped to the
            // shared parent domain so the subsequent navigation to the mTLS subdomain
            // doesn't carry the token in the URL (referer headers, server logs, browser
            // history). Backend's prepare-redirect sets the cookie; the verify-redirect on
            // the mTLS subdomain reads it.
            const csrfMatch = document.cookie.match(/(?:^|;\s*)CSRF-TOKEN=([^;]*)/);
            const csrfHeaders: Record<string, string> = {};
            if (csrfMatch) csrfHeaders['X-CSRF-Token'] = decodeURIComponent(csrfMatch[1]);

            const prepResp = await fetch(`${API_BASE}/auth/mtls/prepare-redirect`, {
                method: 'POST',
                credentials: 'include',
                headers: { 'Content-Type': 'application/json', ...csrfHeaders },
                body: JSON.stringify({ mfaToken }),
            });
            if (!prepResp.ok) {
                const err = await prepResp.json().catch(() => ({ error: `HTTP ${prepResp.status}` }));
                throw new Error(err.error || err.message || 'Failed to prepare mTLS handoff');
            }

            window.location.href = `${mtlsInfo.subdomain}/auth/mtls/verify-redirect`;
        } catch (err: any) {
            setError(err.message || 'Failed to start mTLS verification');
            setLoading(false);
        }
    };

    const handleWebauthnVerify = async () => {
        setLoading(true);
        setError(null);
        try {
            // Get assertion options
            const csrfMatch = document.cookie.match(/(?:^|;\s*)CSRF-TOKEN=([^;]*)/);
            const csrfHeaders: Record<string, string> = {};
            if (csrfMatch) csrfHeaders['X-CSRF-Token'] = decodeURIComponent(csrfMatch[1]);
            const optionsResp = await fetch(`${API_BASE}/auth/webauthn/assertion-options`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json', ...csrfHeaders },
                body: JSON.stringify({ mfaToken }),
            });

            if (!optionsResp.ok) {
                const err = await optionsResp.json().catch(() => ({ error: `HTTP ${optionsResp.status}` }));
                throw new Error(err.error || err.message || 'Failed to get assertion options');
            }

            const options = await optionsResp.json();

            // Decode challenge and allowCredentials from base64url
            options.challenge = base64urlToBuffer(options.challenge);
            if (options.allowCredentials) {
                options.allowCredentials = options.allowCredentials.map((c: any) => ({
                    ...c,
                    id: base64urlToBuffer(c.id),
                }));
            }

            // Call browser credentials API
            const credential = (await navigator.credentials.get({
                publicKey: options,
            })) as PublicKeyCredential;

            if (!credential) {
                throw new Error('No credential returned from browser');
            }

            const assertionResponse = credential.response as AuthenticatorAssertionResponse;

            // Send assertion to server (bind the session to this device's PoP key on success).
            const waProof = await createDpopProof('POST', `${API_BASE}/auth/webauthn/assertion`);
            if (waProof) csrfHeaders['DPoP'] = waProof;
            const verifyResp = await fetch(`${API_BASE}/auth/webauthn/assertion`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json', ...csrfHeaders },
                body: JSON.stringify({
                    mfaToken,
                    assertionResponse: {
                        id: credential.id,
                        rawId: bufferToBase64url(credential.rawId),
                        type: credential.type,
                        response: {
                            authenticatorData: bufferToBase64url(assertionResponse.authenticatorData),
                            clientDataJSON: bufferToBase64url(assertionResponse.clientDataJSON),
                            signature: bufferToBase64url(assertionResponse.signature),
                            userHandle: assertionResponse.userHandle
                                ? bufferToBase64url(assertionResponse.userHandle)
                                : null,
                        },
                        clientExtensionResults: credential.getClientExtensionResults(),
                    },
                }),
            });

            if (!verifyResp.ok) {
                const err = await verifyResp.json().catch(() => ({ error: `HTTP ${verifyResp.status}` }));
                throw new Error(err.error || err.message || 'WebAuthn verification failed');
            }

            const data = await verifyResp.json();
            storeTokensAndRedirect(data);
        } catch (err: any) {
            if (err.name === 'NotAllowedError') {
                setError('Security key verification was cancelled or timed out.');
            } else {
                setError(err.message || 'Verification failed');
            }
        } finally {
            setLoading(false);
        }
    };

    return (
        <div className="flex justify-center items-center min-h-screen bg-gray-50 dark:bg-gray-900">
            <div className="bg-gray-100 dark:bg-gray-800 p-8 rounded-lg shadow-lg w-full max-w-md space-y-6 border border-gray-300 dark:border-gray-700">
                <h2 className="text-2xl font-semibold text-center text-gray-900 dark:text-white">
                    Two-Factor Authentication
                </h2>

                {/* Method selector tabs */}
                {methods.length > 1 && (
                    <div className="flex rounded overflow-hidden border border-gray-400 dark:border-gray-600">
                        {methods.map((m) => (
                            <button
                                key={m}
                                onClick={() => {
                                    setActiveMethod(m);
                                    setError(null);
                                }}
                                className={`flex-1 py-2 text-sm font-medium transition-colors ${
                                    activeMethod === m
                                        ? 'bg-blue-600 text-gray-900 dark:text-white'
                                        : 'bg-gray-200 dark:bg-gray-700 text-gray-700 dark:text-gray-300 hover:bg-gray-300 dark:hover:bg-gray-600'
                                }`}
                            >
                                {m === 'totp' ? 'Authenticator App' : m === 'mtls' ? 'Client Certificate' : 'Security Key'}
                            </button>
                        ))}
                    </div>
                )}

                {error && (
                    <div className="bg-red-50 dark:bg-red-900/50 border border-red-300 dark:border-red-700 text-red-800 dark:text-red-300 text-sm text-center p-2 rounded">
                        {error}
                    </div>
                )}

                {/* TOTP verification */}
                {activeMethod === 'totp' && (
                    <form onSubmit={handleTotpVerify} className="space-y-4">
                        <p className="text-sm text-gray-600 dark:text-gray-400 text-center">
                            Enter the 6-digit code from your authenticator app.
                        </p>
                        <div>
                            <input
                                type="text"
                                inputMode="numeric"
                                pattern="[0-9]*"
                                maxLength={6}
                                autoComplete="one-time-code"
                                className="w-full bg-gray-200 dark:bg-gray-700 border border-gray-400 dark:border-gray-600 text-gray-900 dark:text-white rounded px-3 py-3 focus:border-blue-500 focus:outline-none text-center text-2xl tracking-widest"
                                value={totpCode}
                                onChange={(e) => setTotpCode(e.target.value.replace(/\D/g, ''))}
                                placeholder="000000"
                                autoFocus
                                required
                            />
                        </div>
                        <button
                            type="submit"
                            disabled={loading || totpCode.length !== 6}
                            className="w-full bg-blue-600 text-gray-900 dark:text-white py-2 rounded hover:bg-blue-700 disabled:opacity-50 transition-colors"
                        >
                            {loading ? 'Verifying...' : 'Verify'}
                        </button>
                    </form>
                )}

                {/* WebAuthn verification */}
                {activeMethod === 'webauthn' && (
                    <div className="space-y-4">
                        <p className="text-sm text-gray-600 dark:text-gray-400 text-center">
                            Use your security key to verify your identity.
                        </p>
                        <button
                            onClick={handleWebauthnVerify}
                            disabled={loading}
                            className="w-full bg-blue-600 text-gray-900 dark:text-white py-2 rounded hover:bg-blue-700 disabled:opacity-50 transition-colors"
                        >
                            {loading ? 'Waiting for security key...' : 'Verify with Security Key'}
                        </button>
                    </div>
                )}

                {/* mTLS verification */}
                {activeMethod === 'mtls' && (
                    <div className="space-y-4">
                        <p className="text-sm text-gray-600 dark:text-gray-400 text-center">
                            Your browser will prompt you to select a client certificate.
                        </p>
                        <button
                            onClick={handleMtlsVerify}
                            disabled={loading}
                            className="w-full bg-blue-600 text-gray-900 dark:text-white py-2 rounded hover:bg-blue-700 disabled:opacity-50 transition-colors"
                        >
                            {loading ? 'Verifying certificate...' : 'Verify with Client Certificate'}
                        </button>
                        <p className="text-xs text-gray-600 text-center">
                            Make sure your mTLS certificate (.pfx) is imported in your browser's certificate store.
                        </p>
                    </div>
                )}

                <div className="text-center">
                    <Link
                        to="/login"
                        className="text-sm text-gray-600 dark:text-gray-400 hover:text-gray-700 dark:text-gray-300 transition-colors"
                    >
                        Back to Login
                    </Link>
                </div>
            </div>
        </div>
    );
};

// Utility: base64url string to ArrayBuffer
function base64urlToBuffer(base64url: string): ArrayBuffer {
    const base64 = base64url.replace(/-/g, '+').replace(/_/g, '/');
    const pad = base64.length % 4 === 0 ? '' : '='.repeat(4 - (base64.length % 4));
    const binary = atob(base64 + pad);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
        bytes[i] = binary.charCodeAt(i);
    }
    return bytes.buffer;
}

// Utility: ArrayBuffer to base64url string
function bufferToBase64url(buffer: ArrayBuffer): string {
    const bytes = new Uint8Array(buffer);
    let binary = '';
    for (let i = 0; i < bytes.byteLength; i++) {
        binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

export default MfaVerify;
