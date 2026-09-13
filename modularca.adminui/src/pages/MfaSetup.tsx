import React, { useState, useEffect } from 'react';
import { useNavigate, Navigate } from 'react-router-dom';
import { isAuthenticated, isMfaSetupRequired, setMfaSetupRequired } from '../components/auth';
import { apiGet, apiPost, apiLogout, apiBlob, clearTokens } from '../api/client';
import { generateQrSvg } from '@shared-auth/utils/qrcode';

interface AllowedCa {
    caId: string;
    caName: string;
    caLabel: string;
}

const MfaSetup: React.FC = () => {
    const navigate = useNavigate();

    // TOTP state
    const [totpSecret, setTotpSecret] = useState<string | null>(null);
    const [provisioningUri, setProvisioningUri] = useState<string | null>(null);
    const [totpCode, setTotpCode] = useState('');
    const [totpLoading, setTotpLoading] = useState(false);
    const [totpError, setTotpError] = useState<string | null>(null);
    const [totpSuccess, setTotpSuccess] = useState(false);

    // WebAuthn state
    const [webauthnLoading, setWebauthnLoading] = useState(false);
    const [webauthnError, setWebauthnError] = useState<string | null>(null);
    const [webauthnSuccess, setWebauthnSuccess] = useState(false);

    // mTLS state
    const [mtlsCas, setMtlsCas] = useState<AllowedCa[]>([]);
    const [mtlsSelectedCa, setMtlsSelectedCa] = useState<string>('');
    const [mtlsDeviceName, setMtlsDeviceName] = useState('');
    const [mtlsLoading, setMtlsLoading] = useState(false);
    const [mtlsError, setMtlsError] = useState<string | null>(null);
    const [mtlsSuccess, setMtlsSuccess] = useState(false);
    const [mtlsPassword, setMtlsPassword] = useState<string | null>(null);

    const webauthnAvailable = typeof window !== 'undefined' && !!window.PublicKeyCredential;

    // Load allowed CAs for mTLS enrollment
    useEffect(() => {
        apiGet<AllowedCa[]>('/auth/mtls/allowed-cas')
            .then((cas) => {
                // Array.isArray, not a truthiness check. `cas || []` accepted anything truthy,
                // and the API client returns the raw body as a string when a response does not
                // declare itself JSON — a string passes `||`, satisfies `.length > 1`, and then
                // has no `.map`, which crashed the whole page at render. The admin UI showed its
                // error boundary; the user UI, which has none, showed a white screen.
                const list = Array.isArray(cas) ? cas : [];
                setMtlsCas(list);
                if (list.length > 0) setMtlsSelectedCa(list[0].caId);
            })
            .catch(() => setMtlsCas([]));
    }, []);

    // Require authentication
    if (!isAuthenticated()) {
        return <Navigate to="/login" replace />;
    }

    // If MFA is already set up (no mfaSetupRequired flag), redirect to the security page.
    // Users should use /admin/security to manage MFA, not this page directly.
    if (!isMfaSetupRequired()) {
        return <Navigate to="/security" replace />;
    }

    const handleTotpSetup = async () => {
        setTotpLoading(true);
        setTotpError(null);
        try {
            const data = await apiPost<{ secret: string; provisioningUri: string }>(
                '/auth/totp/setup', {}
            );
            setTotpSecret(data.secret);
            setProvisioningUri(data.provisioningUri);
        } catch (err: any) {
            setTotpError(err.message || 'Failed to initialize TOTP setup');
        } finally {
            setTotpLoading(false);
        }
    };

    const handleTotpVerify = async (e: React.FormEvent) => {
        e.preventDefault();
        setTotpLoading(true);
        setTotpError(null);
        try {
            // Route through apiPost so auth + CSRF + refresh
            // is shared with every other request.
            await apiPost('/auth/totp/verify-setup', { code: totpCode });
            // Scrub the displayed shared secret from React state
            // immediately on successful verification.
            setTotpSecret(null);
            setProvisioningUri(null);
            setTotpCode('');
            setTotpSuccess(true);
            // Redirect after a brief delay so the user sees the success message.
            // Clear tokens and redirect in one step to avoid a race where the auth
            // context fires an API call with a stale token during the delay.
            setTimeout(() => { clearTokens(); window.location.href = '/admin/login'; }, 1500);
        } catch (err: any) {
            setTotpError(err.message || 'Invalid verification code');
        } finally {
            setTotpLoading(false);
        }
    };

    const handleWebauthnRegister = async () => {
        setWebauthnLoading(true);
        setWebauthnError(null);
        try {
            // Get registration options from the server
            const options = await apiPost<any>('/auth/webauthn/register-options');

            // Decode challenge and user.id from base64url
            options.challenge = base64urlToBuffer(options.challenge);
            if (options.user?.id) {
                options.user.id = base64urlToBuffer(options.user.id);
            }
            // Same defect one step later: a truthy non-array would reach .map and throw from
            // inside the registration handler.
            if (Array.isArray(options.excludeCredentials)) {
                options.excludeCredentials = options.excludeCredentials.map((c: any) => ({
                    ...c,
                    id: base64urlToBuffer(c.id),
                }));
            }

            // Call browser credentials API
            const credential = (await navigator.credentials.create({
                publicKey: options,
            })) as PublicKeyCredential;

            if (!credential) {
                throw new Error('No credential returned from browser');
            }

            const attestationResponse = credential.response as AuthenticatorAttestationResponse;
            const transports = typeof attestationResponse.getTransports === 'function' ? attestationResponse.getTransports() : [];

            // Send result to server
            await apiPost('/auth/webauthn/register', {
                id: credential.id,
                rawId: bufferToBase64url(credential.rawId),
                type: credential.type,
                response: {
                    attestationObject: bufferToBase64url(attestationResponse.attestationObject),
                    clientDataJSON: bufferToBase64url(attestationResponse.clientDataJSON),
                    transports,
                },
                clientExtensionResults: credential.getClientExtensionResults(),
            });

            setWebauthnSuccess(true);
            setTimeout(() => { clearTokens(); window.location.href = '/admin/login'; }, 1500);
        } catch (err: any) {
            if (err.name === 'NotAllowedError') {
                setWebauthnError('Security key registration was cancelled or timed out.');
            } else {
                setWebauthnError(err.message || 'Failed to register security key');
            }
        } finally {
            setWebauthnLoading(false);
        }
    };

    const handleMtlsEnroll = async () => {
        setMtlsLoading(true);
        setMtlsError(null);
        try {
            // Route through apiBlob so auth + CSRF + refresh
            // handling is shared with the rest of the SPA.
            const resp = await apiBlob('/auth/mtls/enroll', {
                method: 'POST',
                body: JSON.stringify({
                    caId: mtlsSelectedCa,
                    deviceName: mtlsDeviceName || undefined,
                }),
            });

            // Extract password from header
            const password = resp.headers.get('X-Pkcs12-Password');
            setMtlsPassword(password);

            // Download the PKCS#12 file
            const blob = await resp.blob();
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = 'mtls-credential.pfx';
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            URL.revokeObjectURL(url);

            setMtlsSuccess(true);
            // Don't clear mfaSetupRequired yet — the guard would redirect before
            // the user can see the password. It's cleared when they click "Log in".
        } catch (err: any) {
            setMtlsError(err.message || 'Failed to enroll client certificate');
        } finally {
            setMtlsLoading(false);
        }
    };

    // Scrub the displayed PKCS#12 password from React state
    // when the user dismisses or navigates away from the success view.
    const clearMtlsPassword = () => setMtlsPassword(null);

    return (
        <div className="flex justify-center items-start min-h-screen bg-gray-50 dark:bg-gray-900 py-12 px-4">
            <div className="w-full max-w-lg space-y-6">
                <div className="text-center">
                    <h2 className="text-2xl font-semibold text-gray-900 dark:text-white">
                        Multi-Factor Authentication Setup Required
                    </h2>
                    <p className="text-gray-600 dark:text-gray-400 mt-2">
                        Your account requires MFA. Set up at least one method to continue.
                    </p>
                </div>

                {/* TOTP Setup Card */}
                <div className="bg-gray-100 dark:bg-gray-800 p-6 rounded-lg shadow-lg border border-gray-300 dark:border-gray-700 space-y-4">
                    <h3 className="text-lg font-medium text-gray-900 dark:text-white">Authenticator App (TOTP)</h3>

                    {totpSuccess ? (
                        <div className="bg-green-50 dark:bg-green-900/50 border border-green-300 dark:border-green-700 text-green-800 dark:text-green-300 text-sm p-3 rounded">
                            Authenticator app configured successfully. Redirecting to login...
                        </div>
                    ) : !totpSecret ? (
                        <button
                            onClick={handleTotpSetup}
                            disabled={totpLoading}
                            className="w-full bg-blue-600 text-gray-900 dark:text-white py-2 rounded hover:bg-blue-700 disabled:opacity-50 transition-colors"
                        >
                            {totpLoading ? 'Setting up...' : 'Set up Authenticator App'}
                        </button>
                    ) : (
                        <form onSubmit={handleTotpVerify} className="space-y-4">
                            <div className="space-y-4">
                                <p className="text-sm text-gray-700 dark:text-gray-300">
                                    Scan the QR code with your authenticator app:
                                </p>
                                {provisioningUri && (
                                    <div className="flex justify-center bg-white p-4 rounded-lg mx-auto" style={{ width: 'fit-content' }}>
                                        <div dangerouslySetInnerHTML={{ __html: generateQrSvg(provisioningUri, 3, 2) }} />
                                    </div>
                                )}
                                <details className="text-sm">
                                    <summary className="text-gray-600 dark:text-gray-400 cursor-pointer hover:text-gray-700 dark:text-gray-300">
                                        Can't scan? Enter manually
                                    </summary>
                                    <div className="bg-gray-200 dark:bg-gray-700 p-3 rounded mt-2">
                                        <p className="text-xs text-gray-600 dark:text-gray-400 mb-1">Secret key:</p>
                                        <code className="text-sm text-yellow-800 dark:text-yellow-300 break-all select-all">
                                            {totpSecret}
                                        </code>
                                    </div>
                                </details>
                            </div>
                            <div>
                                <label className="block text-sm font-medium text-gray-700 dark:text-gray-300">
                                    Verification Code
                                </label>
                                <input
                                    type="text"
                                    inputMode="numeric"
                                    pattern="[0-9]*"
                                    maxLength={6}
                                    autoComplete="off"
                                    className="w-full bg-gray-200 dark:bg-gray-700 border border-gray-400 dark:border-gray-600 text-gray-900 dark:text-white rounded px-3 py-2 mt-1 focus:border-blue-500 focus:outline-none text-center text-lg tracking-widest"
                                    value={totpCode}
                                    onChange={(e) => setTotpCode(e.target.value.replace(/\D/g, ''))}
                                    placeholder="000000"
                                    required
                                />
                            </div>
                            <button
                                type="submit"
                                disabled={totpLoading || totpCode.length !== 6}
                                className="w-full bg-blue-600 text-gray-900 dark:text-white py-2 rounded hover:bg-blue-700 disabled:opacity-50 transition-colors"
                            >
                                {totpLoading ? 'Verifying...' : 'Verify'}
                            </button>
                        </form>
                    )}

                    {totpError && (
                        <div className="bg-red-50 dark:bg-red-900/50 border border-red-300 dark:border-red-700 text-red-800 dark:text-red-300 text-sm p-2 rounded">
                            {totpError}
                        </div>
                    )}
                </div>

                {/* WebAuthn Setup Card */}
                {webauthnAvailable && (
                    <div className="bg-gray-100 dark:bg-gray-800 p-6 rounded-lg shadow-lg border border-gray-300 dark:border-gray-700 space-y-4">
                        <h3 className="text-lg font-medium text-gray-900 dark:text-white">Security Key (WebAuthn)</h3>

                        {webauthnSuccess ? (
                            <div className="bg-green-50 dark:bg-green-900/50 border border-green-300 dark:border-green-700 text-green-800 dark:text-green-300 text-sm p-3 rounded">
                                Security key registered successfully. Redirecting to login...
                            </div>
                        ) : (
                            <button
                                onClick={handleWebauthnRegister}
                                disabled={webauthnLoading}
                                className="w-full bg-blue-600 text-gray-900 dark:text-white py-2 rounded hover:bg-blue-700 disabled:opacity-50 transition-colors"
                            >
                                {webauthnLoading ? 'Waiting for security key...' : 'Register Security Key'}
                            </button>
                        )}

                        {webauthnError && (
                            <div className="bg-red-50 dark:bg-red-900/50 border border-red-300 dark:border-red-700 text-red-800 dark:text-red-300 text-sm p-2 rounded">
                                {webauthnError}
                            </div>
                        )}
                    </div>
                )}

                {/* mTLS Certificate Setup Card */}
                {mtlsCas.length > 0 && (
                    <div className="bg-gray-100 dark:bg-gray-800 p-6 rounded-lg shadow-lg border border-gray-300 dark:border-gray-700 space-y-4">
                        <h3 className="text-lg font-medium text-gray-900 dark:text-white">Client Certificate (mTLS)</h3>
                        <p className="text-sm text-gray-600 dark:text-gray-400">
                            Enroll a client certificate signed by your organization's CA for certificate-based MFA.
                        </p>

                        {mtlsSuccess ? (
                            <div className="space-y-3">
                                <div className="bg-green-50 dark:bg-green-900/50 border border-green-300 dark:border-green-700 text-green-800 dark:text-green-300 text-sm p-3 rounded">
                                    Client certificate enrolled successfully.
                                </div>
                                {mtlsPassword && (
                                    <div className="bg-yellow-50 dark:bg-yellow-900/30 border border-yellow-300 dark:border-yellow-700 text-yellow-800 dark:text-yellow-300 text-sm p-3 rounded">
                                        <p className="font-semibold mb-1">PKCS#12 Password — save this before continuing!</p>
                                        <code className="text-lg tracking-wider select-all block mt-2 p-2 bg-gray-50 dark:bg-gray-900 rounded text-center">{mtlsPassword}</code>
                                        <p className="text-xs text-yellow-800 dark:text-yellow-400 mt-2">This password will not be shown again. You need it to import the certificate.</p>
                                    </div>
                                )}
                                <button
                                    onClick={() => { clearMtlsPassword(); setMfaSetupRequired(false); apiLogout(); }}
                                    className="w-full bg-green-600 text-gray-900 dark:text-white py-2 rounded hover:bg-green-700 transition-colors"
                                >
                                    I've saved the password — Log in with MFA
                                </button>
                            </div>
                        ) : (
                            <div className="space-y-4">
                                {mtlsCas.length > 1 && (
                                    <div>
                                        <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">Signing CA</label>
                                        <select
                                            value={mtlsSelectedCa}
                                            onChange={(e) => setMtlsSelectedCa(e.target.value)}
                                            className="w-full bg-gray-200 dark:bg-gray-700 border border-gray-400 dark:border-gray-600 text-gray-900 dark:text-white rounded px-3 py-2 focus:border-blue-500 focus:outline-none"
                                        >
                                            {mtlsCas.map((ca) => (
                                                <option key={ca.caId} value={ca.caId}>{ca.caName}</option>
                                            ))}
                                        </select>
                                    </div>
                                )}
                                {mtlsCas.length === 1 && (
                                    <div className="text-sm text-gray-600 dark:text-gray-400">
                                        Signed by: <span className="text-gray-900 dark:text-white">{mtlsCas[0].caName}</span>
                                    </div>
                                )}
                                <div>
                                    <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">Device Name (optional)</label>
                                    <input
                                        type="text"
                                        className="w-full bg-gray-200 dark:bg-gray-700 border border-gray-400 dark:border-gray-600 text-gray-900 dark:text-white rounded px-3 py-2 focus:border-blue-500 focus:outline-none"
                                        value={mtlsDeviceName}
                                        onChange={(e) => setMtlsDeviceName(e.target.value)}
                                        placeholder="e.g., Work Laptop"
                                    />
                                </div>
                                <button
                                    onClick={handleMtlsEnroll}
                                    disabled={mtlsLoading || !mtlsSelectedCa}
                                    className="w-full bg-blue-600 text-gray-900 dark:text-white py-2 rounded hover:bg-blue-700 disabled:opacity-50 transition-colors"
                                >
                                    {mtlsLoading ? 'Generating certificate...' : 'Enroll Client Certificate'}
                                </button>
                            </div>
                        )}

                        {mtlsError && (
                            <div className="bg-red-50 dark:bg-red-900/50 border border-red-300 dark:border-red-700 text-red-800 dark:text-red-300 text-sm p-2 rounded">
                                {mtlsError}
                            </div>
                        )}
                    </div>
                )}
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

export default MfaSetup;
