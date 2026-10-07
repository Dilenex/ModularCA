import React, { useState, useEffect } from 'react';
import { useNavigate, Navigate } from 'react-router-dom';
import { isAuthenticated, isMfaSetupRequired, setMfaSetupRequired } from '../components/auth';
import { apiGet, apiPost, apiLogout, apiBlob, clearTokens } from '../api/client';
import { generateQrSvg } from '@shared-auth/utils/qrcode';
import { LOGIN_PATH } from '../portal';

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
    const [totpDeviceName, setTotpDeviceName] = useState('');
    const [totpCode, setTotpCode] = useState('');
    const [totpLoading, setTotpLoading] = useState(false);
    const [totpError, setTotpError] = useState<string | null>(null);
    const [totpSuccess, setTotpSuccess] = useState(false);
    /** One-time recovery codes returned by verify-setup. The server will never show them again. */
    const [recoveryCodes, setRecoveryCodes] = useState<string[]>([]);

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

    // If MFA is already set up (no mfaSetupRequired flag), redirect to the account page
    // (security is a tab there). MFA is managed from there, not from this page.
    if (!isMfaSetupRequired()) {
        return <Navigate to="/account" replace />;
    }

    const handleTotpSetup = async () => {
        setTotpLoading(true);
        setTotpError(null);
        try {
            const body: { deviceName?: string } = {};
            const trimmedName = totpDeviceName.trim();
            if (trimmedName.length > 0) body.deviceName = trimmedName;
            const data = await apiPost<{ secret: string; provisioningUri: string }>(
                '/auth/totp/setup', body
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
            //
            // verify-setup returns one-time recovery codes that the server hashes and never
            // reveals again. This page used to discard the whole response and redirect after
            // 1.5s, so the codes were generated, stored, and lost, leaving a user who lost
            // their authenticator with no way back in short of an admin MFA reset. (The
            // self-service portal had the fix before the two apps were merged.)
            const result: any = await apiPost('/auth/totp/verify-setup', { code: totpCode });
            const codes: string[] = Array.isArray(result?.recoveryCodes) ? result.recoveryCodes : [];
            // Scrub the displayed shared secret from React state
            // immediately on successful verification.
            setTotpSecret(null);
            setProvisioningUri(null);
            setTotpCode('');
            setRecoveryCodes(codes);
            setTotpSuccess(true);
            // Clear tokens now so no context fires an API call with a stale token while the
            // user reads the codes. Auto-redirect only when there is nothing to copy down.
            clearTokens();
            if (codes.length === 0) {
                setTimeout(() => { window.location.href = LOGIN_PATH; }, 1500);
            }
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
            setTimeout(() => { clearTokens(); window.location.href = LOGIN_PATH; }, 1500);
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
        <div className="flex justify-center items-start min-h-screen bg-ground py-12 px-4">
            <div className="w-full max-w-lg space-y-6">
                <div className="text-center">
                    <h2 className="text-2xl font-semibold text-ink">
                        Multi-Factor Authentication Setup Required
                    </h2>
                    <p className="text-ink-muted mt-2">
                        Your account requires MFA. Set up at least one method to continue.
                    </p>
                </div>

                {/* TOTP Setup Card */}
                <div className="bg-raised p-6 rounded-lg border border-line space-y-4">
                    <h3 className="text-lg font-medium text-ink">Authenticator App (TOTP)</h3>

                    {totpSuccess ? (
                        <div className="space-y-4">
                            <div className="bg-ok-soft border border-ok/40 text-ok text-sm p-3 rounded">
                                {recoveryCodes.length > 0
                                    ? 'Authenticator app configured successfully.'
                                    : 'Authenticator app configured successfully. Redirecting to login...'}
                            </div>
                            {recoveryCodes.length > 0 && (
                                <div className="bg-warn-soft border border-warn/40 rounded p-4 space-y-3">
                                    <p className="text-sm font-semibold text-warn">
                                        Save your recovery codes now — they will not be shown again.
                                    </p>
                                    <p className="text-xs text-warn">
                                        Each code works once. They are the only way back into your account if you
                                        lose your authenticator.
                                    </p>
                                    <ul className="grid grid-cols-2 gap-1 data-mono text-ink">
                                        {recoveryCodes.map((code) => (<li key={code}>{code}</li>))}
                                    </ul>
                                    <button
                                        type="button"
                                        onClick={() => { window.location.href = LOGIN_PATH; }}
                                        className="w-full bg-accent text-on-accent py-2 rounded hover:bg-accent-hover transition-colors"
                                    >
                                        I have saved my recovery codes — continue to login
                                    </button>
                                </div>
                            )}
                        </div>
                    ) : !totpSecret ? (
                        <div className="space-y-4">
                            <div>
                                <label className="block text-sm font-medium text-ink mb-1" htmlFor="totp-device-name">Device Name (optional)</label>
                                <input
                                    id="totp-device-name"
                                    type="text"
                                    className="w-full bg-raised border border-line-strong text-ink rounded px-3 py-2 focus:border-accent focus:outline-none"
                                    value={totpDeviceName}
                                    onChange={(e) => setTotpDeviceName(e.target.value)}
                                    placeholder="e.g., Authy on iPhone"
                                />
                            </div>
                            <button
                                onClick={handleTotpSetup}
                                disabled={totpLoading}
                                className="w-full bg-accent text-on-accent py-2 rounded hover:bg-accent-hover disabled:opacity-50 transition-colors"
                            >
                                {totpLoading ? 'Setting up...' : 'Set up Authenticator App'}
                            </button>
                        </div>
                    ) : (
                        <form onSubmit={handleTotpVerify} className="space-y-4">
                            <div className="space-y-4">
                                <p className="text-sm text-ink">
                                    Scan the QR code with your authenticator app:
                                </p>
                                {provisioningUri && (
                                    <div className="flex justify-center bg-white p-4 rounded-lg mx-auto" style={{ width: 'fit-content' }}>
                                        <div dangerouslySetInnerHTML={{ __html: generateQrSvg(provisioningUri, 3, 2) }} />
                                    </div>
                                )}
                                <details className="text-sm">
                                    <summary className="text-ink-muted cursor-pointer hover:text-ink">
                                        Can't scan? Enter manually
                                    </summary>
                                    <div className="bg-sunken p-3 rounded mt-2">
                                        <p className="text-xs text-ink-muted mb-1">Secret key:</p>
                                        <code className="text-sm text-warn break-all select-all">
                                            {totpSecret}
                                        </code>
                                    </div>
                                </details>
                            </div>
                            <div>
                                <label className="block text-sm font-medium text-ink">
                                    Verification Code
                                </label>
                                <input
                                    type="text"
                                    inputMode="numeric"
                                    pattern="[0-9]*"
                                    maxLength={6}
                                    autoComplete="off"
                                    className="w-full bg-raised border border-line-strong text-ink rounded px-3 py-2 mt-1 focus:border-accent focus:outline-none text-center text-lg tracking-widest"
                                    value={totpCode}
                                    onChange={(e) => setTotpCode(e.target.value.replace(/\D/g, ''))}
                                    placeholder="000000"
                                    required
                                />
                            </div>
                            <button
                                type="submit"
                                disabled={totpLoading || totpCode.length !== 6}
                                className="w-full bg-accent text-on-accent py-2 rounded hover:bg-accent-hover disabled:opacity-50 transition-colors"
                            >
                                {totpLoading ? 'Verifying...' : 'Verify'}
                            </button>
                        </form>
                    )}

                    {totpError && (
                        <div className="bg-crit-soft border border-crit/40 text-crit text-sm p-2 rounded">
                            {totpError}
                        </div>
                    )}
                </div>

                {/* WebAuthn Setup Card */}
                {webauthnAvailable && (
                    <div className="bg-raised p-6 rounded-lg border border-line space-y-4">
                        <h3 className="text-lg font-medium text-ink">Security Key (WebAuthn)</h3>

                        {webauthnSuccess ? (
                            <div className="bg-ok-soft border border-ok/40 text-ok text-sm p-3 rounded">
                                Security key registered successfully. Redirecting to login...
                            </div>
                        ) : (
                            <button
                                onClick={handleWebauthnRegister}
                                disabled={webauthnLoading}
                                className="w-full bg-accent text-on-accent py-2 rounded hover:bg-accent-hover disabled:opacity-50 transition-colors"
                            >
                                {webauthnLoading ? 'Waiting for security key...' : 'Register Security Key'}
                            </button>
                        )}

                        {webauthnError && (
                            <div className="bg-crit-soft border border-crit/40 text-crit text-sm p-2 rounded">
                                {webauthnError}
                            </div>
                        )}
                    </div>
                )}

                {/* mTLS Certificate Setup Card */}
                {mtlsCas.length > 0 && (
                    <div className="bg-raised p-6 rounded-lg border border-line space-y-4">
                        <h3 className="text-lg font-medium text-ink">Client Certificate (mTLS)</h3>
                        <p className="text-sm text-ink-muted">
                            Enroll a client certificate signed by your organization's CA for certificate-based MFA.
                        </p>

                        {mtlsSuccess ? (
                            <div className="space-y-3">
                                <div className="bg-ok-soft border border-ok/40 text-ok text-sm p-3 rounded">
                                    Client certificate enrolled successfully.
                                </div>
                                {mtlsPassword && (
                                    <div className="bg-warn-soft border border-warn/40 text-warn text-sm p-3 rounded">
                                        <p className="font-semibold mb-1">PKCS#12 Password — save this before continuing!</p>
                                        <code className="text-lg tracking-wider select-all block mt-2 p-2 bg-sunken rounded text-center">{mtlsPassword}</code>
                                        <p className="text-xs text-warn mt-2">This password will not be shown again. You need it to import the certificate.</p>
                                    </div>
                                )}
                                <button
                                    onClick={() => { clearMtlsPassword(); setMfaSetupRequired(false); apiLogout(); }}
                                    className="w-full bg-ok text-on-accent py-2 rounded hover:bg-ok-hover transition-colors"
                                >
                                    I've saved the password — Log in with MFA
                                </button>
                            </div>
                        ) : (
                            <div className="space-y-4">
                                {mtlsCas.length > 1 && (
                                    <div>
                                        <label className="block text-sm font-medium text-ink mb-1">Signing CA</label>
                                        <select
                                            value={mtlsSelectedCa}
                                            onChange={(e) => setMtlsSelectedCa(e.target.value)}
                                            className="w-full bg-raised border border-line-strong text-ink rounded px-3 py-2 focus:border-accent focus:outline-none"
                                        >
                                            {mtlsCas.map((ca) => (
                                                <option key={ca.caId} value={ca.caId}>{ca.caName}</option>
                                            ))}
                                        </select>
                                    </div>
                                )}
                                {mtlsCas.length === 1 && (
                                    <div className="text-sm text-ink-muted">
                                        Signed by: <span className="text-ink">{mtlsCas[0].caName}</span>
                                    </div>
                                )}
                                <div>
                                    <label className="block text-sm font-medium text-ink mb-1">Device Name (optional)</label>
                                    <input
                                        type="text"
                                        className="w-full bg-raised border border-line-strong text-ink rounded px-3 py-2 focus:border-accent focus:outline-none"
                                        value={mtlsDeviceName}
                                        onChange={(e) => setMtlsDeviceName(e.target.value)}
                                        placeholder="e.g., Work Laptop"
                                    />
                                </div>
                                <button
                                    onClick={handleMtlsEnroll}
                                    disabled={mtlsLoading || !mtlsSelectedCa}
                                    className="w-full bg-accent text-on-accent py-2 rounded hover:bg-accent-hover disabled:opacity-50 transition-colors"
                                >
                                    {mtlsLoading ? 'Generating certificate...' : 'Enroll Client Certificate'}
                                </button>
                            </div>
                        )}

                        {mtlsError && (
                            <div className="bg-crit-soft border border-crit/40 text-crit text-sm p-2 rounded">
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
