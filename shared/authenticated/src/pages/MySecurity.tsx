/**
 * Self-service MFA management: TOTP, security keys and mTLS credentials.
 *
 * Shared because the two copies were ~600 lines at 4% divergence, and the divergence was a bug —
 * running the OPPOSITE way from the DataTable one. userui captured the one-time TOTP recovery
 * codes the server returns from /auth/totp/verify and displayed them; adminui awaited the same
 * call without binding its result and reported success. The server hashes those codes and never
 * reveals them again, so an administrator who enrolled TOTP through the admin UI was left with no
 * way back into the most privileged account on the CA if they lost their authenticator.
 *
 * This version is userui's. adminui contributed nothing the other lacked: its only extra import,
 * useNavigate, was never called.
 */
import React, { useState, useEffect } from 'react';
import { useAuthClient } from '../api/AuthClientContext';
import { useStepUp } from '../components/StepUpMfaContext';
import { generateQrSvg } from '../utils/qrcode';
import { StepUpOps } from '@shared/generated';

interface TotpStatus { enrolled: boolean; deviceName?: string; registeredAt?: string; lastUsedAt?: string; }
interface WebAuthnCred { id: string; deviceName?: string; registeredAt: string; lastUsedAt?: string; }
interface MtlsCred { id: string; deviceName?: string; serialNumber: string; issuedAt: string; expiresAt: string; signingCaId: string; }
interface MfaStatus { totp: TotpStatus; webauthn: { enrolled: boolean; credentials: WebAuthnCred[] }; mtls: { enrolled: boolean; credentials: MtlsCred[] }; hasStepUpCapability: boolean; }
interface AllowedCa { caId: string; caName: string; caLabel: string; }

const MAX_WEBAUTHN_KEYS = 3;

export const MySecurity: React.FC<{ embedded?: boolean }> = ({ embedded = false }) => {
    const { apiGet, apiPost, apiPostWithMfa, api, apiBlobWithMfa } = useAuthClient();
    const { requireStepUp } = useStepUp();
    const [mfa, setMfa] = useState<MfaStatus | null>(null);
    const [allowedCas, setAllowedCas] = useState<AllowedCa[]>([]);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState<string | null>(null);
    const [actionMsg, setActionMsg] = useState<string | null>(null);

    // TOTP setup state
    const [totpSetupActive, setTotpSetupActive] = useState(false);
    const [totpSecret, setTotpSecret] = useState<string | null>(null);
    const [provisioningUri, setProvisioningUri] = useState<string | null>(null);
    const [totpCode, setTotpCode] = useState('');
    const [totpLoading, setTotpLoading] = useState(false);
    /** One-time TOTP recovery codes; shown once, then never again by the server. */
    const [recoveryCodes, setRecoveryCodes] = useState<string[]>([]);
    const [totpDeviceName, setTotpDeviceName] = useState('');

    // WebAuthn setup state
    const [webauthnLoading, setWebauthnLoading] = useState(false);
    const [webauthnDeviceName, setWebauthnDeviceName] = useState('');

    // TOTP confirmation modal state
    const [totpModalOpen, setTotpModalOpen] = useState(false);
    const [totpModalCode, setTotpModalCode] = useState('');
    const [totpModalTitle, setTotpModalTitle] = useState('');
    const [totpModalLoading, setTotpModalLoading] = useState(false);
    const [totpModalCallback, setTotpModalCallback] = useState<((code: string) => Promise<void>) | null>(null);

    // mTLS enrollment state
    const [mtlsSelectedCa, setMtlsSelectedCa] = useState('');
    const [mtlsDeviceName, setMtlsDeviceName] = useState('');
    const [mtlsEnrolling, setMtlsEnrolling] = useState(false);
    const [mtlsPassword, setMtlsPassword] = useState<string | null>(null);

    const webauthnAvailable = typeof window !== 'undefined' && !!window.PublicKeyCredential;

    const loadMfaStatus = () => {
        setLoading(true);
        Promise.all([
            apiGet<MfaStatus>('/api/v1/account/mfa'),
            apiGet<AllowedCa[]>('/auth/mtls/allowed-cas').catch(() => [] as AllowedCa[]),
        ]).then(([status, cas]) => {
            setMfa(status);
            setAllowedCas(cas);
            if (cas.length > 0 && !mtlsSelectedCa) setMtlsSelectedCa(cas[0].caId);
        }).catch(err => setError(err.message))
          .finally(() => setLoading(false));
    };

    useEffect(() => { loadMfaStatus(); }, []);

    const showMsg = (msg: string) => { setActionMsg(msg); setTimeout(() => setActionMsg(null), 4000); };

    /// Opens the TOTP confirmation modal and invokes the callback with the entered code.
    const openTotpModal = (title: string, callback: (code: string) => Promise<void>) => {
        setTotpModalTitle(title);
        setTotpModalCode('');
        setTotpModalLoading(false);
        setTotpModalCallback(() => callback);
        setTotpModalOpen(true);
    };

    const handleTotpModalConfirm = async () => {
        if (!totpModalCallback || totpModalCode.length !== 6) return;
        setTotpModalLoading(true);
        try {
            await totpModalCallback(totpModalCode);
            setTotpModalOpen(false);
        } catch (err: any) {
            setError(err.message);
            setTotpModalLoading(false);
        }
    };

    const closeTotpModal = () => {
        if (totpModalLoading) return;
        setTotpModalOpen(false);
    };

    // ── TOTP ──

    const handleTotpSetup = async () => {
        setTotpLoading(true);
        setError(null);
        try {
            // Backend requires step-up when the user already has another MFA factor;
            // apiPostWithMfa catches the `requiresStepUp` 403 and retries with X-MFA-Token.
            const data = await apiPostWithMfa<{ secret: string; provisioningUri: string }>(
                '/auth/totp/setup',
                { deviceName: totpDeviceName || undefined },
                requireStepUp,
                StepUpOps.TotpSetup
            );
            setTotpSecret(data.secret);
            setProvisioningUri(data.provisioningUri);
            setTotpSetupActive(true);
        } catch (err: any) {
            if (err.message !== 'Step-up MFA cancelled') setError(err.message);
        }
        finally { setTotpLoading(false); }
    };

    const handleTotpVerify = async (e: React.FormEvent) => {
        e.preventDefault();
        setTotpLoading(true);
        setError(null);
        try {
            // Capture the one-time recovery codes: the server hashes them and never reveals
            // them again, so discarding the response here left the user with no way back in
            // after losing their authenticator.
            const result: any = await apiPostWithMfa(
                '/auth/totp/verify-setup',
                { code: totpCode },
                requireStepUp,
                StepUpOps.TotpVerifySetup
            );
            const codes: string[] = Array.isArray(result?.recoveryCodes) ? result.recoveryCodes : [];
            setRecoveryCodes(codes);
            showMsg(codes.length > 0
                ? 'Authenticator app enrolled. Save your recovery codes below — they will not be shown again.'
                : 'Authenticator app enrolled successfully');
            setTotpSetupActive(false);
            setTotpSecret(null);
            setProvisioningUri(null);
            setTotpCode('');
            setTotpDeviceName('');
            loadMfaStatus();
        } catch (err: any) {
            if (err.message !== 'Step-up MFA cancelled') setError(err.message);
        }
        finally { setTotpLoading(false); }
    };

    const handleRemoveTotp = () => {
        openTotpModal('Confirm TOTP Removal', async (code: string) => {
            const stepUp = await apiPost<{ mfaToken: string }>('/auth/mfa/verify-stepup/totp', { code, operation: 'totp-remove', targetId: null });
            await api('/auth/totp', { method: 'DELETE', headers: { 'X-MFA-Token': stepUp.mfaToken } });
            showMsg('TOTP removed');
            loadMfaStatus();
        });
    };

    // ── WebAuthn ──

    const handleWebauthnRegister = async () => {
        setWebauthnLoading(true);
        setError(null);
        try {
            const options = await apiPost<any>('/auth/webauthn/register-options');
            options.challenge = base64urlToBuffer(options.challenge);
            if (options.user?.id) options.user.id = base64urlToBuffer(options.user.id);
            if (options.excludeCredentials) {
                options.excludeCredentials = options.excludeCredentials.map((c: any) => ({
                    ...c, id: base64urlToBuffer(c.id),
                }));
            }

            const credential = (await navigator.credentials.create({ publicKey: options })) as PublicKeyCredential;
            if (!credential) throw new Error('No credential returned');

            const attestation = credential.response as AuthenticatorAttestationResponse;
            const transports = typeof attestation.getTransports === 'function' ? attestation.getTransports() : [];
            await apiPostWithMfa(
                `/auth/webauthn/register?deviceName=${encodeURIComponent(webauthnDeviceName || 'Security Key')}`,
                {
                    id: credential.id,
                    rawId: bufferToBase64url(credential.rawId),
                    type: credential.type,
                    response: {
                        attestationObject: bufferToBase64url(attestation.attestationObject),
                        clientDataJSON: bufferToBase64url(attestation.clientDataJSON),
                        transports,
                    },
                    clientExtensionResults: credential.getClientExtensionResults(),
                },
                requireStepUp,
                StepUpOps.WebAuthnRegister
            );

            showMsg('Security key registered');
            setWebauthnDeviceName('');
            loadMfaStatus();
        } catch (err: any) {
            if (err.name === 'NotAllowedError') setError('Security key registration was cancelled or timed out.');
            else if (err.message !== 'Step-up MFA cancelled') setError(err.message || 'Failed to register security key');
        } finally { setWebauthnLoading(false); }
    };

    const handleRemoveWebauthn = (credId: string) => {
        if (!confirm('Remove this security key?')) return;
        openTotpModal('Confirm Security Key Removal', async (code: string) => {
            const stepUp = await apiPost<{ mfaToken: string }>('/auth/mfa/verify-stepup/totp', { code, operation: 'webauthn-delete', targetId: credId });
            await api(`/auth/webauthn/credentials/${credId}`, { method: 'DELETE', headers: { 'X-MFA-Token': stepUp.mfaToken } });
            showMsg('Security key removed');
            loadMfaStatus();
        });
    };

    // ── mTLS ──

    const handleMtlsEnroll = async () => {
        setMtlsEnrolling(true);
        setMtlsPassword(null);
        try {
            // apiBlobWithMfa handles auth + CSRF + refresh + step-up retry uniformly with
            // the rest of the SPA. The backend returns 403 with requiresStepUp when the
            // user already has another MFA factor; the helper re-prompts and retries.
            const resp = await apiBlobWithMfa(
                '/auth/mtls/enroll',
                {
                    method: 'POST',
                    body: JSON.stringify({ caId: mtlsSelectedCa, deviceName: mtlsDeviceName || undefined }),
                },
                requireStepUp,
                StepUpOps.MtlsEnroll
            );
            const password = resp.headers.get('X-Pkcs12-Password');
            setMtlsPassword(password);
            const blob = await resp.blob();
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url; a.download = `mtls-${mtlsDeviceName || 'credential'}.pfx`;
            document.body.appendChild(a); a.click(); document.body.removeChild(a);
            URL.revokeObjectURL(url);
            setMtlsDeviceName('');
            showMsg('mTLS certificate enrolled');
            loadMfaStatus();
        } catch (err: any) {
            if (err.message !== 'Step-up MFA cancelled') setError(err.message);
        }
        finally { setMtlsEnrolling(false); }
    };

    const handleRevokeMtls = (credId: string) => {
        if (!confirm('Revoke this client certificate?')) return;
        openTotpModal('Confirm mTLS Revocation', async (code: string) => {
            const stepUp = await apiPost<{ mfaToken: string }>('/auth/mfa/verify-stepup/totp', { code, operation: 'mtls-delete', targetId: credId });
            await api(`/auth/mtls/credentials/${credId}`, { method: 'DELETE', headers: { 'X-MFA-Token': stepUp.mfaToken } });
            showMsg('mTLS credential revoked');
            loadMfaStatus();
        });
    };

    const formatDate = (d?: string | null) => d ? new Date(d).toLocaleString() : 'Never';

    if (loading && !mfa) return <div className="p-6 text-ink-muted">Loading MFA status...</div>;

    const webauthnCount = mfa?.webauthn.credentials.length || 0;
    const canAddWebauthn = webauthnAvailable && webauthnCount < MAX_WEBAUTHN_KEYS;

    return (
        <div className={embedded ? 'space-y-6' : 'p-6 max-w-3xl mx-auto space-y-6'}>
            {!embedded && (
                <div>
                    <h1 className="text-xl font-semibold text-ink">My Security</h1>
                    <p className="text-sm text-ink-muted mt-1">Manage your multi-factor authentication methods and account security.</p>
                </div>
            )}

            {error && <div className="bg-crit-soft border border-crit/40 text-crit text-sm p-3 rounded">{error} <button onClick={() => setError(null)} className="ml-2 text-crit underline">dismiss</button></div>}
            {actionMsg && <div className="bg-ok-soft border border-ok/40 text-ok text-sm p-3 rounded">{actionMsg}</div>}

            {mfa && !mfa.hasStepUpCapability && (
                <div className="bg-warn-soft border border-warn/40 rounded-lg p-4 space-y-2">
                    <p className="text-warn text-sm font-semibold">Step-up MFA not available</p>
                    <p className="text-warn text-xs">You need TOTP or a security key to perform destructive operations. mTLS alone is not sufficient for step-up verification. Set up one of the methods below.</p>
                </div>
            )}

            {/* ── TOTP ── */}
            <div className="bg-raised border border-line rounded-lg p-5 space-y-4">
                {recoveryCodes.length > 0 && (
                    <div className="bg-warn-soft border border-warn/40 rounded p-4 space-y-3">
                        <p className="text-sm font-semibold text-warn">
                            Save your recovery codes now — they will not be shown again.
                        </p>
                        <p className="text-xs text-warn">
                            Each code works once, and they are the only way back into your account if you lose
                            your authenticator.
                        </p>
                        <ul className="grid grid-cols-2 gap-1 data-mono text-ink">
                            {recoveryCodes.map((code) => (<li key={code}>{code}</li>))}
                        </ul>
                        <button
                            type="button"
                            onClick={() => setRecoveryCodes([])}
                            className="text-xs px-3 py-1.5 rounded bg-warn text-on-accent hover:bg-warn-hover transition-colors"
                        >
                            I have saved them — dismiss
                        </button>
                    </div>
                )}
                <div className="flex items-center justify-between">
                    <h2 className="text-sm font-semibold text-ink">Authenticator App (TOTP)</h2>
                    {mfa?.totp.enrolled ? (
                        <span className="text-xs px-2 py-0.5 rounded bg-ok-soft text-ok border border-ok/40">Enrolled</span>
                    ) : (
                        <span className="text-xs px-2 py-0.5 rounded bg-sunken text-ink-muted border border-line-strong">Not enrolled</span>
                    )}
                </div>

                {mfa?.totp.enrolled ? (
                    <div className="space-y-2">
                        <div className="text-xs text-ink-muted space-y-1">
                            {mfa.totp.deviceName && <div>Device: <span className="text-ink">{mfa.totp.deviceName}</span></div>}
                            <div>Registered: <span className="text-ink">{formatDate(mfa.totp.registeredAt)}</span></div>
                            <div>Last used: <span className="text-ink">{formatDate(mfa.totp.lastUsedAt)}</span></div>
                        </div>
                        <button onClick={handleRemoveTotp} className="text-xs text-crit hover:text-crit transition-colors">Remove TOTP</button>
                    </div>
                ) : totpSetupActive ? (
                    <div className="space-y-4">
                        <p className="text-sm text-ink">Scan the QR code with your authenticator app:</p>
                        {provisioningUri && (
                            <div className="flex justify-center bg-white p-4 rounded-lg mx-auto" style={{ width: 'fit-content' }}>
                                <div dangerouslySetInnerHTML={{ __html: generateQrSvg(provisioningUri, 3, 2) }} />
                            </div>
                        )}
                        <details className="text-sm">
                            <summary className="text-ink-muted cursor-pointer hover:text-ink">Can't scan? Enter manually</summary>
                            <div className="bg-sunken p-3 rounded mt-2">
                                <p className="text-xs text-ink-muted mb-1">Secret key:</p>
                                <code className="text-sm text-warn break-all select-all">{totpSecret}</code>
                            </div>
                        </details>
                        <form onSubmit={handleTotpVerify} className="space-y-3">
                            <div>
                                <label className="block text-xs text-ink-muted mb-1">Verification Code</label>
                                <input type="text" inputMode="numeric" pattern="[0-9]*" maxLength={6}
                                    className="w-full bg-raised border border-line-strong text-ink rounded px-3 py-2 focus:border-accent focus:outline-none text-center text-lg tracking-widest"
                                    value={totpCode} onChange={e => setTotpCode(e.target.value.replace(/\D/g, ''))}
                                    placeholder="000000" autoFocus required />
                            </div>
                            <div className="flex gap-2">
                                <button type="submit" disabled={totpLoading || totpCode.length !== 6}
                                    className="flex-1 bg-accent text-on-accent py-2 rounded hover:bg-accent-hover disabled:opacity-50 transition-colors text-sm">
                                    {totpLoading ? 'Verifying...' : 'Verify & Enable'}
                                </button>
                                <button type="button" onClick={() => { setTotpSetupActive(false); setTotpSecret(null); setProvisioningUri(null); setTotpCode(''); }}
                                    className="px-4 py-2 bg-sunken text-ink rounded hover:bg-hover transition-colors text-sm">
                                    Cancel
                                </button>
                            </div>
                        </form>
                    </div>
                ) : (
                    <div className="space-y-3">
                        <div className="flex gap-2 items-end">
                            <div className="flex-1">
                                <label className="block text-xs text-ink-muted mb-1">Device Name (optional)</label>
                                <input type="text" value={totpDeviceName} onChange={e => setTotpDeviceName(e.target.value)}
                                    placeholder="e.g., Google Authenticator" className="w-full bg-raised border border-line-strong text-ink rounded px-3 py-2 text-sm focus:border-accent focus:outline-none" />
                            </div>
                            <button onClick={handleTotpSetup} disabled={totpLoading}
                                className="bg-accent text-on-accent px-4 py-2 rounded hover:bg-accent-hover disabled:opacity-50 transition-colors text-sm whitespace-nowrap">
                                {totpLoading ? 'Setting up...' : 'Set up TOTP'}
                            </button>
                        </div>
                    </div>
                )}
            </div>

            {/* ── WebAuthn ── */}
            {webauthnAvailable && (
                <div className="bg-raised border border-line rounded-lg p-5 space-y-4">
                    <div className="flex items-center justify-between">
                        <h2 className="text-sm font-semibold text-ink">Security Keys (WebAuthn)</h2>
                        <span className="text-xs px-2 py-0.5 rounded bg-sunken text-ink-muted border border-line-strong">
                            {webauthnCount} / {MAX_WEBAUTHN_KEYS}
                        </span>
                    </div>

                    {mfa?.webauthn.credentials.map(cred => (
                        <div key={cred.id} className="flex items-center justify-between py-2 border-t border-line">
                            <div className="text-xs text-ink-muted">
                                <span className="text-ink">{cred.deviceName || 'Security Key'}</span>
                                <span className="ml-2">Registered {formatDate(cred.registeredAt)}</span>
                                {cred.lastUsedAt && <span className="ml-2">| Last used {formatDate(cred.lastUsedAt)}</span>}
                            </div>
                            <button onClick={() => handleRemoveWebauthn(cred.id)} className="text-xs text-crit hover:text-crit">Remove</button>
                        </div>
                    ))}

                    {canAddWebauthn ? (
                        <div className="flex gap-2 items-end pt-2 border-t border-line">
                            <div className="flex-1">
                                <label className="block text-xs text-ink-muted mb-1">Key Name (optional)</label>
                                <input type="text" value={webauthnDeviceName} onChange={e => setWebauthnDeviceName(e.target.value)}
                                    placeholder="e.g., YubiKey 5" className="w-full bg-raised border border-line-strong text-ink rounded px-3 py-2 text-sm focus:border-accent focus:outline-none" />
                            </div>
                            <button onClick={handleWebauthnRegister} disabled={webauthnLoading}
                                className="bg-accent text-on-accent px-4 py-2 rounded hover:bg-accent-hover disabled:opacity-50 transition-colors text-sm whitespace-nowrap">
                                {webauthnLoading ? 'Waiting...' : 'Register Key'}
                            </button>
                        </div>
                    ) : webauthnCount >= MAX_WEBAUTHN_KEYS ? (
                        <p className="text-xs text-ink-muted pt-2 border-t border-line">Maximum of {MAX_WEBAUTHN_KEYS} security keys reached. Remove one to register another.</p>
                    ) : null}
                </div>
            )}

            {/* ── mTLS ── */}
            <div className="bg-raised border border-line rounded-lg p-5 space-y-4">
                <div className="flex items-center justify-between">
                    <h2 className="text-sm font-semibold text-ink">Client Certificates (mTLS)</h2>
                    {mfa?.mtls.enrolled ? (
                        <span className="text-xs px-2 py-0.5 rounded bg-ok-soft text-ok border border-ok/40">{mfa.mtls.credentials.length} cert{mfa.mtls.credentials.length !== 1 ? 's' : ''}</span>
                    ) : (
                        <span className="text-xs px-2 py-0.5 rounded bg-sunken text-ink-muted border border-line-strong">Not enrolled</span>
                    )}
                </div>

                {mfa?.mtls.credentials.map(cred => (
                    <div key={cred.id} className="flex items-center justify-between py-2 border-t border-line">
                        <div className="text-xs text-ink-muted">
                            <span className="text-ink">{cred.deviceName || 'Client Certificate'}</span>
                            <span className="ml-2 font-mono">{cred.serialNumber}</span>
                            <span className="ml-2">Expires {formatDate(cred.expiresAt)}</span>
                        </div>
                        <button onClick={() => handleRevokeMtls(cred.id)} className="text-xs text-crit hover:text-crit">Revoke</button>
                    </div>
                ))}

                {mtlsPassword && (
                    <div className="bg-warn-soft border border-warn/40 rounded p-3 space-y-1">
                        <p className="text-warn text-sm font-semibold">PKCS#12 Password — save this!</p>
                        <code className="text-sm text-warn tracking-wider select-all block bg-sunken rounded p-2 text-center">{mtlsPassword}</code>
                        <p className="text-xs text-warn">This password will not be shown again.</p>
                        <button onClick={() => setMtlsPassword(null)} className="text-xs text-ink-muted hover:text-ink">Dismiss</button>
                    </div>
                )}

                {allowedCas.length > 0 && (
                    <div className="space-y-3 pt-2 border-t border-line">
                        <p className="text-xs text-ink-muted">Enroll a new client certificate:</p>
                        <div className="flex gap-2 items-end">
                            {allowedCas.length > 1 && (
                                <div className="flex-1">
                                    <label className="block text-xs text-ink-muted mb-1">Signing CA</label>
                                    <select value={mtlsSelectedCa} onChange={e => setMtlsSelectedCa(e.target.value)}
                                        className="w-full bg-raised border border-line-strong text-ink rounded px-3 py-2 text-sm focus:border-accent focus:outline-none">
                                        {allowedCas.map(ca => <option key={ca.caId} value={ca.caId}>{ca.caName}</option>)}
                                    </select>
                                </div>
                            )}
                            <div className="flex-1">
                                <label className="block text-xs text-ink-muted mb-1">Device Name</label>
                                <input type="text" value={mtlsDeviceName} onChange={e => setMtlsDeviceName(e.target.value)}
                                    placeholder="e.g., Work Laptop" className="w-full bg-raised border border-line-strong text-ink rounded px-3 py-2 text-sm focus:border-accent focus:outline-none" />
                            </div>
                            <button onClick={handleMtlsEnroll} disabled={mtlsEnrolling || !mtlsSelectedCa}
                                className="bg-accent text-on-accent px-4 py-2 rounded hover:bg-accent-hover disabled:opacity-50 transition-colors text-sm whitespace-nowrap">
                                {mtlsEnrolling ? 'Enrolling...' : 'Enroll'}
                            </button>
                        </div>
                    </div>
                )}
            </div>

            {/* ── Password ── */}
            <ChangePasswordSection requireStepUp={requireStepUp} showMsg={showMsg} setError={setError} />

            {/* TOTP Confirmation Modal */}
            {totpModalOpen && (
                <div className="fixed inset-0 z-50 flex items-center justify-center bg-scrim" onClick={closeTotpModal}>
                    <div className="bg-raised border border-line rounded-xl shadow-2xl p-6 w-full max-w-sm mx-4 space-y-4" onClick={(e) => e.stopPropagation()}>
                        <h3 className="text-lg font-bold text-ink">{totpModalTitle}</h3>
                        <p className="text-sm text-ink-muted">Enter your TOTP code to confirm:</p>
                        <input type="password" inputMode="numeric" maxLength={6} value={totpModalCode}
                            onChange={e => setTotpModalCode(e.target.value.replace(/\D/g, ''))}
                            autoComplete="one-time-code" placeholder="000000" autoFocus
                            className="w-full px-3 py-2 bg-raised border border-line-strong rounded text-sm text-ink text-center text-lg tracking-widest focus:outline-none focus:border-accent" />
                        <div className="flex justify-end gap-3">
                            <button onClick={closeTotpModal} disabled={totpModalLoading}
                                className="px-4 py-2 text-sm bg-sunken text-ink rounded hover:bg-hover transition-colors disabled:opacity-50">
                                Cancel
                            </button>
                            <button onClick={handleTotpModalConfirm} disabled={totpModalCode.length !== 6 || totpModalLoading}
                                className="px-4 py-2 text-sm bg-accent text-on-accent rounded hover:bg-accent-hover disabled:opacity-40 transition-colors">
                                {totpModalLoading ? 'Verifying...' : 'Confirm'}
                            </button>
                        </div>
                    </div>
                </div>
            )}
        </div>
    );
};

/* ── Inline Change Password ── */
const ChangePasswordSection: React.FC<{
    requireStepUp: (op: string, tid?: string) => Promise<string>;
    showMsg: (msg: string) => void;
    setError: (msg: string) => void;
}> = ({ requireStepUp, showMsg, setError }) => {
    const { apiPutWithMfa } = useAuthClient();
    const [open, setOpen] = useState(false);
    const [oldPassword, setOldPassword] = useState('');
    const [newPassword, setNewPassword] = useState('');
    const [confirmPassword, setConfirmPassword] = useState('');
    const [saving, setSaving] = useState(false);

    const handleChange = async (e: React.FormEvent) => {
        e.preventDefault();
        if (newPassword !== confirmPassword) {
            setError('Passwords do not match');
            return;
        }
        if (newPassword.length < 8) {
            setError('Password must be at least 8 characters');
            return;
        }
        setSaving(true);
        try {
            await apiPutWithMfa('/api/v1/account/password', {
                oldPassword,
                newPassword,
                confirmNewPassword: confirmPassword,
            }, requireStepUp, StepUpOps.ChangePassword);
            showMsg('Password changed successfully');
            setOpen(false);
            setOldPassword('');
            setNewPassword('');
            setConfirmPassword('');
        } catch (err: any) {
            if (err.message !== 'Step-up MFA cancelled') setError(err.message || 'Failed to change password');
        } finally { setSaving(false); }
    };

    const inputClass = 'w-full bg-raised border border-line-strong text-ink rounded px-3 py-2 text-sm focus:border-accent focus:outline-none';

    return (
        <div className="bg-raised border border-line rounded-lg p-5 space-y-4">
            <div className="flex items-center justify-between">
                <h2 className="text-sm font-semibold text-ink">Password</h2>
                {!open && (
                    <button onClick={() => setOpen(true)} className="text-sm bg-sunken text-ink px-4 py-2 rounded hover:bg-hover transition-colors">
                        Change Password
                    </button>
                )}
            </div>
            {open && (
                <form onSubmit={handleChange} className="space-y-3">
                    <div>
                        <label className="block text-xs text-ink-muted mb-1">Current Password</label>
                        <input type="password" required value={oldPassword} onChange={e => setOldPassword(e.target.value)} className={inputClass} />
                    </div>
                    <div>
                        <label className="block text-xs text-ink-muted mb-1">New Password</label>
                        <input type="password" required minLength={8} value={newPassword} onChange={e => setNewPassword(e.target.value)} className={inputClass} />
                    </div>
                    <div>
                        <label className="block text-xs text-ink-muted mb-1">Confirm New Password</label>
                        <input type="password" required value={confirmPassword} onChange={e => setConfirmPassword(e.target.value)}
                            className={`${inputClass} ${confirmPassword && confirmPassword !== newPassword ? 'border-crit' : ''}`} />
                        {confirmPassword && confirmPassword !== newPassword && (
                            <p className="text-xs text-crit mt-1">Passwords do not match</p>
                        )}
                    </div>
                    <div className="flex gap-2">
                        <button type="submit" disabled={saving || !oldPassword || !newPassword || newPassword !== confirmPassword}
                            className="bg-accent text-on-accent px-4 py-2 rounded hover:bg-accent-hover disabled:opacity-50 transition-colors text-sm">
                            {saving ? 'Changing...' : 'Change Password'}
                        </button>
                        <button type="button" onClick={() => { setOpen(false); setOldPassword(''); setNewPassword(''); setConfirmPassword(''); }}
                            className="bg-sunken text-ink px-4 py-2 rounded hover:bg-hover transition-colors text-sm">
                            Cancel
                        </button>
                    </div>
                </form>
            )}
        </div>
    );
};

// base64url helpers
function base64urlToBuffer(b64: string): ArrayBuffer {
    const base64 = b64.replace(/-/g, '+').replace(/_/g, '/');
    const pad = base64.length % 4 === 0 ? '' : '='.repeat(4 - (base64.length % 4));
    const bin = atob(base64 + pad);
    const bytes = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
    return bytes.buffer;
}

function bufferToBase64url(buf: ArrayBuffer): string {
    const bytes = new Uint8Array(buf);
    let bin = '';
    for (let i = 0; i < bytes.byteLength; i++) bin += String.fromCharCode(bytes[i]);
    return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

