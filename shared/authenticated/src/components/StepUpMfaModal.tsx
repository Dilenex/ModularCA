import React, { useState, useEffect, useRef } from 'react';

/**
 * Step-up MFA prompt, shared by adminui and userui.
 *
 * userui's copy was TOTP-only: 140 lines against adminui's 256, with no WebAuthn path at
 * all. A user whose only second factor is a security key could therefore not complete ANY
 * step-up-gated action in the user portal — not revoke their own certificate, not change
 * their email. The prompt appeared and there was nothing they could do with it.
 *
 * `apiPost` and `factors` are injected rather than imported so this file stays free of
 * app-local modules: each app binds its own client, and adminui already knows the user's
 * factors from its AuthContext while userui resolves them from /api/v1/me.
 */

/** Which second factors the user has enrolled. */
export interface MfaFactors {
    totp: boolean;
    webauthn: boolean;
}

export interface StepUpMfaModalProps {
    isOpen: boolean;
    operation: string;
    targetId?: string;
    onSuccess: (mfaToken: string) => void;
    onCancel: () => void;
    /** The host app's authenticated POST. */
    apiPost: <T = any>(path: string, body?: object) => Promise<T>;
    /**
     * Enrolled factors. When omitted the modal offers TOTP only — the safe default, since
     * attempting a WebAuthn ceremony for a user with no credential produces a browser error
     * rather than a useful prompt.
     */
    factors?: MfaFactors;
}

function base64urlToBuffer(base64url: string): ArrayBuffer {
    const base64 = base64url.replace(/-/g, '+').replace(/_/g, '/');
    const pad = base64.length % 4 === 0 ? '' : '='.repeat(4 - (base64.length % 4));
    const binary = atob(base64 + pad);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
    return bytes.buffer;
}

function bufferToBase64url(buffer: ArrayBuffer): string {
    const bytes = new Uint8Array(buffer);
    let binary = '';
    for (let i = 0; i < bytes.byteLength; i++) binary += String.fromCharCode(bytes[i]);
    return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

export const StepUpMfaModal: React.FC<StepUpMfaModalProps> = ({
    isOpen, operation, targetId, onSuccess, onCancel, apiPost, factors,
}) => {
    const [code, setCode] = useState('');
    const [loading, setLoading] = useState(false);
    const [webauthnLoading, setWebauthnLoading] = useState(false);
    const [error, setError] = useState<string | null>(null);
    const abortRef = useRef<AbortController | null>(null);
    const settledRef = useRef(false);

    // Default to TOTP-only when the caller could not resolve the factors.
    const hasTotp = factors?.totp ?? true;
    const hasWebauthn = factors?.webauthn ?? false;

    useEffect(() => {
        if (!isOpen) {
            settledRef.current = false;
            return;
        }
        if (!hasWebauthn) return;

        settledRef.current = false;
        const controller = new AbortController();
        abortRef.current = controller;

        (async () => {
            try {
                setWebauthnLoading(true);
                const options = await apiPost<any>('/auth/mfa/verify-stepup/webauthn-options', {});
                if (controller.signal.aborted || settledRef.current) return;

                options.challenge = base64urlToBuffer(options.challenge);
                if (options.allowCredentials) {
                    options.allowCredentials = options.allowCredentials.map((c: any) => ({
                        ...c,
                        id: base64urlToBuffer(c.id),
                    }));
                }

                const credential = await navigator.credentials.get({
                    publicKey: options,
                    signal: controller.signal,
                }) as PublicKeyCredential | null;

                if (!credential || controller.signal.aborted || settledRef.current) return;

                const assertionResponse = credential.response as AuthenticatorAssertionResponse;
                const data = await apiPost<{ mfaToken?: string; token?: string }>(
                    '/auth/mfa/verify-stepup/webauthn',
                    {
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
                        operation,
                        targetId,
                    },
                );

                if (settledRef.current) return;
                settledRef.current = true;
                setCode('');
                onSuccess(data.mfaToken || data.token || '');
            } catch (err: any) {
                if (controller.signal.aborted || settledRef.current) return;
                if (err.name !== 'AbortError' && err.name !== 'NotAllowedError') {
                    setError(err.message || 'Security key verification failed');
                }
            } finally {
                setWebauthnLoading(false);
            }
        })();

        return () => {
            controller.abort();
            abortRef.current = null;
        };
    }, [isOpen, hasWebauthn, operation, targetId, onSuccess]);

    if (!isOpen) return null;

    const handleTotpSubmit = async (e: React.FormEvent) => {
        e.preventDefault();
        if (code.length !== 6 || settledRef.current) return;

        setLoading(true);
        setError(null);

        try {
            const data = await apiPost<{ mfaToken?: string; token?: string }>(
                '/auth/mfa/verify-stepup/totp',
                { code, operation, targetId },
            );
            settledRef.current = true;
            abortRef.current?.abort();
            setCode('');
            onSuccess(data.mfaToken || data.token || '');
        } catch (err: any) {
            setError(err.message || 'Invalid verification code');
        } finally {
            setLoading(false);
        }
    };

    const handleCancel = () => {
        settledRef.current = true;
        abortRef.current?.abort();
        setCode('');
        setError(null);
        onCancel();
    };

    return (
        <div className="fixed inset-0 z-50 flex items-center justify-center">
            <div
                className="absolute inset-0 bg-black/25 dark:bg-black/60 backdrop-blur-sm"
                onClick={handleCancel}
            />

            <div className="relative bg-gray-100 dark:bg-gray-800 border border-gray-300 dark:border-gray-700 rounded-lg shadow-xl w-full max-w-md mx-4 p-6 space-y-5">
                <div className="text-center">
                    <h3 className="text-lg font-semibold text-gray-900 dark:text-white">
                        Step-Up Verification Required
                    </h3>
                    <p className="text-sm text-gray-600 dark:text-gray-400 mt-1">
                        This operation requires additional authentication.
                        {hasTotp && hasWebauthn
                            ? ' Enter a TOTP code or tap your security key.'
                            : hasWebauthn
                            ? ' Tap your security key to continue.'
                            : ' Enter the 6-digit code from your authenticator app.'}
                    </p>
                </div>

                {error && (
                    <div className="bg-red-50 dark:bg-red-900/50 border border-red-300 dark:border-red-700 text-red-800 dark:text-red-300 text-sm text-center p-2 rounded">
                        {error}
                    </div>
                )}

                {/* WebAuthn — auto-triggered, shows status */}
                {hasWebauthn && (
                    <div className="bg-blue-50 dark:bg-blue-900/20 border border-blue-200 dark:border-blue-800 rounded-lg p-4 text-center">
                        <div className="flex items-center justify-center gap-2">
                            {webauthnLoading ? (
                                <>
                                    <svg className="animate-pulse w-5 h-5 text-blue-600 dark:text-blue-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 7a2 2 0 012 2m4 0a6 6 0 01-7.743 5.743L11 17H9v2H7v2H4a1 1 0 01-1-1v-2.586a1 1 0 01.293-.707l5.964-5.964A6 6 0 1121 9z" />
                                    </svg>
                                    <span className="text-sm font-medium text-blue-700 dark:text-blue-300">
                                        Waiting for security key...
                                    </span>
                                </>
                            ) : (
                                <span className="text-sm text-blue-600 dark:text-blue-400">
                                    Security key ready
                                </span>
                            )}
                        </div>
                    </div>
                )}

                {/* TOTP — manual entry */}
                {hasTotp && (
                    <form onSubmit={handleTotpSubmit} className="space-y-4">
                        {hasWebauthn && (
                            <div className="flex items-center gap-3">
                                <div className="flex-1 border-t border-gray-300 dark:border-gray-600" />
                                <span className="text-xs text-gray-600 uppercase">or enter code</span>
                                <div className="flex-1 border-t border-gray-300 dark:border-gray-600" />
                            </div>
                        )}
                        <div>
                            <input
                                type="text"
                                inputMode="numeric"
                                pattern="[0-9]*"
                                maxLength={6}
                                className="w-full bg-gray-200 dark:bg-gray-700 border border-gray-400 dark:border-gray-600 text-gray-900 dark:text-white rounded px-3 py-3 focus:border-blue-500 focus:outline-none text-center text-2xl tracking-widest"
                                value={code}
                                onChange={(e) => setCode(e.target.value.replace(/\D/g, ''))}
                                placeholder="000000"
                                autoFocus={!hasWebauthn}
                                required
                            />
                        </div>
                        <button
                            type="submit"
                            disabled={loading || code.length !== 6}
                            className="w-full py-2 text-sm font-medium bg-blue-600 text-white rounded hover:bg-blue-700 disabled:opacity-50 transition-colors"
                        >
                            {loading ? 'Verifying...' : 'Verify Code'}
                        </button>
                    </form>
                )}

                <div className="flex justify-center">
                    <button
                        type="button"
                        onClick={handleCancel}
                        className="py-2 px-6 text-sm font-medium bg-gray-200 dark:bg-gray-700 text-gray-700 dark:text-gray-300 rounded hover:bg-gray-300 dark:hover:bg-gray-600 transition-colors"
                    >
                        Cancel
                    </button>
                </div>

                <p className="text-xs text-gray-600 text-center">
                    Operation: <span className="font-mono text-gray-600 dark:text-gray-400">{operation}</span>
                    {targetId && (
                        <>
                            {' '} | Target: <span className="font-mono text-gray-600 dark:text-gray-400">{targetId}</span>
                        </>
                    )}
                </p>
            </div>
        </div>
    );
};
