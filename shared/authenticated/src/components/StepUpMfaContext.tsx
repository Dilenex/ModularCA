import React, { createContext, useContext, useState, useCallback, useRef } from 'react';
import { StepUpMfaModal, type MfaFactors } from './StepUpMfaModal';

/// <summary>
/// React context provider for step-up MFA verification.
/// Provides a requireStepUp function that shows the MFA modal and returns
/// a Promise resolving to the MFA token on successful verification.
/// </summary>
interface StepUpContext {
    requireStepUp: (operation: string, targetId?: string) => Promise<string>;
}

const StepUpCtx = createContext<StepUpContext>({
    requireStepUp: () => Promise.reject(new Error('No StepUpMfaProvider')),
});

export const useStepUp = () => useContext(StepUpCtx);

export interface StepUpMfaProviderProps {
    children: React.ReactNode;
    /** The host app's authenticated POST and GET. */
    apiPost: <T = any>(path: string, body?: object) => Promise<T>;
    apiGet: <T = any>(path: string) => Promise<T>;
    /**
     * Enrolled factors, when the host already knows them (adminui has them in AuthContext).
     * Omit and the provider resolves them once from /api/v1/me — which is how userui, which has
     * no auth context at all, gets a WebAuthn prompt instead of a TOTP-only one.
     */
    factors?: MfaFactors;
}

export const StepUpMfaProvider: React.FC<StepUpMfaProviderProps> = ({
    children, apiPost, apiGet, factors: providedFactors,
}) => {
    const [isOpen, setIsOpen] = useState(false);
    const [resolvedFactors, setResolvedFactors] = useState<MfaFactors | undefined>(providedFactors);
    const [operation, setOperation] = useState('');
    const [targetId, setTargetId] = useState<string | undefined>();
    const resolveRef = useRef<((token: string) => void) | null>(null);
    const rejectRef = useRef<((err: Error) => void) | null>(null);

    // Resolve enrolled factors the first time a step-up is requested, when the host app does
    // not already know them. Deferred rather than done on mount so an app that never triggers a
    // step-up never makes the call.
    React.useEffect(() => {
        if (providedFactors) { setResolvedFactors(providedFactors); return; }
        if (!isOpen || resolvedFactors) return;
        let cancelled = false;
        (async () => {
            try {
                const me = await apiGet<{ mfa?: MfaFactors }>('/api/v1/me');
                if (!cancelled && me?.mfa) setResolvedFactors({ totp: !!me.mfa.totp, webauthn: !!me.mfa.webauthn });
            } catch {
                // Leave undefined — the modal falls back to TOTP-only, which is what this app
                // did unconditionally before. A failure here must not block the prompt.
            }
        })();
        return () => { cancelled = true; };
    }, [isOpen, providedFactors, resolvedFactors, apiGet]);

    const requireStepUp = useCallback((op: string, tid?: string): Promise<string> => {
        setOperation(op);
        setTargetId(tid);
        setIsOpen(true);
        return new Promise<string>((resolve, reject) => {
            resolveRef.current = resolve;
            rejectRef.current = reject;
        });
    }, []);

    const handleSuccess = (mfaToken: string) => {
        setIsOpen(false);
        resolveRef.current?.(mfaToken);
        resolveRef.current = null;
        rejectRef.current = null;
    };

    const handleCancel = () => {
        setIsOpen(false);
        rejectRef.current?.(new Error('Step-up MFA cancelled'));
        resolveRef.current = null;
        rejectRef.current = null;
    };

    return (
        <StepUpCtx.Provider value={{ requireStepUp }}>
            {children}
            <StepUpMfaModal
                isOpen={isOpen}
                operation={operation}
                targetId={targetId}
                onSuccess={handleSuccess}
                onCancel={handleCancel}
                apiPost={apiPost}
                factors={resolvedFactors}
            />
        </StepUpCtx.Provider>
    );
};
