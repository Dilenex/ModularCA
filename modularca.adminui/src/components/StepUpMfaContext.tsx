import React from 'react';
import { StepUpMfaProvider as SharedProvider, useStepUp } from '@shared-auth/components/StepUpMfaContext';
import { apiGet, apiPost } from '../api/client';
import { useAuth } from '../context/AuthContext';

/**
 * Binds the shared step-up provider to this app's API client.
 *
 * The provider and its modal live in `@shared-auth/components`. They were shared with the
 * former modularca.userui, whose own copy was TOTP-only — a user with only a security key could
 * not complete any step-up-gated action there. That app is now the /user prefix of this one.
 *
 * This app passes its own factors from AuthContext, so no extra /api/v1/me call is made.
 */
export const StepUpMfaProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
    const { user } = useAuth();
    return (
        <SharedProvider
            apiPost={apiPost}
            apiGet={apiGet}
            factors={user?.mfa ? { totp: !!user.mfa.totp, webauthn: !!user.mfa.webauthn } : undefined}
        >
            {children}
        </SharedProvider>
    );
};

export { useStepUp };
