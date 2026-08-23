import React from 'react';
import { StepUpMfaProvider as SharedProvider, useStepUp } from '@shared-auth/components/StepUpMfaContext';
import { apiGet, apiPost } from '../api/client';

/**
 * Binds the shared step-up provider to this app's API client.
 *
 * This app previously had its own TOTP-only modal, so a user whose second factor is a security
 * key was shown a six-digit code box they had no way to fill — every step-up-gated action was
 * unreachable for them. The shared modal supports both factors.
 *
 * No `factors` prop: this app has no auth context, so the provider resolves them from
 * /api/v1/me the first time a step-up is requested.
 */
export const StepUpMfaProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => (
    <SharedProvider apiPost={apiPost} apiGet={apiGet}>
        {children}
    </SharedProvider>
);

export { useStepUp };
