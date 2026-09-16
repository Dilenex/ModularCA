import React, { createContext, useContext, useEffect, useState, useCallback } from 'react';
import { apiGet, getToken } from '../api/client';
import type { Capability } from '@shared/generated';
import { can as canOn, canAnywhere as canOnAny, canUseAdminConsole as computeCanUseAdminConsole, NO_CAPABILITIES, type EffectiveCapabilities } from '../authz';

/**
 * Shape returned by GET /api/v1/me. The SPA uses this instead of decoding the JWT body to
 * learn the current identity and, through `capabilities`, what the caller may do at system
 * scope and on each CA. The group list is informational; nothing gates on it.
 */
export interface AuthGroup {
    id: string;
    name: string;
    displayName: string;
    templateName: string | null; // 'Administrator' | 'Operator' | 'Auditor' | 'Requester' | null (custom)
    isSystemGroup: boolean;
    certificateAuthorityId: string | null;
    caLabel: string | null;
    tenantId: string;
}

export interface AuthMeResponse {
    id: string;
    username: string;
    email: string | null;
    displayName: string | null;
    firstName: string;
    lastName: string;
    isActive: boolean;
    groups: AuthGroup[];
    scopes: string[];
    isSuper?: boolean;
    capabilities: EffectiveCapabilities;
    mfa: {
        configured: boolean;
        totp: boolean;
        webauthn: boolean;
        mtls: boolean;
    };
    tenantId: string | null;
}

export interface AuthContextValue {
    user: AuthMeResponse | null;
    loading: boolean;
    error: string | null;
    refresh: () => Promise<void>;
    /** The caller's effective capabilities; `NO_CAPABILITIES` until `/api/v1/me` answers. */
    capabilities: EffectiveCapabilities;
    /** Whether `capability` is held on `caId`, or at system scope when no CA is given. */
    can: (capability: Capability, caId?: string | null) => boolean;
    /** Whether `capability` is held at system scope or on any CA. */
    canAnywhere: (capability: Capability) => boolean;
    /**
     * Whether the signed-in user has anything to do in the management console (see
     * `canUseAdminConsole` in portal.ts). A user without it landing on `/admin` is sent to
     * `/user` instead of a dashboard of failing admin calls.
     */
    canUseAdminConsole: boolean;
}

const AuthContext = createContext<AuthContextValue>({
    user: null,
    loading: true,
    error: null,
    refresh: async () => { },
    capabilities: NO_CAPABILITIES,
    can: () => false,
    canAnywhere: () => false,
    canUseAdminConsole: false,
});

export const useAuth = () => useContext(AuthContext);

export const AuthProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
    const [user, setUser] = useState<AuthMeResponse | null>(null);
    const [loading, setLoading] = useState<boolean>(true);
    const [error, setError] = useState<string | null>(null);

    const refresh = useCallback(async () => {
        if (!getToken()) {
            setUser(null);
            setLoading(false);
            return;
        }
        try {
            setLoading(true);
            const me = await apiGet<AuthMeResponse>('/api/v1/me');
            setUser(me);
            setError(null);
        } catch (e: any) {
            setUser(null);
            setError(e?.message || 'Failed to load user');
        } finally {
            setLoading(false);
        }
    }, []);

    useEffect(() => {
        refresh();
    }, [refresh]);

    const capabilities = user?.capabilities ?? NO_CAPABILITIES;
    const can = useCallback((capability: Capability, caId?: string | null) => canOn(capabilities, capability, caId), [capabilities]);
    const canAnywhere = useCallback((capability: Capability) => canOnAny(capabilities, capability), [capabilities]);

    const canUseAdminConsole = computeCanUseAdminConsole(capabilities);

    return (
        <AuthContext.Provider value={{ user, loading, error, refresh, capabilities, can, canAnywhere, canUseAdminConsole }}>
            {children}
        </AuthContext.Provider>
    );
};
