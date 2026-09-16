// Every direct localStorage.getItem('authToken') call now
// routes through the api/client.ts getToken helper so a future cookie-based
// auth migration is a one-line change. Do not re-introduce localStorage reads
// here.
import { getToken as clientGetToken, clearTokens } from '../api/client';
import { LOGIN_PATH } from '../portal';

export function isAuthenticated(): boolean {
    // Presence-based, NOT clock-based. The server is the authority on token validity (it validates
    // the JWT, and the refresh-on-401 flow in api/client handles genuine expiry). We deliberately do
    // NOT gate on `new Date() < exp` here: a client/server clock skew would otherwise make a
    // freshly-issued token look already-expired and bounce ProtectedRoute to /login in an infinite
    // loop while /me still returns 200. A stale/expired token left here is harmless — the next API
    // call refreshes it, or the server 401 clears it.
    return !!clientGetToken() && !!localStorage.getItem('expiresAt');
}

export function getToken(): string | null {
    return clientGetToken();
}

export function isMfaSetupRequired(): boolean {
    return localStorage.getItem('mfaSetupRequired') === 'true';
}

export function setMfaSetupRequired(required: boolean) {
    if (required) localStorage.setItem('mfaSetupRequired', 'true');
    else localStorage.removeItem('mfaSetupRequired');
}

export function logout() {
    clearTokens();
    window.location.href = LOGIN_PATH;
}
