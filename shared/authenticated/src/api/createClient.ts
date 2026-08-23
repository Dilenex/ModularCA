/**
 * The authenticated API client, shared by the two SPAs that have a logged-in user.
 *
 * This exists because adminui and userui each had their own copy — 527 and 464 lines — and the
 * copies had drifted in exactly the way that matters. adminui gained a single-flight refresh
 * guard and DPoP proof-of-possession; userui got neither. Without the guard, a page that fires
 * several requests at once issues several concurrent /auth/refresh calls with the same refresh
 * token, and the backend's refresh-token-family compromise detection correctly reads that as
 * theft and hard-logs the user out. The admin UI was fixed; the user UI was left with the bug.
 *
 * Only ONE thing differs between the two apps: the route basename, '/admin' or '/user'. So this
 * is a factory rather than a module of free functions, and everything else — refresh handling,
 * CSRF, DPoP, step-up retry, blob downloads — is now written once.
 *
 * Two dependencies are injected rather than imported, because each app owns its own:
 *  - `toast`, so a failure surfaces in that app's notification system
 *  - nothing else; DPoP moved into this module, which is how userui gains it
 *
 * Module-level state in the original (the in-flight refresh promise) becomes closure state per
 * client instance. That is the correct scope: one client per app, one refresh in flight per
 * client.
 */
import { createDpopProof } from './dpop';

/** A toast notifier supplied by the consuming app. */
export type ToastFn = (type: 'success' | 'error' | 'warning' | 'info', message: string) => void;

export interface AuthClientConfig {
    /** Route basename for this SPA: '/admin' or '/user'. Used for same-origin detection and
     *  for the login / mfa-setup redirects the client performs on 401. */
    basename: string;
    /** Surface errors in the host app's notification system. Optional: omit and errors are
     *  thrown but not toasted. */
    toast?: ToastFn;
}

/**
 * Builds an authenticated API client bound to one SPA's basename.
 */
export interface LoginResponse {
  token?: string;
  expiresAt?: string;
  refreshToken?: string;
  mfaSetupRequired?: boolean;
  requiresMfa?: boolean;
  requirePasswordChange?: boolean;
  mfaToken?: string;
  method?: string;
  availableMethods?: string[];
}

export function createAuthClient(config: AuthClientConfig) {
    const basename = config.basename;
    const globalToast: ToastFn = config.toast ?? (() => { /* no notifier configured */ });

    // When served from the same origin (Staging/Release), use empty base (relative paths).
    // In dev mode, use the VITE_API_URL env variable. There is no longer a hardcoded
    // fallback — a missing VITE_API_URL in a non-same-origin build
    // will surface as obvious 404s during development instead of silently shipping the
    // wrong port to production.
    const isSameOrigin = window.location.pathname.startsWith(basename);
    const VITE_API_URL = (import.meta as any).env?.VITE_API_URL as string | undefined;
    const API_BASE = isSameOrigin ? '' : (VITE_API_URL || '');
    if (!isSameOrigin && !VITE_API_URL) {
      // Surface as a console warning during dev — production builds always run
      // same-origin so this branch never fires there.
      // eslint-disable-next-line no-console
      console.warn('[modularca-adminui] VITE_API_URL is not set; API calls will be sent to the current origin.');
    }

    /**
     * Single chokepoint for reading the access token. Today this
     * still reads from localStorage; flipping the SPA to HttpOnly cookie auth becomes a
     * one-line change here once the backend cookie scheme is enabled. ALL request paths
     * (api(), apiBlob(), and direct fetch in pages) MUST go through this helper instead
     * of touching localStorage directly.
     */
    function getToken(): string | null {
      return localStorage.getItem('authToken');
    }

    function getRefreshToken(): string | null {
      return localStorage.getItem('refreshToken');
    }

    function getExpiry(): number {
      const exp = localStorage.getItem('expiresAt');
      return exp ? new Date(exp).getTime() : 0;
    }

    function setTokens(token: string, expiresAt: string, refreshToken: string) {
      localStorage.setItem('authToken', token);
      localStorage.setItem('expiresAt', expiresAt);
      localStorage.setItem('refreshToken', refreshToken);
    }

    /**
     * Clears all client-side auth state. Exported so the AuthContext and a future
     * cookie-mode logout can share the same teardown path.
     */
    function clearTokens() {
      localStorage.removeItem('authToken');
      localStorage.removeItem('expiresAt');
      localStorage.removeItem('refreshToken');
      localStorage.removeItem('mfaSetupRequired');
    }

    /**
     * In-flight Promise cache so concurrent callers share a single
     * refresh request. Without this, a dashboard with N parallel widget loads would fire
     * N /auth/refresh calls with the same refresh token; one would win and the others
     * would either land on a stale token or 401 if the backend one-shots refresh tokens.
     */
    let inflightRefresh: Promise<string | null> | null = null;

    async function refreshIfNeeded(): Promise<string | null> {
      const token = getToken();
      const expiry = getExpiry();
      const now = Date.now();

      // Only refresh inside the 5-minute pre-expiry window.
      if (!token || expiry <= 0 || expiry - now >= 5 * 60 * 1000) {
        return token;
      }

      if (inflightRefresh) {
        return inflightRefresh;
      }

      const refreshToken = getRefreshToken();
      if (!refreshToken) {
        return token;
      }

      inflightRefresh = (async () => {
        try {
          // Proof-of-possession: sign a DPoP proof with the device's non-extractable key so the
          // server can confirm this refresh comes from the device the session was bound to.
          const refreshHeaders: Record<string, string> = { 'Content-Type': 'application/json' };
          const proof = await createDpopProof('POST', `${API_BASE}/auth/refresh`);
          if (proof) refreshHeaders['DPoP'] = proof;
          const resp = await fetch(`${API_BASE}/auth/refresh`, {
            method: 'POST',
            headers: refreshHeaders,
            credentials: 'same-origin',
            body: JSON.stringify({ refreshToken }),
          });

          if (resp.ok) {
            const data = await resp.json();
            setTokens(data.token, data.expiresAt, data.refreshToken);
            return data.token as string;
          }

          // A failed refresh used to silently fall back to the stale
          // token; now we clear everything and force re-auth so the user does not get
          // stuck in a 401 loop with widgets disagreeing on session state.
          clearTokens();
          window.location.href = `${basename}/login`;
          return null;
        } catch {
          clearTokens();
          window.location.href = `${basename}/login`;
          return null;
        } finally {
          inflightRefresh = null;
        }
      })();

      return inflightRefresh;
    }

    /**
     * Reads the CSRF double-submit cookie set by the backend. Centralized so every
     * helper uses the same regex and decoding rules.
     */
    function readCsrfCookie(): string | null {
      const m = document.cookie.match(/(?:^|;\s*)CSRF-TOKEN=([^;]*)/);
      return m ? decodeURIComponent(m[1]) : null;
    }

    function buildAuthHeaders(extra?: Record<string, string>): Record<string, string> {
      const headers: Record<string, string> = { ...(extra || {}) };
      const token = getToken();
      if (token) headers['Authorization'] = `Bearer ${token}`;
      const csrf = readCsrfCookie();
      if (csrf) headers['X-CSRF-Token'] = csrf;
      return headers;
    }

    async function api<T = any>(path: string, options: RequestInit = {}): Promise<T> {
      const token = await refreshIfNeeded();

      const headers: Record<string, string> = {
        ...(options.headers as Record<string, string> || {}),
      };

      if (token) {
        headers['Authorization'] = `Bearer ${token}`;
      }

      // CSRF double-submit: always include the token from the cookie
      const csrf = readCsrfCookie();
      if (csrf) {
        headers['X-CSRF-Token'] = csrf;
      }

      if (options.body && !headers['Content-Type']) {
        headers['Content-Type'] = 'application/json';
      }

      const resp = await fetch(`${API_BASE}${path}`, {
        ...options,
        credentials: 'same-origin',
        headers,
      });

      if (resp.status === 401) {
        // Don't redirect to login for step-up MFA verification failures — the modal
        // handles retries. The user's session is still valid; only the step-up code was wrong.
        const isStepUp = path.includes('/verify-stepup');
        if (!isStepUp) {
          clearTokens();
          window.location.href = `${basename}/login`;
        }
        const errBody = await resp.json().catch(() => ({ error: 'Unauthorized' }));
        throw new Error(errBody.error || 'Unauthorized');
      }

      if (resp.status === 403) {
        const body = await resp.text();
        try {
          const parsed = JSON.parse(body);
          if (parsed.mfaSetupRequired && !window.location.pathname.includes('/mfa-setup')) {
            localStorage.setItem('mfaSetupRequired', 'true');
            window.location.href = `${basename}/mfa-setup`;
            throw new Error('MFA setup required');
          }
          if (parsed.requiresStepUp) {
            const err = new Error(parsed.error || 'MFA re-verification required') as any;
            err.requiresStepUp = true;
            throw err;
          }
        } catch (e) {
          if (e instanceof Error && (e.message === 'MFA setup required' || (e as any).requiresStepUp)) throw e;
          // Not a JSON body or not MFA-related, fall through to normal error handling
        }
        const message = body || `HTTP ${resp.status}`;
        throw new Error(message);
      }

      if (!resp.ok) {
        const errorBody = await resp.text();
        let message = `HTTP ${resp.status}`;
        if (errorBody) {
          try {
            const parsed = JSON.parse(errorBody);
            if (parsed.errors) {
              // ASP.NET validation error format: { errors: { field: ["msg"] } }
              const details = Object.entries(parsed.errors)
                .map(([field, msgs]) => `${field}: ${(msgs as string[]).join(', ')}`)
                .join('; ');
              message = parsed.title ? `${parsed.title} — ${details}` : details;
            } else {
              message = parsed.error || parsed.message || parsed.title || errorBody;
            }
          } catch {
            message = errorBody;
          }
        }
        globalToast('error', message);
        throw new Error(message);
      }

      const text = await resp.text();
      if (!text) return undefined as T;

      try {
        return JSON.parse(text) as T;
      } catch {
        return text as unknown as T;
      }
    }

    function apiGet<T = any>(path: string): Promise<T> {
      return api<T>(path, { method: 'GET' });
    }

    function apiPost<T = any>(path: string, body?: object): Promise<T> {
      return api<T>(path, {
        method: 'POST',
        body: body ? JSON.stringify(body) : undefined,
      });
    }

    function apiPut<T = any>(path: string, body?: object): Promise<T> {
      return api<T>(path, {
        method: 'PUT',
        body: body ? JSON.stringify(body) : undefined,
      });
    }

    function apiDelete(path: string): Promise<void> {
      return api<void>(path, { method: 'DELETE' });
    }

    /**
     * Blob-aware request helper for downloads (CSV, PFX, PEM, etc.)
     * and for endpoints that return non-JSON bodies. Handles auth + CSRF + refresh in
     * exactly the same way as <see cref="api"/>, exposes the raw Response for header
     * access (e.g. Content-Disposition), and forces same-origin credentials. Pages that
     * previously hand-rolled fetch() should call this instead.
     */
    async function apiBlob(
      path: string,
      options: RequestInit = {},
    ): Promise<Response> {
      await refreshIfNeeded();

      const headers = buildAuthHeaders(options.headers as Record<string, string> | undefined);
      if (options.body && !headers['Content-Type']) {
        headers['Content-Type'] = 'application/json';
      }

      const resp = await fetch(`${API_BASE}${path}`, {
        ...options,
        credentials: 'same-origin',
        headers,
      });

      if (resp.status === 401) {
        clearTokens();
        window.location.href = `${basename}/login`;
        throw new Error('Unauthorized');
      }

      if (!resp.ok) {
        let message = `HTTP ${resp.status}`;
        let requiresStepUp = false;
        try {
          const text = await resp.clone().text();
          if (text) {
            try {
              const parsed = JSON.parse(text);
              message = parsed.error || parsed.message || parsed.title || text;
              // Forward the step-up sentinel so apiBlobWithMfa can retry with X-MFA-Token.
              if (parsed.requiresStepUp === true) requiresStepUp = true;
            } catch {
              message = text;
            }
          }
        } catch {
          // fall through with HTTP status
        }
        if (requiresStepUp) {
          const err = new Error(message) as any;
          err.requiresStepUp = true;
          throw err;
        }
        globalToast('error', message);
        throw new Error(message);
      }

      return resp;
    }

    /// Blob variant of apiWithMfa: retries the download with an X-MFA-Token header
    /// if the first attempt returns a 403 with requiresStepUp.
    async function apiBlobWithMfa(
      path: string,
      options: RequestInit,
      stepUpFn: (operation: string, targetId?: string) => Promise<string>,
      operation: string,
      targetId?: string,
    ): Promise<Response> {
      try {
        return await apiBlob(path, options);
      } catch (err: any) {
        if (isStepUpRequired(err)) {
          const mfaToken = await stepUpFn(operation, targetId);
          const headers = {
            ...(options.headers as Record<string, string> || {}),
            'X-MFA-Token': mfaToken,
          };
          return await apiBlob(path, { ...options, headers });
        }
        throw err;
      }
    }


    async function apiLogin(username: string, password: string): Promise<LoginResponse> {
      const headers: Record<string, string> = { 'Content-Type': 'application/json' };
      const csrf = readCsrfCookie();
      if (csrf) {
        headers['X-CSRF-Token'] = csrf;
      }
      // Bind the session to this device's PoP key when login completes without MFA.
      const loginProof = await createDpopProof('POST', `${API_BASE}/auth/login`);
      if (loginProof) headers['DPoP'] = loginProof;

      const resp = await fetch(`${API_BASE}/auth/login`, {
        method: 'POST',
        headers,
        credentials: 'same-origin',
        body: JSON.stringify({ username, password }),
      });

      // Handle 403 with requirePasswordChange — not a fatal error, return it to the caller
      if (resp.status === 403) {
        const body = await resp.json().catch(() => ({ error: `HTTP ${resp.status}` }));
        if (body.requirePasswordChange) {
          return { requirePasswordChange: true } as LoginResponse;
        }
        throw new Error(body.error || body.message || `Login failed (${resp.status})`);
      }

      if (!resp.ok) {
        const err = await resp.json().catch(() => ({ error: `HTTP ${resp.status}` }));
        throw new Error(err.error || err.message || `Login failed (${resp.status})`);
      }

      const data: LoginResponse = await resp.json();

      // Only store tokens when a JWT is present
      if (data.token && data.expiresAt && data.refreshToken) {
        setTokens(data.token, data.expiresAt, data.refreshToken);
      }

      // Sync the MFA setup flag with the backend response
      if (data.mfaSetupRequired) {
        localStorage.setItem('mfaSetupRequired', 'true');
      } else {
        localStorage.removeItem('mfaSetupRequired');
      }

      return data;
    }

    /// Calls the pre-JWT password change endpoint for forced password resets.
    async function apiChangePassword(
      username: string,
      oldPassword: string,
      newPassword: string,
      confirmNewPassword: string,
    ): Promise<{ message: string }> {
      const cpHeaders: Record<string, string> = { 'Content-Type': 'application/json' };
      const cpCsrf = readCsrfCookie();
      if (cpCsrf) {
        cpHeaders['X-CSRF-Token'] = cpCsrf;
      }

      const resp = await fetch(`${API_BASE}/auth/change-password`, {
        method: 'POST',
        headers: cpHeaders,
        credentials: 'same-origin',
        body: JSON.stringify({ username, oldPassword, newPassword, confirmNewPassword }),
      });

      const body = await resp.json().catch(() => ({ error: `HTTP ${resp.status}` }));

      if (!resp.ok) {
        const message = body.details
          ? `${body.error}: ${body.details.join(', ')}`
          : body.error || body.message || `Password change failed (${resp.status})`;
        throw new Error(message);
      }

      return body;
    }

    /**
     * Server-side logout. Best-effort: if the POST fails (network
     * down, token already revoked), we still clear client state and route to login.
     * Intentionally fire-and-forget on failure — the user has clicked Logout and
     * deserves to see the login screen regardless of the network outcome.
     */
    async function apiLogout() {
      try {
        const headers = buildAuthHeaders();
        await fetch(`${API_BASE}/auth/logout`, {
          method: 'POST',
          headers,
          credentials: 'same-origin',
        });
      } catch {
        // Ignore — we're logging out client-side either way.
      }
      clearTokens();
      window.location.href = `${basename}/login`;
    }

    /// Checks whether an error indicates that step-up MFA is required.
    function isStepUpRequired(err: any): boolean {
      return err?.requiresStepUp === true;
    }

    /// Wraps an API call with automatic step-up MFA handling.
    /// If the initial request returns a 403 with requiresStepUp, it invokes
    /// stepUpFn to obtain an MFA token, then retries the request with the
    /// X-MFA-Token header.
    async function apiWithMfa<T = any>(
      path: string,
      options: RequestInit,
      stepUpFn: (operation: string, targetId?: string) => Promise<string>,
      operation: string,
      targetId?: string,
    ): Promise<T> {
      try {
        return await api<T>(path, options);
      } catch (err: any) {
        if (isStepUpRequired(err)) {
          const mfaToken = await stepUpFn(operation, targetId);
          const headers = {
            ...(options.headers as Record<string, string> || {}),
            'X-MFA-Token': mfaToken,
          };
          return api<T>(path, { ...options, headers });
        }
        throw err;
      }
    }

    /// Step-up-aware POST helper.
    function apiPostWithMfa<T = any>(
      path: string,
      body: object | undefined,
      stepUpFn: (operation: string, targetId?: string) => Promise<string>,
      operation: string,
      targetId?: string,
    ): Promise<T> {
      return apiWithMfa<T>(
        path,
        { method: 'POST', body: body ? JSON.stringify(body) : undefined },
        stepUpFn,
        operation,
        targetId,
      );
    }

    /// Step-up-aware PUT helper.
    function apiPutWithMfa<T = any>(
      path: string,
      body: object | undefined,
      stepUpFn: (operation: string, targetId?: string) => Promise<string>,
      operation: string,
      targetId?: string,
    ): Promise<T> {
      return apiWithMfa<T>(
        path,
        { method: 'PUT', body: body ? JSON.stringify(body) : undefined },
        stepUpFn,
        operation,
        targetId,
      );
    }

    /// Step-up-aware DELETE helper.
    function apiDeleteWithMfa(
      path: string,
      stepUpFn: (operation: string, targetId?: string) => Promise<string>,
      operation: string,
      targetId?: string,
    ): Promise<void> {
      return apiWithMfa<void>(path, { method: 'DELETE' }, stepUpFn, operation, targetId);
    }

    return {
        API_BASE,
        getToken,
        clearTokens,
        readCsrfCookie,
        api,
        apiGet,
        apiPost,
        apiPut,
        apiDelete,
        apiBlob,
        apiBlobWithMfa,
        apiLogin,
        apiChangePassword,
        apiLogout,
        isStepUpRequired,
        apiWithMfa,
        apiPostWithMfa,
        apiPutWithMfa,
        apiDeleteWithMfa,
    };
}
