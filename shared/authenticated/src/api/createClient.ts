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
import { problemNotice } from './notices';
import { ApiError, parseProblem, type ApiProblem } from './problem';
import type { NoticeInput, NoticeSeverity } from '@shared/notifications/notice';
import { noteReported } from '@shared/notifications/reported';

/**
 * A toast notifier supplied by the consuming app.
 *
 * `message` widened from `string` to {@link NoticeInput} so this client can hand over the problem
 * it already parsed instead of flattening it back into one sentence. Both apps satisfy this with
 * `globalToast`, which accepts either arm; a notifier that only accepts strings no longer
 * type-checks, which is the intended pressure.
 */
export type ToastFn = (type: NoticeSeverity, message: NoticeInput, duration?: number) => void;

/**
 * Per-request options: everything `fetch` accepts, plus this client's own.
 *
 * `toast` is not a `RequestInit` key and is ignored by `fetch`, so the whole object can still be
 * spread straight into the call rather than being split apart at every use.
 */
export interface ApiRequestOptions extends RequestInit {
    /**
     * Set false to suppress the automatic error toast for this request.
     *
     * For callers that report the failure themselves in a form this client cannot produce — a bulk
     * action that runs N requests and wants one sentence about the batch rather than N toasts. A
     * caller that simply re-reports the same failure does NOT need this: the duplicate is already
     * suppressed. See shared/common/src/notifications/reported.ts.
     */
    toast?: boolean;
}

export interface AuthClientConfig {
    /** Route basename for this SPA: '/admin' or '/user' (or '' on the site-root sign-in pages).
     *  Used for same-origin detection. */
    basename: string;
    /** Where a 401 sends the browser. Defaults to `${basename}/login`; the console passes the
     *  site-root `/login` its sign-in pages live at. A function is evaluated at redirect time. */
    loginPath?: string | (() => string);
    /** Where a "set up MFA first" response sends the browser. Defaults to `${basename}/mfa-setup`. */
    mfaSetupPath?: string;
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

/** Web Locks name shared by every SPA on the origin that rotates the refresh token. */
export const REFRESH_LOCK_NAME = 'modularca-token-refresh';

/** A refresh still pending after this long is abandoned so the cross-tab lock is released. */
export const REFRESH_TIMEOUT_MS = 15_000;

/** A refresh that failed transiently (network, timeout, 429, 5xx); the stored session is left intact. */
export class SessionRefreshError extends Error {
    readonly status?: number;
    constructor(status?: number) {
        super('Could not refresh your session. Check your connection and try again.');
        this.name = 'SessionRefreshError';
        this.status = status;
        Object.setPrototypeOf(this, SessionRefreshError.prototype);
    }
}

/** Work done under the refresh lock by {@link withSessionRefreshToken} ran past REFRESH_TIMEOUT_MS; the session is left intact. */
export class SessionRequestTimeoutError extends Error {
    constructor() {
        super('The request timed out. Check your connection and try again.');
        this.name = 'SessionRequestTimeoutError';
        Object.setPrototypeOf(this, SessionRequestTimeoutError.prototype);
    }
}

export function createAuthClient(config: AuthClientConfig) {
    const basename = config.basename;
    const loginPathConfig = config.loginPath ?? `${basename}/login`;
    const loginPath = () => (typeof loginPathConfig === 'function' ? loginPathConfig() : loginPathConfig);
    const mfaSetupPath = config.mfaSetupPath ?? `${basename}/mfa-setup`;
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

    /** The rotation actually executing in this tab; every rotate joins it, with or without Web Locks. */
    let inflightRotate: Promise<string | null> | null = null;

    function rotateOnce(intended: string, force = false): Promise<string | null> {
      if (!inflightRotate) {
        inflightRotate = rotate(intended, force).finally(() => { inflightRotate = null; });
      }
      return inflightRotate;
    }

    function inRefreshWindow(): boolean {
      const expiry = getExpiry();
      return !!getToken() && expiry > 0 && expiry - Date.now() < 5 * 60 * 1000;
    }

    /**
     * Serialises refreshes across every tab of this origin. The server revokes the whole token
     * family when a rotated refresh token is replayed, so two tabs racing with the same token
     * would log out every tab. Without the Web Locks API this degrades to the in-tab guard only.
     */
    function withRefreshLock<T>(fn: () => Promise<T>): Promise<T> {
      const locks = typeof navigator !== 'undefined' ? navigator.locks : undefined;
      return locks?.request ? locks.request(REFRESH_LOCK_NAME, fn) : fn();
    }

    /**
     * Rotates `intended` unless another tab already did (stored token changed or the access
     * token is fresh again; `force` skips the freshness check). Only 400/401/403 end the session;
     * anything else throws {@link SessionRefreshError} and leaves the shared tokens alone.
     */
    async function rotate(intended: string, force = false): Promise<string | null> {
      const stored = getRefreshToken();
      if (!stored || stored !== intended || (!force && !inRefreshWindow())) return getToken();

      const abort = new AbortController();
      let timedOut!: () => void;
      const deadline = new Promise<never>((_, reject) => {
        timedOut = () => reject(new SessionRefreshError());
      });
      deadline.catch(() => undefined);
      const timer = setTimeout(() => { abort.abort(); timedOut(); }, REFRESH_TIMEOUT_MS);
      const bounded = <T>(p: Promise<T>) => Promise.race([p, deadline]);

      try {
        let resp: Response;
        try {
          const refreshHeaders: Record<string, string> = { 'Content-Type': 'application/json' };
          const proof = await bounded(createDpopProof('POST', `${API_BASE}/auth/refresh`));
          if (proof) refreshHeaders['DPoP'] = proof;
          resp = await bounded(fetch(`${API_BASE}/auth/refresh`, {
            method: 'POST',
            headers: refreshHeaders,
            credentials: 'same-origin',
            body: JSON.stringify({ refreshToken: stored }),
            signal: abort.signal,
          }));
        } catch {
          throw new SessionRefreshError();
        }

        if (resp.ok) {
          const data = await bounded(resp.json()).catch(() => null);
          if (!data?.token || !data.expiresAt || !data.refreshToken) throw new SessionRefreshError(resp.status);
          setTokens(data.token, data.expiresAt, data.refreshToken);
          return data.token as string;
        }

        if (resp.status === 400 || resp.status === 401 || resp.status === 403) {
          clearTokens();
          window.location.href = loginPath();
          return null;
        }
        throw new SessionRefreshError(resp.status);
      } finally {
        clearTimeout(timer);
      }
    }

    async function refreshIfNeeded(): Promise<string | null> {
      const token = getToken();
      if (!inRefreshWindow()) return token;

      if (!inflightRefresh) {
        const intended = getRefreshToken();
        if (!intended) return token;
        inflightRefresh = withRefreshLock(() => rotateOnce(intended))
          .finally(() => { inflightRefresh = null; });
      }

      try {
        return await inflightRefresh;
      } catch (e) {
        const current = getToken();
        if (current && getExpiry() > Date.now()) return current;
        throw e;
      }
    }

    /**
     * Rotates the refresh token now, whatever the local expiry says: for a caller whose access token
     * the server rejected although this client thinks it valid (clock skew). Shares the lock and
     * single-flight of every other rotation, so a token another tab just rotated is not re-sent.
     * Resolves to the current access token, or null once the session has ended (tokens cleared and
     * the browser sent to login); throws {@link SessionRefreshError} on a transient failure.
     */
    async function forceRefresh(): Promise<string | null> {
      const intended = getRefreshToken();
      if (!intended) return null;
      if (inflightRefresh) await inflightRefresh.catch(() => undefined);
      return withRefreshLock(() => rotateOnce(intended, true));
    }

    /**
     * Runs `fn` holding the cross-tab refresh lock, after any due rotation, with the refresh token
     * current at that moment, so an endpoint that takes the refresh token in its body can never be
     * sent one another tab has already rotated. `request` is {@link api} minus the refresh step,
     * which would otherwise wait on the lock held here. `fn` is bounded by REFRESH_TIMEOUT_MS: on
     * expiry its requests are aborted, the lock is released and {@link SessionRequestTimeoutError}
     * is thrown with the tokens untouched.
     */
    async function withSessionRefreshToken<T>(
      fn: (refreshToken: string, request: <R = any>(path: string, options?: ApiRequestOptions) => Promise<R>) => Promise<T>,
    ): Promise<T> {
      if (inflightRefresh) await inflightRefresh.catch(() => undefined);
      return withRefreshLock(async () => {
        const intended = getRefreshToken();
        if (intended && inRefreshWindow()) {
          try {
            await rotateOnce(intended);
          } catch (e) {
            if (!getToken() || getExpiry() <= Date.now()) throw e;
          }
        }
        const refreshToken = getRefreshToken();
        if (!refreshToken) throw new Error('No session refresh token; sign in again.');

        const expired = new AbortController();
        let timedOut!: (e: Error) => void;
        const deadline = new Promise<never>((_, reject) => { timedOut = reject; });
        deadline.catch(() => undefined);
        const timer = setTimeout(() => { timedOut(new SessionRequestTimeoutError()); expired.abort(); }, REFRESH_TIMEOUT_MS);

        const request = <R = any>(path: string, options: ApiRequestOptions = {}): Promise<R> => {
          if (expired.signal.aborted) return Promise.reject(new SessionRequestTimeoutError());
          const ctl = new AbortController();
          const cancel = () => ctl.abort();
          const outer = options.signal;
          expired.signal.addEventListener('abort', cancel);
          outer?.addEventListener('abort', cancel);
          if (outer?.aborted) ctl.abort();
          return send<R>(path, { ...options, signal: ctl.signal }, getToken()).finally(() => {
            expired.signal.removeEventListener('abort', cancel);
            outer?.removeEventListener('abort', cancel);
          });
        };

        try {
          return await Promise.race([fn(refreshToken, request), deadline]);
        } finally {
          clearTimeout(timer);
        }
      });
    }

    /** Replaces the access token for the current session, keeping its refresh token. */
    function storeAccessToken(token: string, expiresAt: string) {
      const refreshToken = getRefreshToken();
      if (!refreshToken) throw new Error('No session refresh token; sign in again.');
      setTokens(token, expiresAt, refreshToken);
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

    async function api<T = any>(path: string, options: ApiRequestOptions = {}): Promise<T> {
      return send<T>(path, options, await refreshIfNeeded());
    }

    async function send<T>(path: string, options: ApiRequestOptions, token: string | null): Promise<T> {
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
          window.location.href = loginPath();
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
            window.location.href = mfaSetupPath;
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
        // Deliberately not toasted: a 403 that is not an MFA sentinel is surfaced by the
        // caller, which usually has somewhere better to put it than a corner of the screen.
        throw new ApiError(parseProblem(resp.status, body, resp.headers));
      }

      if (!resp.ok) {
        const problem = parseProblem(resp.status, await resp.text(), resp.headers);
        // `toast: false` is for a caller that reports the failure itself in a form this cannot
        // produce — a bulk action summarising "3 of 12 failed" wants one sentence about the batch,
        // not one toast per request. Everything else keeps the safety net.
        if (options.toast !== false) {
          // The structure, not `problem.message`. The client is holding a parsed title, detail,
          // remediation, code and correlation id at this point, and composing them into one string
          // here only to have the toast render that string was the last place the structure was
          // being thrown away. `err.message` is unaffected: ApiError still carries the composed line
          // for the call sites that catch and toast it.
          globalToast('error', problemNotice(problem));
          // ...and having toasted it, record the composed line so that the call site catching this
          // error and toasting `err.message` — which about a hundred of them do — does not put the
          // same failure on screen a second time in a strictly worse form.
          noteReported(problem.message);
        }
        throw new ApiError(problem);
      }

      const text = await resp.text();
      if (!text) return undefined as T;

      // Only attempt a JSON parse when the server said it sent JSON. Several endpoints return
      // application/x-pem-file, application/pkix-cert, CSV or text/plain, and inferring the shape
      // from whether JSON.parse happened to throw is guesswork: it silently maps a malformed JSON
      // body to a string rather than surfacing it.
      //
      // This does not by itself fix the issuance shape problem. /issue and /reissue return
      // `{pem, warnings}` when warnings exist and a bare PEM otherwise, so callers such as
      // CertificateReissueModal read `result.newSerialNumber` off a string on the common path and
      // always fall back to "new serial unknown". That needs the endpoints to return one shape.
      const contentType = resp.headers.get('content-type') ?? '';
      if (!/json/i.test(contentType)) {
        return text as unknown as T;
      }

      try {
        return JSON.parse(text) as T;
      } catch {
        return text as unknown as T;
      }
    }

    function apiGet<T = any>(path: string, options: ApiRequestOptions = {}): Promise<T> {
      return api<T>(path, { ...options, method: 'GET' });
    }

    function apiPost<T = any>(path: string, body?: object, options: ApiRequestOptions = {}): Promise<T> {
      return api<T>(path, {
        ...options,
        method: 'POST',
        body: body ? JSON.stringify(body) : undefined,
      });
    }

    function apiPut<T = any>(path: string, body?: object, options: ApiRequestOptions = {}): Promise<T> {
      return api<T>(path, {
        ...options,
        method: 'PUT',
        body: body ? JSON.stringify(body) : undefined,
      });
    }

    function apiDelete(path: string, options: ApiRequestOptions = {}): Promise<void> {
      return api<void>(path, { ...options, method: 'DELETE' });
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
      options: ApiRequestOptions = {},
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
        window.location.href = loginPath();
        throw new Error('Unauthorized');
      }

      if (!resp.ok) {
        let problem: ApiProblem;
        try {
          problem = parseProblem(resp.status, await resp.clone().text(), resp.headers);
        } catch {
          // Reading the body failed; report the status rather than losing the error entirely.
          problem = parseProblem(resp.status, '', resp.headers);
        }
        const err = new ApiError(problem);
        // Forward the step-up sentinel so apiBlobWithMfa can retry with X-MFA-Token.
        if ((problem.raw as { requiresStepUp?: unknown } | undefined)?.requiresStepUp === true) {
          err.requiresStepUp = true;
          throw err;
        }
        if (options.toast !== false) {
          globalToast('error', problemNotice(problem));
          noteReported(problem.message);
        }
        throw err;
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
      window.location.href = loginPath();
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
        forceRefresh,
        withSessionRefreshToken,
        storeAccessToken,
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
