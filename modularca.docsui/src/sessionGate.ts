export type VerifyResult = 'ok' | 'redirecting' | 'error';

export interface SessionGateDeps {
    hasToken(): boolean;
    verify(): Promise<VerifyResult>;
    redirectToLogin(): void;
    now?(): number;
}

/** Server re-verification is skipped on navigation until the last success is this old. */
export const REVERIFY_AFTER_MS = 5 * 60 * 1000;
/** Floor between server checks triggered by the tab becoming visible. */
export const VISIBLE_REVERIFY_AFTER_MS = 30 * 1000;

const SESSION_KEYS = new Set(['authToken', 'refreshToken', 'expiresAt']);

/**
 * Keeps a docs tab honest after the initial /me check: every navigation confirms a token is still
 * stored, the server is re-asked only when the tab becomes visible or the last check is stale, and
 * a sign-out in another tab (seen as a `storage` event) redirects at once.
 */
export function createSessionGate(deps: SessionGateDeps) {
    const now = deps.now ?? Date.now;
    let lastVerified = -Infinity;
    let pending: Promise<VerifyResult> | null = null;

    function verify(): Promise<VerifyResult> {
        pending ??= deps.verify()
            .then((r) => { if (r === 'ok') lastVerified = now(); return r; })
            .finally(() => { pending = null; });
        return pending;
    }

    function ensureToken(): boolean {
        if (deps.hasToken()) return true;
        deps.redirectToLogin();
        return false;
    }

    function onNavigate() {
        if (ensureToken() && now() - lastVerified > REVERIFY_AFTER_MS) void verify();
    }

    function onVisible() {
        if (ensureToken() && now() - lastVerified > VISIBLE_REVERIFY_AFTER_MS) void verify();
    }

    function onStorage(key: string | null) {
        if ((key === null || SESSION_KEYS.has(key)) && !deps.hasToken()) deps.redirectToLogin();
    }

    /** Subscribes to `storage` on `win` and `visibilitychange` on `doc`; returns the unsubscribe. */
    function watch(win: EventTarget, doc: EventTarget & { visibilityState?: string }) {
        const storage = (e: Event) => onStorage((e as StorageEvent).key ?? null);
        const visibility = () => { if (doc.visibilityState === 'visible') onVisible(); };
        win.addEventListener('storage', storage);
        doc.addEventListener('visibilitychange', visibility);
        return () => {
            win.removeEventListener('storage', storage);
            doc.removeEventListener('visibilitychange', visibility);
        };
    }

    return { verify, onNavigate, onVisible, onStorage, watch };
}
