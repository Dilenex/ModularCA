import { createAuthClient } from '@shared-auth/api/createClient';
import { globalToast } from '@shared/context/ToastContext';
import { BASENAME, LOGIN_PATH, MFA_SETUP_PATH } from '../portal';

/**
 * This app's authenticated API client.
 *
 * The implementation lives in `@shared-auth/api/createClient`. It used to be a full copy here and
 * another in the (since merged) user portal app, and the copies drifted: this one carried the
 * single-flight refresh guard and DPoP binding that the other lacked.
 *
 * Everything below is re-export, so existing call sites (`import { apiGet } from '../api/client'`)
 * are unchanged.
 */
// The basename follows the portal this bundle was loaded under (`/admin`, `/user`, or `` on the
// sign-in pages). The sign-in pages themselves sit at the site root, shared by both portals, so
// a 401 anywhere bounces to the one /login.
const client = createAuthClient({ basename: BASENAME, loginPath: LOGIN_PATH, mfaSetupPath: MFA_SETUP_PATH, toast: globalToast });


/**
 * The same instance, exported whole so App.tsx can hand it to <AuthClientProvider> for
 * shared pages. The named re-exports below remain the idiom for this app's own code.
 */
export const authClient = client;

export const {
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
} = client;

export type { LoginResponse } from '@shared-auth/api/createClient';

/** Same-origin when served under the app's basename; otherwise the configured API origin. */
export const API_BASE = (window.location.pathname.startsWith(BASENAME)
    ? ''
    : ((import.meta as any).env?.VITE_API_URL as string | undefined) || '');

/**
 * Fetches every page of a paginated list endpoint and returns the concatenated items.
 *
 * Endpoints like `/api/v1/user/certificates` return `{ total, page, pageSize, totalPages, items }`
 * and default to 25 per page. Callers that render into a client-side-paging DataTable were doing
 * a plain apiGet and taking `.items`, which silently capped them at the FIRST page — a user with
 * more than 25 certificates simply never saw the rest, including ones just issued.
 *
 * `maxPages` bounds the work for pathological accounts; when it truncates, `truncated` says so
 * rather than quietly showing a partial list.
 */
export async function apiGetAllPages<T = any>(
    path: string,
    pageSize = 100,
    maxPages = 20,
): Promise<{ items: T[]; total: number; truncated: boolean }> {
    const sep = path.includes('?') ? '&' : '?';
    const first: any = await apiGet<any>(`${path}${sep}page=1&pageSize=${pageSize}`);

    // Tolerate an endpoint that returns a bare array rather than an envelope.
    if (Array.isArray(first)) return { items: first as T[], total: first.length, truncated: false };

    const items: T[] = [...(first.items ?? [])];
    const totalPages: number = first.totalPages ?? 1;
    const pagesToFetch = Math.min(totalPages, maxPages);

    for (let page = 2; page <= pagesToFetch; page++) {
        const next: any = await apiGet<any>(`${path}${sep}page=${page}&pageSize=${pageSize}`);
        items.push(...(next.items ?? []));
    }

    return { items, total: first.total ?? items.length, truncated: totalPages > pagesToFetch };
}
