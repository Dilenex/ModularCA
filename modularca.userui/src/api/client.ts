import { createAuthClient } from '@shared-auth/api/createClient';
import { globalToast } from '../context/ToastContext';

/**
 * This app's authenticated API client.
 *
 * The implementation lives in `@shared-auth/api/createClient` and is shared with modularca.adminui.
 * It used to be a full copy here, and the copies drifted: this one had NO single-flight refresh guard, so concurrent requests fired concurrent
 * /auth/refresh calls with the same token and the backend's family-compromise detection
 * hard-logged the user out. It had no DPoP binding either. Both arrive with the shared
 * implementation.
 *
 * Everything below is re-export, so existing call sites (`import { apiGet } from '../api/client'`)
 * are unchanged.
 */
const client = createAuthClient({ basename: '/user', toast: globalToast });

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
export const API_BASE = (window.location.pathname.startsWith('/user')
    ? ''
    : ((import.meta as any).env?.VITE_API_URL as string | undefined) || '');
