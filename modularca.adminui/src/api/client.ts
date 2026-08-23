import { createAuthClient } from '@shared-auth/api/createClient';
import { globalToast } from '../context/ToastContext';

/**
 * This app's authenticated API client.
 *
 * The implementation lives in `@shared-auth/api/createClient` and is shared with modularca.userui.
 * It used to be a full copy here, and the copies drifted: this one carried the single-flight refresh guard and DPoP binding that userui lacked.
 *
 * Everything below is re-export, so existing call sites (`import { apiGet } from '../api/client'`)
 * are unchanged.
 */
const client = createAuthClient({ basename: '/admin', toast: globalToast });

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
export const API_BASE = (window.location.pathname.startsWith('/admin')
    ? ''
    : ((import.meta as any).env?.VITE_API_URL as string | undefined) || '');
