import { globalToast } from '../context/ToastContext';
import { readCsrfCookie } from '@shared/csrf';

// Synced with the admin client. Same-origin in
// production builds; the dev fallback URL is no longer hardcoded so a missing
// VITE_API_URL surfaces as 404s instead of silently shipping the wrong port.
const isSameOrigin = window.location.pathname.startsWith('/public');
const VITE_API_URL = (import.meta as any).env?.VITE_API_URL as string | undefined;
const API_BASE = isSameOrigin ? '' : (VITE_API_URL || '');
if (!isSameOrigin && !VITE_API_URL) {
    // eslint-disable-next-line no-console
    console.warn('[modularca-publicui] VITE_API_URL is not set; API calls will be sent to the current origin.');
}

export async function api<T = any>(path: string, options: RequestInit = {}): Promise<T> {
    const headers: Record<string, string> = {
        ...(options.headers as Record<string, string> || {}),
    };

    // Send CSRF on every request so consistency is enforced
    // regardless of helper used. The backend ignores it on safe methods.
    const csrf = readCsrfCookie();
    if (csrf) headers['X-CSRF-Token'] = csrf;

    if (options.body && !headers['Content-Type']) {
        headers['Content-Type'] = 'application/json';
    }

    const resp = await fetch(`${API_BASE}${path}`, {
        ...options,
        credentials: 'same-origin',
        headers,
    });

    if (!resp.ok) {
        const text = await resp.text();
        let message = `HTTP ${resp.status}`;
        if (text) {
            try {
                const parsed = JSON.parse(text);
                if (parsed.errors) {
                    const details = Object.entries(parsed.errors)
                        .map(([field, msgs]) => `${field}: ${(msgs as string[]).join(', ')}`)
                        .join('; ');
                    message = parsed.title ? `${parsed.title} — ${details}` : details;
                } else {
                    message = parsed.error || parsed.message || parsed.title || text;
                }
            } catch {
                message = text;
            }
        }
        // Surface every non-2xx via the existing ToastContext.
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

export const apiGet = <T = any>(path: string) => api<T>(path, { method: 'GET' });

export const apiPost = <T = any>(path: string, body?: object) =>
    api<T>(path, {
        method: 'POST',
        body: body ? JSON.stringify(body) : undefined,
    });

export const apiPut = <T = any>(path: string, body?: object) =>
    api<T>(path, {
        method: 'PUT',
        body: body ? JSON.stringify(body) : undefined,
    });

export const apiDelete = (path: string) => api<void>(path, { method: 'DELETE' });

export { API_BASE };
