import { readCsrfCookie } from '@shared/csrf';

/// Reads the CSRF cookie (`__Host-CSRF-TOKEN` over HTTPS, `CSRF-TOKEN` over plain HTTP) for the X-CSRF-Token header.
export function getCsrfToken(): string {
    return readCsrfCookie() ?? '';
}

/// Returns headers object with CSRF token included.
export function csrfHeaders(extra?: Record<string, string>): Record<string, string> {
    return {
        'Content-Type': 'application/json',
        'X-CSRF-Token': getCsrfToken(),
        ...extra,
    };
}
