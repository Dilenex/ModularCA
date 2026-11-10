import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { createAuthClient } from '@shared-auth/api/createClient';
import { rateLimitMessage, retryAfterSeconds } from '@shared-auth/api/rateLimit';

/**
 * A 429 on the sign-in pages. LoginRateLimitMiddleware answers
 * `{ error: "Too many requests. Try again later.", retryAfterSeconds }` with a Retry-After header;
 * a proxy in front may answer 429 with no JSON, which reached the page as "HTTP 429".
 */
const json = (status: number, body: unknown, headers: Record<string, string> = {}) =>
    new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json', ...headers } });

/** The limiter's answer for a window of `minutes`. */
const limited = (minutes: number) =>
    json(429, { error: 'Too many requests. Try again later.', retryAfterSeconds: minutes * 60 }, { 'Retry-After': String(minutes * 60) });

describe('retryAfterSeconds', () => {
    it('reads the body first, then the header', () => {
        expect(retryAfterSeconds({ retryAfterSeconds: 900 }, '300')).toBe(900);
        expect(retryAfterSeconds({ error: 'x' }, '300')).toBe(300);
        expect(retryAfterSeconds(null, ' 300 ')).toBe(300);
    });

    it('is null when neither names a wait', () => {
        expect(retryAfterSeconds({ error: 'HTTP 429' }, null)).toBeNull();
        expect(retryAfterSeconds(undefined, undefined)).toBeNull();
        expect(retryAfterSeconds({ retryAfterSeconds: 0 }, '0')).toBeNull();
        expect(retryAfterSeconds({ retryAfterSeconds: '900' }, '')).toBeNull();
        expect(retryAfterSeconds({ retryAfterSeconds: Number.NaN }, '-5')).toBeNull();
    });

    it('does not read the HTTP-date form of the header', () => {
        expect(retryAfterSeconds(null, 'Wed, 21 Oct 2026 07:28:00 GMT')).toBeNull();
    });
});

describe('rateLimitMessage', () => {
    it('gives the wait in minutes, as an upper bound', () => {
        expect(rateLimitMessage({ retryAfterSeconds: 900 }, null)).toBe('Too many attempts. Wait up to 15 minutes, then try again.');
        expect(rateLimitMessage(null, '300')).toBe('Too many attempts. Wait up to 5 minutes, then try again.');
    });

    it('rounds a part of a minute up', () => {
        expect(rateLimitMessage({ retryAfterSeconds: 61 }, null)).toBe('Too many attempts. Wait up to 2 minutes, then try again.');
        expect(rateLimitMessage({ retryAfterSeconds: 30 }, null)).toBe('Too many attempts. Wait up to a minute, then try again.');
    });

    it('still reads as a sentence when the answer names no wait', () => {
        expect(rateLimitMessage({ error: 'HTTP 429' }, null)).toBe('Too many attempts. Wait a few minutes, then try again.');
    });
});

describe('the sign-in calls on a 429', () => {
    let fetchMock: ReturnType<typeof vi.fn>;
    const client = () => createAuthClient({ basename: '/admin', loginPath: '/login' });

    beforeEach(() => {
        fetchMock = vi.fn();
        vi.stubGlobal('localStorage', { getItem: () => null, setItem: () => { }, removeItem: () => { } });
        vi.stubGlobal('window', { location: { pathname: '/admin/login', origin: 'https://ca.test', href: '/admin/login' } });
        vi.stubGlobal('document', { cookie: '' });
        vi.stubGlobal('fetch', fetchMock);
        vi.stubGlobal('navigator', {});
    });

    afterEach(() => {
        vi.unstubAllGlobals();
    });

    it('login says how long to wait', async () => {
        fetchMock.mockResolvedValue(limited(5));
        await expect(client().apiLogin('admin', 'pw')).rejects.toThrow('Too many attempts. Wait up to 5 minutes, then try again.');
    });

    it('login reads as a sentence when a proxy answers 429 without JSON', async () => {
        // Was "HTTP 429".
        fetchMock.mockResolvedValue(new Response('<html>429 Too Many Requests</html>', { status: 429 }));
        await expect(client().apiLogin('admin', 'pw')).rejects.toThrow('Too many attempts. Wait a few minutes, then try again.');
    });

    it('login uses the Retry-After header when the body names no wait', async () => {
        fetchMock.mockResolvedValue(new Response('slow down', { status: 429, headers: { 'Retry-After': '120' } }));
        await expect(client().apiLogin('admin', 'pw')).rejects.toThrow('Too many attempts. Wait up to 2 minutes, then try again.');
    });

    it('the forced password change says how long to wait', async () => {
        fetchMock.mockResolvedValue(limited(5));
        await expect(client().apiChangePassword('admin', 'old', 'new', 'new')).rejects.toThrow('Too many attempts. Wait up to 5 minutes, then try again.');
    });

    it('claim says how long to wait: its window is 15 minutes', async () => {
        fetchMock.mockResolvedValue(limited(15));
        await expect(client().apiClaimAccount('tok', 'pw', 'pw')).rejects.toThrow('Too many attempts. Wait up to 15 minutes, then try again.');
    });

    it('other refusals keep the server\'s sentence', async () => {
        fetchMock.mockResolvedValue(json(401, { error: 'Invalid username or password' }));
        await expect(client().apiLogin('admin', 'pw')).rejects.toThrow('Invalid username or password');
    });
});
