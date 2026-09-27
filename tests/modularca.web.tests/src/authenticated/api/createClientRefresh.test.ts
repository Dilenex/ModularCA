import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { createAuthClient, REFRESH_LOCK_NAME, REFRESH_TIMEOUT_MS, SessionRefreshError, SessionRequestTimeoutError } from '@shared-auth/api/createClient';

/**
 * Refresh-token rotation in the shared client. The server revokes the whole token family when an
 * already-rotated refresh token is replayed, so these pin that concurrent refreshes (in one tab,
 * or across tabs sharing localStorage) send exactly one POST, and that a transient failure never
 * wipes the session every other tab is using.
 */

class MemoryStorage {
    private map = new Map<string, string>();
    getItem(k: string) { return this.map.has(k) ? this.map.get(k)! : null; }
    setItem(k: string, v: string) { this.map.set(k, String(v)); }
    removeItem(k: string) { this.map.delete(k); }
    clear() { this.map.clear(); }
}

/** Minimal Web Locks stand-in: one exclusive FIFO queue per name, shared by every "tab". */
function makeLocks() {
    const tails = new Map<string, Promise<unknown>>();
    const names: string[] = [];
    return {
        names,
        request<T>(name: string, fn: () => Promise<T>): Promise<T> {
            names.push(name);
            const prev = tails.get(name) ?? Promise.resolve();
            const run = prev.then(() => fn());
            tails.set(name, run.catch(() => undefined));
            return run;
        },
    };
}

const deferred = <T>() => {
    let resolve!: (v: T) => void;
    const promise = new Promise<T>((r) => { resolve = r; });
    return { promise, resolve };
};

const json = (status: number, body: unknown) =>
    new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } });

let storage: MemoryStorage;
let win: { location: { pathname: string; origin: string; href: string } };
let fetchMock: ReturnType<typeof vi.fn>;

function seedSession(expiresInMs: number, refreshToken = 'rt-1', token = 'at-1') {
    storage.setItem('authToken', token);
    storage.setItem('refreshToken', refreshToken);
    storage.setItem('expiresAt', new Date(Date.now() + expiresInMs).toISOString());
}

const refreshCalls = () => fetchMock.mock.calls.filter(([url]) => String(url).endsWith('/auth/refresh'));
const authHeaderOf = (url: string) =>
    (fetchMock.mock.calls.find(([u]) => u === url)?.[1]?.headers as Record<string, string>)?.Authorization;

const newClient = () => createAuthClient({ basename: '/admin', loginPath: '/login' });

beforeEach(() => {
    storage = new MemoryStorage();
    win = { location: { pathname: '/admin/dashboard', origin: 'https://ca.test', href: '/admin/dashboard' } };
    fetchMock = vi.fn();
    vi.stubGlobal('localStorage', storage);
    vi.stubGlobal('window', win);
    vi.stubGlobal('document', { cookie: '' });
    vi.stubGlobal('fetch', fetchMock);
    vi.stubGlobal('navigator', {});
});

afterEach(() => {
    vi.useRealTimers();
    vi.unstubAllGlobals();
});

describe('refresh single-flight', () => {
    it('two concurrent requests in one tab send one refresh POST (no Web Locks)', async () => {
        seedSession(60_000);
        const gate = deferred<void>();
        fetchMock.mockImplementation(async (url: string) => {
            if (url.endsWith('/auth/refresh')) {
                await gate.promise;
                return json(200, { token: 'at-2', expiresAt: new Date(Date.now() + 3_600_000).toISOString(), refreshToken: 'rt-2' });
            }
            return json(200, { ok: true });
        });
        const client = newClient();
        const both = Promise.all([client.apiGet('/api/v1/a'), client.apiGet('/api/v1/b')]);
        gate.resolve();
        await both;

        expect(refreshCalls()).toHaveLength(1);
        expect(storage.getItem('refreshToken')).toBe('rt-2');
        expect(authHeaderOf('/api/v1/a')).toBe('Bearer at-2');
        expect(authHeaderOf('/api/v1/b')).toBe('Bearer at-2');
    });

    it('two tabs refreshing the same token at once send one refresh POST under the lock', async () => {
        const locks = makeLocks();
        vi.stubGlobal('navigator', { locks });
        seedSession(60_000);
        fetchMock.mockImplementation(async (url: string, init: RequestInit) => {
            if (url.endsWith('/auth/refresh')) {
                const sent = JSON.parse(String(init.body)).refreshToken;
                expect(sent).toBe('rt-1');
                return json(200, { token: 'at-2', expiresAt: new Date(Date.now() + 3_600_000).toISOString(), refreshToken: 'rt-2' });
            }
            return json(200, { ok: true });
        });
        const tabA = newClient();
        const tabB = newClient();
        await Promise.all([tabA.apiGet('/api/v1/a'), tabB.apiGet('/api/v1/b')]);

        expect(locks.names).toEqual([REFRESH_LOCK_NAME, REFRESH_LOCK_NAME]);
        expect(refreshCalls()).toHaveLength(1);
        expect(authHeaderOf('/api/v1/a')).toBe('Bearer at-2');
        expect(authHeaderOf('/api/v1/b')).toBe('Bearer at-2');
    });

    it('skips the POST when another tab rotated the token while this one waited for the lock', async () => {
        vi.stubGlobal('navigator', {
            locks: {
                request: async <T>(_name: string, fn: () => Promise<T>) => {
                    seedSession(3_600_000, 'rt-other', 'at-other');
                    return fn();
                },
            },
        });
        seedSession(60_000);
        fetchMock.mockImplementation(async () => json(200, { ok: true }));

        await newClient().apiGet('/api/v1/a');

        expect(refreshCalls()).toHaveLength(0);
        expect(authHeaderOf('/api/v1/a')).toBe('Bearer at-other');
    });

    it('skips the POST when the stored refresh token changed even if still near expiry', async () => {
        vi.stubGlobal('navigator', {
            locks: {
                request: async <T>(_name: string, fn: () => Promise<T>) => {
                    seedSession(60_000, 'rt-other', 'at-other');
                    return fn();
                },
            },
        });
        seedSession(60_000);
        fetchMock.mockImplementation(async () => json(200, { ok: true }));

        await newClient().apiGet('/api/v1/a');

        expect(refreshCalls()).toHaveLength(0);
        expect(authHeaderOf('/api/v1/a')).toBe('Bearer at-other');
    });
});

describe('refresh failure handling', () => {
    it.each([503, 500, 429])('a %i from /auth/refresh keeps the tokens and proceeds while the access token is still valid', async (status) => {
        seedSession(60_000);
        fetchMock.mockImplementation(async (url: string) =>
            url.endsWith('/auth/refresh') ? json(status, { error: 'busy' }) : json(200, { ok: true }));

        await newClient().apiGet('/api/v1/a');

        expect(storage.getItem('authToken')).toBe('at-1');
        expect(storage.getItem('refreshToken')).toBe('rt-1');
        expect(win.location.href).toBe('/admin/dashboard');
        expect(authHeaderOf('/api/v1/a')).toBe('Bearer at-1');
    });

    it('a network error on refresh with an expired access token throws SessionRefreshError and clears nothing', async () => {
        seedSession(-1_000);
        storage.setItem('mfaSetupRequired', 'true');
        fetchMock.mockImplementation(async (url: string) => {
            if (url.endsWith('/auth/refresh')) throw new TypeError('Failed to fetch');
            return json(200, { ok: true });
        });

        await expect(newClient().apiBlob('/api/v1/me')).rejects.toBeInstanceOf(SessionRefreshError);

        expect(storage.getItem('authToken')).toBe('at-1');
        expect(storage.getItem('refreshToken')).toBe('rt-1');
        expect(storage.getItem('mfaSetupRequired')).toBe('true');
        expect(win.location.href).toBe('/admin/dashboard');
        expect(fetchMock.mock.calls.some(([u]) => u === '/api/v1/me')).toBe(false);
    });

    it.each([400, 401])('a %i from /auth/refresh ends the session and redirects to login', async (status) => {
        seedSession(-1_000);
        storage.setItem('mfaSetupRequired', 'true');
        fetchMock.mockImplementation(async (url: string) =>
            url.endsWith('/auth/refresh') ? json(status, { error: 'invalid_grant' }) : json(401, {}));

        await expect(newClient().apiBlob('/api/v1/me')).rejects.toThrow();

        expect(storage.getItem('authToken')).toBeNull();
        expect(storage.getItem('refreshToken')).toBeNull();
        expect(storage.getItem('expiresAt')).toBeNull();
        expect(storage.getItem('mfaSetupRequired')).toBeNull();
        expect(win.location.href).toBe('/login');
    });
});

/** A fetch that never answers, rejecting only when its signal aborts, as a real hung request does. */
const hang = (init?: RequestInit) => new Promise<Response>((_, reject) => {
    init?.signal?.addEventListener('abort', () => reject(new DOMException('aborted', 'AbortError')));
});

describe('refresh timeout', () => {
    it('a hung /auth/refresh times out as SessionRefreshError, keeps the tokens and releases the lock', async () => {
        vi.useFakeTimers({ toFake: ['setTimeout', 'clearTimeout'] });
        const locks = makeLocks();
        vi.stubGlobal('navigator', { locks });
        seedSession(-1_000);
        let hung = true;
        fetchMock.mockImplementation(async (url: string, init?: RequestInit) => {
            if (url.endsWith('/auth/refresh')) {
                if (hung) return hang(init);
                return json(200, { token: 'at-2', expiresAt: new Date(Date.now() + 3_600_000).toISOString(), refreshToken: 'rt-2' });
            }
            return json(200, { ok: true });
        });
        const client = newClient();

        const first = expect(client.apiBlob('/api/v1/me')).rejects.toBeInstanceOf(SessionRefreshError);
        await vi.advanceTimersByTimeAsync(REFRESH_TIMEOUT_MS);
        await first;

        expect(storage.getItem('authToken')).toBe('at-1');
        expect(storage.getItem('refreshToken')).toBe('rt-1');
        expect(win.location.href).toBe('/admin/dashboard');
        expect((refreshCalls()[0][1] as RequestInit).signal?.aborted).toBe(true);

        hung = false;
        await newClient().apiGet('/api/v1/a');
        expect(refreshCalls()).toHaveLength(2);
        expect(authHeaderOf('/api/v1/a')).toBe('Bearer at-2');
    });
});

describe('withSessionRefreshToken (badge switch)', () => {
    const badgeBody = () => JSON.parse(String(fetchMock.mock.calls.find(([u]) => u === '/api/v1/auth/badge')![1].body));

    function switchBadge(client: ReturnType<typeof newClient>) {
        return client.withSessionRefreshToken(async (refreshToken, request) => {
            const r = await request<{ token: string; expiresAt: string }>('/api/v1/auth/badge', {
                method: 'POST',
                body: JSON.stringify({ badgeId: 'b1', refreshToken }),
            });
            client.storeAccessToken(r.token, r.expiresAt);
        });
    }

    const badgeResponse = () => json(200, { token: 'at-badge', expiresAt: new Date(Date.now() + 3_600_000).toISOString() });

    it('rotates first near expiry and sends the new refresh token, never the rotated one', async () => {
        vi.stubGlobal('navigator', { locks: makeLocks() });
        seedSession(60_000);
        fetchMock.mockImplementation(async (url: string) => {
            if (url.endsWith('/auth/refresh')) {
                return json(200, { token: 'at-2', expiresAt: new Date(Date.now() + 3_600_000).toISOString(), refreshToken: 'rt-2' });
            }
            return badgeResponse();
        });

        await switchBadge(newClient());

        expect(refreshCalls()).toHaveLength(1);
        expect(badgeBody().refreshToken).toBe('rt-2');
        expect(authHeaderOf('/api/v1/auth/badge')).toBe('Bearer at-2');
        expect(storage.getItem('authToken')).toBe('at-badge');
        expect(storage.getItem('refreshToken')).toBe('rt-2');
    });

    it('reads the refresh token inside the lock, after another tab rotated it', async () => {
        vi.stubGlobal('navigator', {
            locks: {
                request: async <T>(_name: string, fn: () => Promise<T>) => {
                    seedSession(3_600_000, 'rt-other', 'at-other');
                    return fn();
                },
            },
        });
        seedSession(60_000);
        fetchMock.mockImplementation(async () => badgeResponse());

        await switchBadge(newClient());

        expect(refreshCalls()).toHaveLength(0);
        expect(badgeBody().refreshToken).toBe('rt-other');
        expect(storage.getItem('refreshToken')).toBe('rt-other');
    });

    it('holds the lock for the badge request, so another tab cannot rotate mid-flight', async () => {
        vi.stubGlobal('navigator', { locks: makeLocks() });
        seedSession(3_600_000);
        const badgeGate = deferred<void>();
        const order: string[] = [];
        fetchMock.mockImplementation(async (url: string, init?: RequestInit) => {
            if (url === '/api/v1/auth/badge') {
                await badgeGate.promise;
                order.push('badge');
                return badgeResponse();
            }
            if (url.endsWith('/auth/refresh')) {
                order.push(`refresh:${JSON.parse(String(init!.body)).refreshToken}`);
                return json(200, { token: 'at-2', expiresAt: new Date(Date.now() + 3_600_000).toISOString(), refreshToken: 'rt-2' });
            }
            return json(200, { ok: true });
        });
        const tabA = newClient();
        const tabB = newClient();

        const switching = switchBadge(tabA);
        await Promise.resolve();
        storage.setItem('expiresAt', new Date(Date.now() + 60_000).toISOString());
        const other = tabB.apiGet('/api/v1/b');
        await new Promise((r) => setTimeout(r, 0));
        expect(order).toEqual([]);

        badgeGate.resolve();
        await Promise.all([switching, other]);
        expect(order[0]).toBe('badge');
        expect(badgeBody().refreshToken).toBe('rt-1');
    });

    it('a hung badge request times out, releases the lock and keeps the tokens', async () => {
        vi.useFakeTimers({ toFake: ['setTimeout', 'clearTimeout'] });
        vi.stubGlobal('navigator', { locks: makeLocks() });
        seedSession(3_600_000);
        fetchMock.mockImplementation(async (url: string, init?: RequestInit) => {
            if (url === '/api/v1/auth/badge') return hang(init);
            if (url.endsWith('/auth/refresh')) {
                expect(JSON.parse(String(init!.body)).refreshToken).toBe('rt-1');
                return json(200, { token: 'at-2', expiresAt: new Date(Date.now() + 3_600_000).toISOString(), refreshToken: 'rt-2' });
            }
            return json(200, { ok: true });
        });
        const tabA = newClient();
        const tabB = newClient();

        const switching = expect(switchBadge(tabA)).rejects.toBeInstanceOf(SessionRequestTimeoutError);
        await vi.advanceTimersByTimeAsync(0);
        storage.setItem('expiresAt', new Date(Date.now() + 60_000).toISOString());
        const other = tabB.apiGet('/api/v1/b');
        await vi.advanceTimersByTimeAsync(0);
        expect(refreshCalls()).toHaveLength(0);
        expect(storage.getItem('refreshToken')).toBe('rt-1');

        await vi.advanceTimersByTimeAsync(REFRESH_TIMEOUT_MS);
        await switching;
        await other;

        const badgeInit = fetchMock.mock.calls.find(([u]) => u === '/api/v1/auth/badge')![1] as RequestInit;
        expect(badgeInit.signal?.aborted).toBe(true);
        expect(win.location.href).toBe('/admin/dashboard');
        expect(refreshCalls()).toHaveLength(1);
        expect(storage.getItem('refreshToken')).toBe('rt-2');
        expect(authHeaderOf('/api/v1/b')).toBe('Bearer at-2');
    });

    it('without Web Locks, an api() call during the badge rotation joins it (one refresh POST)', async () => {
        seedSession(60_000);
        const gate = deferred<void>();
        fetchMock.mockImplementation(async (url: string) => {
            if (url.endsWith('/auth/refresh')) {
                await gate.promise;
                return json(200, { token: 'at-2', expiresAt: new Date(Date.now() + 3_600_000).toISOString(), refreshToken: 'rt-2' });
            }
            if (url === '/api/v1/auth/badge') return badgeResponse();
            return json(200, { ok: true });
        });
        const client = newClient();

        const switching = switchBadge(client);
        const other = client.apiGet('/api/v1/a');
        gate.resolve();
        await Promise.all([switching, other]);

        expect(refreshCalls()).toHaveLength(1);
        expect(authHeaderOf('/api/v1/a')).toBe('Bearer at-2');
        expect(badgeBody().refreshToken).toBe('rt-2');
        expect(storage.getItem('refreshToken')).toBe('rt-2');
    });

    it('does not start without a refresh token', async () => {
        storage.setItem('authToken', 'at-1');
        await expect(switchBadge(newClient())).rejects.toThrow(/refresh token/);
        expect(fetchMock).not.toHaveBeenCalled();
    });
});

describe('forceRefresh (server rejected a locally valid token)', () => {
    const rotated = () => json(200, { token: 'at-2', expiresAt: new Date(Date.now() + 3_600_000).toISOString(), refreshToken: 'rt-2' });

    it('rotates even when the local expiry is far in the future', async () => {
        seedSession(3_600_000);
        fetchMock.mockImplementation(async () => rotated());

        await expect(newClient().forceRefresh()).resolves.toBe('at-2');

        expect(refreshCalls()).toHaveLength(1);
        expect(storage.getItem('refreshToken')).toBe('rt-2');
    });

    it('concurrent forced refreshes in one tab send one POST', async () => {
        seedSession(3_600_000);
        fetchMock.mockImplementation(async () => rotated());
        const client = newClient();

        const [a, b] = await Promise.all([client.forceRefresh(), client.forceRefresh()]);

        expect(refreshCalls()).toHaveLength(1);
        expect(a).toBe('at-2');
        expect(b).toBe('at-2');
    });

    it('skips the POST when another tab rotated the token while this one waited for the lock', async () => {
        vi.stubGlobal('navigator', {
            locks: {
                request: async <T>(_name: string, fn: () => Promise<T>) => {
                    seedSession(3_600_000, 'rt-other', 'at-other');
                    return fn();
                },
            },
        });
        seedSession(3_600_000);

        await expect(newClient().forceRefresh()).resolves.toBe('at-other');
        expect(refreshCalls()).toHaveLength(0);
    });

    it('a 401 from /auth/refresh ends the session', async () => {
        seedSession(3_600_000);
        fetchMock.mockImplementation(async () => json(401, { error: 'invalid_grant' }));

        await expect(newClient().forceRefresh()).resolves.toBeNull();

        expect(storage.getItem('authToken')).toBeNull();
        expect(win.location.href).toBe('/login');
    });

    it('a transient failure throws SessionRefreshError and keeps the tokens', async () => {
        seedSession(3_600_000);
        fetchMock.mockImplementation(async () => json(503, { error: 'busy' }));

        await expect(newClient().forceRefresh()).rejects.toBeInstanceOf(SessionRefreshError);

        expect(storage.getItem('authToken')).toBe('at-1');
        expect(storage.getItem('refreshToken')).toBe('rt-1');
    });

    it('without a refresh token resolves null and sends nothing', async () => {
        storage.setItem('authToken', 'at-1');
        await expect(newClient().forceRefresh()).resolves.toBeNull();
        expect(fetchMock).not.toHaveBeenCalled();
    });
});
