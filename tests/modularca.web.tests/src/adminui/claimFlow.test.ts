import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { createAuthClient } from '@shared-auth/api/createClient';
import {
    CLAIM_PASSWORD_MISMATCH, CLAIM_TOKEN_REQUIRED, submitClaim, validateClaim, type ClaimForm,
} from '@adminui/pages/claimFlow';

/**
 * The claim page (/claim): a one-time token, a new password and its confirmation, posted to the
 * claim endpoint; on success the sign-in page opens with the username filled in. The page's logic
 * is claimFlow.ts, run here against the real client with `fetch` stubbed, so the request on the
 * wire and the text of each refusal are the ones the page produces.
 */
const json = (status: number, body: unknown, headers: Record<string, string> = {}) =>
    new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json', ...headers } });

const form = (over: Partial<ClaimForm> = {}): ClaimForm =>
    ({ token: 'tok-123', newPassword: 'correct horse battery', confirmNewPassword: 'correct horse battery', ...over });

/** What the server answers every refused token with (AuthController.ClaimRefusedMessage). */
const REFUSED = 'The claim token is not valid. It may be mistyped, expired or already used.';

let fetchMock: ReturnType<typeof vi.fn>;
let cookies: { cookie: string };

/** The page's call: the sign-in pages load at the site root, outside both portals. */
const claimCall = () => createAuthClient({ basename: '/admin', loginPath: '/login' }).apiClaimAccount;
const submit = (f: ClaimForm) => submitClaim(f, claimCall(), '/login');

beforeEach(() => {
    fetchMock = vi.fn();
    cookies = { cookie: '' };
    vi.stubGlobal('localStorage', { getItem: () => null, setItem: () => { }, removeItem: () => { } });
    vi.stubGlobal('window', { location: { pathname: '/admin/claim', origin: 'https://ca.test', href: '/admin/claim' } });
    vi.stubGlobal('document', cookies);
    vi.stubGlobal('fetch', fetchMock);
    vi.stubGlobal('navigator', {});
});

afterEach(() => {
    vi.unstubAllGlobals();
});

describe('validateClaim', () => {
    it('passes a token with a matching password and confirmation', () => {
        expect(validateClaim(form())).toBeNull();
    });

    it('refuses an empty token, and one of nothing but spaces', () => {
        expect(validateClaim(form({ token: '' }))).toBe(CLAIM_TOKEN_REQUIRED);
        // The field's `required` attribute lets this through.
        expect(validateClaim(form({ token: '   ' }))).toBe(CLAIM_TOKEN_REQUIRED);
    });

    it('refuses a confirmation that differs from the password', () => {
        expect(validateClaim(form({ confirmNewPassword: 'correct horse batter' }))).toBe(CLAIM_PASSWORD_MISMATCH);
        expect(validateClaim(form({ confirmNewPassword: '' }))).toBe(CLAIM_PASSWORD_MISMATCH);
    });

    it('names the missing token first when both are wrong', () => {
        expect(validateClaim(form({ token: ' ', confirmNewPassword: 'other' }))).toBe(CLAIM_TOKEN_REQUIRED);
    });
});

describe('submitClaim', () => {
    it('sends nothing when the form is invalid, and shows why', async () => {
        expect(await submit(form({ token: '  ' }))).toEqual({ ok: false, error: CLAIM_TOKEN_REQUIRED });
        expect(await submit(form({ confirmNewPassword: 'different' }))).toEqual({ ok: false, error: CLAIM_PASSWORD_MISMATCH });
        expect(fetchMock).not.toHaveBeenCalled();
    });

    it('posts the trimmed token, the password and its confirmation as JSON to the claim endpoint', async () => {
        fetchMock.mockResolvedValue(json(200, { message: 'Account claimed. Sign in with the new password.', username: 'admin' }));
        await submit(form({ token: '  tok-123\n' }));

        expect(fetchMock).toHaveBeenCalledTimes(1);
        const [url, init] = fetchMock.mock.calls[0];
        expect(url).toBe('/auth/claim');
        expect(init.method).toBe('POST');
        expect(init.credentials).toBe('same-origin');
        expect(init.headers['Content-Type']).toBe('application/json');
        expect(JSON.parse(init.body)).toEqual({
            token: 'tok-123', newPassword: 'correct horse battery', confirmNewPassword: 'correct horse battery',
        });
    });

    it('sends no session: the page is used before there is one', async () => {
        fetchMock.mockResolvedValue(json(200, { message: 'ok', username: 'admin' }));
        await submit(form());
        expect(fetchMock.mock.calls[0][1].headers.Authorization).toBeUndefined();
    });

    it('does not trim the password', async () => {
        fetchMock.mockResolvedValue(json(200, { message: 'ok', username: 'admin' }));
        await submit(form({ newPassword: ' spaced out ', confirmNewPassword: ' spaced out ' }));
        expect(JSON.parse(fetchMock.mock.calls[0][1].body).newPassword).toBe(' spaced out ');
    });

    it('sends the CSRF header when the cookie is set, and none otherwise', async () => {
        fetchMock.mockImplementation(async () => json(200, { message: 'ok', username: 'admin' }));
        await submit(form());
        expect(fetchMock.mock.calls[0][1].headers['X-CSRF-Token']).toBeUndefined();

        cookies.cookie = '__Host-CSRF-TOKEN=abc123';
        await submit(form());
        expect(fetchMock.mock.calls[1][1].headers['X-CSRF-Token']).toBe('abc123');
    });

    it('goes to the sign-in page with the claimed username on success', async () => {
        // The username is the server's: the page never asked for one.
        fetchMock.mockResolvedValue(json(200, { message: 'Account claimed. Sign in with the new password.', username: 'first.admin' }));
        expect(await submit(form())).toEqual({ ok: true, to: '/login', state: { claimed: { username: 'first.admin' } } });
    });

    it('shows the server\'s one sentence for a refused token, and nothing about why', async () => {
        fetchMock.mockResolvedValue(json(400, { error: REFUSED }));
        expect(await submit(form())).toEqual({ ok: false, error: { severity: 'error', detail: REFUSED } });
    });

    it('lists the policy\'s objections when the password is turned down', async () => {
        fetchMock.mockResolvedValue(json(400, {
            error: 'Password does not meet policy requirements',
            details: ['Password must be at least 14 characters', 'Password must contain a digit'],
        }));
        const outcome = await submit(form({ newPassword: 'short', confirmNewPassword: 'short' }));
        expect(outcome).toEqual({
            ok: false,
            error: {
                severity: 'error',
                detail: 'Password does not meet policy requirements: Password must be at least 14 characters, Password must contain a digit',
            },
        });
    });

    it('names the status when the answer is not JSON', async () => {
        fetchMock.mockResolvedValue(new Response('<html>Bad Gateway</html>', { status: 502 }));
        expect(await submit(form())).toEqual({ ok: false, error: { severity: 'error', detail: 'HTTP 502' } });
    });

    it('shows the failure when the request never arrives', async () => {
        fetchMock.mockRejectedValue(new TypeError('Failed to fetch'));
        expect(await submit(form())).toEqual({ ok: false, error: { severity: 'error', detail: 'Failed to fetch' } });
    });

    it('falls back to a generic sentence for an error with no message', async () => {
        const outcome = await submitClaim(form(), async () => { throw new Error(''); }, '/login');
        expect(outcome).toEqual({ ok: false, error: { severity: 'error', detail: 'Unexpected error' } });
    });
});
