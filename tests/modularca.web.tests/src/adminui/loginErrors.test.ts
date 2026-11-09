import { describe, expect, it } from 'vitest';
import { CERTIFICATE_PICKER_HINT, GENERIC_LOGIN_ERROR, LOGIN_ERROR_MESSAGES, loginErrorMessage, withLoginError } from '@adminui/pages/loginErrors';

/**
 * Every code sent to /login?error=: the redirects in MtlsController (login-redirect and
 * verify-redirect) and the console's /mfa-callback page. A code added on either side without a
 * message here falls back to the generic text, which this list exists to prevent.
 */
const KNOWN_CODES = [
    'no_certificate', 'auth_failed', 'cert_not_matched', 'cert_revoked', 'cert_chain_invalid',
    'account_locked', 'user_not_found', 'mfa_token_missing', 'mfa_expired', 'mfa_method_not_allowed',
    'mfa_failed', 'exchange_failed',
];

describe('loginErrorMessage', () => {
    it('has a specific message for every code the server and console send', () => {
        for (const code of KNOWN_CODES) {
            const message = loginErrorMessage(code);
            expect(message, code).toBe(LOGIN_ERROR_MESSAGES[code]);
            expect(message, code).not.toBe(GENERIC_LOGIN_ERROR);
        }
        expect(Object.keys(LOGIN_ERROR_MESSAGES).sort()).toEqual([...KNOWN_CODES].sort());
    });

    it('explains a revoked certificate plainly', () => {
        expect(loginErrorMessage('cert_revoked')).toMatch(/revoked/i);
    });

    it('returns null when there is no code', () => {
        expect(loginErrorMessage(null)).toBeNull();
        expect(loginErrorMessage(undefined)).toBeNull();
        expect(loginErrorMessage('')).toBeNull();
        expect(loginErrorMessage('   ')).toBeNull();
    });

    it('gives unknown codes the generic message without echoing them', () => {
        const hostile = '<img src=x onerror=alert(1)>';
        expect(loginErrorMessage(hostile)).toBe(GENERIC_LOGIN_ERROR);
        expect(loginErrorMessage('something_new')).toBe(GENERIC_LOGIN_ERROR);
        expect(GENERIC_LOGIN_ERROR).not.toContain('something_new');
    });

    it('does not treat object prototype names as codes', () => {
        expect(loginErrorMessage('toString')).toBe(GENERIC_LOGIN_ERROR);
        expect(loginErrorMessage('__proto__')).toBe(GENERIC_LOGIN_ERROR);
    });
});

describe('CERTIFICATE_PICKER_HINT', () => {
    it('tells the user a cancelled prompt ends on an error page and to try again', () => {
        expect(CERTIFICATE_PICKER_HINT).toMatch(/cancel/i);
        expect(CERTIFICATE_PICKER_HINT).toMatch(/error page/i);
        expect(CERTIFICATE_PICKER_HINT).toMatch(/try again/i);
    });
});

describe('withLoginError', () => {
    it('carries the code through the banner and back to the sign-in page', () => {
        const bannerPath = withLoginError('/banner', 'cert_revoked');
        expect(bannerPath).toBe('/banner?error=cert_revoked');
        const code = new URLSearchParams(bannerPath.split('?')[1]).get('error');
        expect(loginErrorMessage(new URLSearchParams(withLoginError('/login', code).split('?')[1]).get('error')))
            .toBe(LOGIN_ERROR_MESSAGES.cert_revoked);
    });

    it('leaves the path bare when there is no code', () => {
        expect(withLoginError('/login', null)).toBe('/login');
        expect(withLoginError('/login', undefined)).toBe('/login');
        expect(withLoginError('/login', '  ')).toBe('/login');
    });

    it('encodes the code so it cannot add parameters', () => {
        expect(withLoginError('/login', 'x&returnUrl=https://evil.example')).toBe('/login?error=x%26returnUrl%3Dhttps%3A%2F%2Fevil.example');
    });
});
