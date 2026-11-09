/**
 * Messages for the `?error=` codes the sign-in page is sent back with. The certificate sign-in
 * routes (`/auth/mtls/login-redirect`, `/auth/mtls/verify-redirect`) redirect here on failure, as
 * does the console's own `/mfa-callback` page. Pure so it can be tested without React.
 */

/**
 * Shown under the certificate buttons. The certificate hostname refuses a connection that offers
 * no certificate, so cancelling the picker ends on the browser's own error page, not here.
 */
export const CERTIFICATE_PICKER_HINT = 'If you cancel the certificate prompt, your browser shows an error page. Go back to this page and try again.';

/** Shown for a code this map does not know. */
export const GENERIC_LOGIN_ERROR = 'Sign-in did not complete. Try again, or sign in with your username and password.';

/** Every code the server or the console sends to `/login?error=`, with the message shown for it. */
export const LOGIN_ERROR_MESSAGES: Readonly<Record<string, string>> = {
    no_certificate: 'Your browser did not present a client certificate. Choose a certificate when your browser asks, or sign in with your username and password.',
    auth_failed: 'This certificate is not enrolled for sign-in. Sign in with your username and password.',
    cert_not_matched: 'This certificate is not enrolled for your account. Choose the certificate you enrolled, or use another method.',
    cert_revoked: 'This certificate can no longer be used to sign in: it has been revoked or put on hold. Sign in another way, or ask an administrator for a new certificate.',
    cert_chain_invalid: 'This certificate could not be verified against the CA that issued it. Sign in another way, or ask an administrator to check your certificate.',
    account_locked: 'This account is disabled or locked. Ask an administrator for help.',
    user_not_found: 'The account for this sign-in no longer exists.',
    mfa_token_missing: 'Your sign-in session was not found. Sign in again.',
    mfa_expired: 'Your sign-in session expired. Sign in again.',
    mfa_method_not_allowed: 'You started this sign-in with a certificate, so a certificate cannot be the second step. Use your authenticator app or security key.',
    mfa_failed: 'Certificate verification did not complete. Sign in again.',
    exchange_failed: 'Sign-in could not be completed. Sign in again.',
};

/**
 * The message for an `?error=` value, or null when there is none. Unknown codes get
 * {@link GENERIC_LOGIN_ERROR}; the raw value is never part of the message.
 */
export function loginErrorMessage(code: string | null | undefined): string | null {
    if (code == null) return null;
    const trimmed = code.trim();
    if (!trimmed) return null;
    return Object.prototype.hasOwnProperty.call(LOGIN_ERROR_MESSAGES, trimmed)
        ? LOGIN_ERROR_MESSAGES[trimmed]
        : GENERIC_LOGIN_ERROR;
}

/**
 * `path` with `code` carried as `?error=`, or `path` alone when there is no code. The sign-in
 * page uses it to pass the code through the login banner, which otherwise sends the browser back
 * to a bare `/login` and the message is lost.
 */
export function withLoginError(path: string, code: string | null | undefined): string {
    const trimmed = code?.trim();
    return trimmed ? `${path}?error=${encodeURIComponent(trimmed)}` : path;
}
