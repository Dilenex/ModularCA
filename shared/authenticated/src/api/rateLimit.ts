/**
 * What a sign-in page says when the rate limiter answers 429.
 *
 * The sign-in endpoints (login, forced password change, claim) are throttled per address, and
 * login per username too. The limiter answers `{ error, retryAfterSeconds }` with a `Retry-After`
 * header; a proxy in front may answer 429 with no JSON at all, which used to reach the page as
 * "HTTP 429". Either way the page says the same thing: too many attempts, and how long to wait
 * when the answer says. The wait is the limiter's whole window, so it is given as an upper bound.
 */

/** The wait a 429 names, in seconds, from its body or else its `Retry-After` header; null if neither does. */
export function retryAfterSeconds(body: unknown, retryAfterHeader: string | null | undefined): number | null {
    const fromBody = (body as { retryAfterSeconds?: unknown } | null | undefined)?.retryAfterSeconds;
    if (typeof fromBody === 'number' && Number.isFinite(fromBody) && fromBody > 0) return fromBody;
    // Delta-seconds only. The HTTP-date form is not what the limiter sends, and reading it would
    // put the browser's clock into the message.
    const header = (retryAfterHeader ?? '').trim();
    if (/^\d+$/.test(header) && Number(header) > 0) return Number(header);
    return null;
}

/** The sentence for a 429: "Too many attempts. Wait up to 15 minutes, then try again." */
export function rateLimitMessage(body: unknown, retryAfterHeader: string | null | undefined): string {
    const seconds = retryAfterSeconds(body, retryAfterHeader);
    if (seconds === null) return 'Too many attempts. Wait a few minutes, then try again.';
    const minutes = Math.ceil(seconds / 60);
    return `Too many attempts. Wait up to ${minutes === 1 ? 'a minute' : `${minutes} minutes`}, then try again.`;
}
