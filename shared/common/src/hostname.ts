/**
 * DNS hostname helpers shared by every ModularCA front end.
 *
 * These live here rather than in each SPA because the same logic previously existed in three
 * places — the admin request form, the user request form, and the reissue modal — with nothing
 * keeping them in step. That shape is the most common defect in this codebase: a fix lands in one
 * copy and the siblings quietly keep the old behaviour.
 */

/** Moved to validators.ts with the other single-value checks; re-exported for existing imports. */
export { looksLikeHostname } from './validators';

/**
 * Case-insensitive comparison of two DNS names. DNS is case-insensitive, so `Example.COM` and
 * `example.com` are the same name and must not be offered as separate SANs.
 */
export function sameHostname(a: string, b: string): boolean {
    return a.trim().toLowerCase() === b.trim().toLowerCase();
}
