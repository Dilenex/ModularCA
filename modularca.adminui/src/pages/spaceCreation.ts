/**
 * What the Create Space dialog says. Free of React so the web tests cover it.
 *
 * Spaces are a soft cap, not a gate: up to four, nothing is said; the fifth and later are
 * created all the same, with a licence recommendation unless the licence carries multi-tenancy.
 * Only the server knows the licence, and no endpoint reports it: the create response's
 * `recommendation` is the one place it says. Entitlements are fixed for the life of the server
 * process, so the console repeats that answer before the next create and says nothing in advance
 * until it has one.
 */

/** Shown in the dialog before every space is created. */
export const SPACE_INTERSTITIAL =
    'Spaces delegate administration within one organisation. They share sign-in, backups, the audit trail and instance administrators. For a separate customer, create a separate instance.';

/** How many spaces an installation may have before a licence is recommended (SpaceCreationGate on the server). */
export const SPACES_WITHOUT_LICENCE = 4;

/** The server's recommendation text (SpaceCreationGate.LicenceRecommendation). */
export const LICENCE_RECOMMENDATION = 'A licence is recommended for more than four spaces.';

/**
 * The recommendation to show before creating, given how many spaces exist and the recommendation
 * the server returned for the last space created (`null` when it returned none, or nothing has
 * been created yet). Shown from the fifth space on, and only when the server last said so.
 */
export function recommendationBeforeCreate(existingSpaces: number, lastServerRecommendation: string | null): string | null {
    return existingSpaces >= SPACES_WITHOUT_LICENCE && lastServerRecommendation ? lastServerRecommendation : null;
}

/** The recommendation a create response carries, or `null` (none, or a licence carries the feature). */
export function recommendationFromResponse(response: unknown): string | null {
    const value = (response as { recommendation?: unknown } | null | undefined)?.recommendation;
    return typeof value === 'string' && value.trim() ? value : null;
}
