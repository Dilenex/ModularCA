/**
 * What the Create Space dialog says. Free of React so the web tests cover it.
 *
 * Spaces are a soft cap, not a gate: up to four, nothing is said; the fifth and later are
 * created all the same, with a licence recommendation. The server decides (it knows the licence);
 * the console says it in advance from the count, and shows the server's answer after creation.
 */

/** Shown in the dialog before every space is created. */
export const SPACE_INTERSTITIAL =
    'Spaces delegate administration within one organisation. They share sign-in, backups, the audit trail and instance administrators. For a separate customer, create a separate instance.';

/** How many spaces an installation may have before a licence is recommended (SpaceCreationGate on the server). */
export const SPACES_WITHOUT_LICENCE = 4;

/** The server's recommendation text (SpaceCreationGate.LicenceRecommendation). */
export const LICENCE_RECOMMENDATION = 'A licence is recommended for more than four spaces.';

/** The recommendation to show before creating, given how many spaces exist: from the fifth space on. */
export function recommendationBeforeCreate(existingSpaces: number): string | null {
    return existingSpaces >= SPACES_WITHOUT_LICENCE ? LICENCE_RECOMMENDATION : null;
}

/** The recommendation a create response carries, or `null` (none, or a licence carries the feature). */
export function recommendationFromResponse(response: unknown): string | null {
    const value = (response as { recommendation?: unknown } | null | undefined)?.recommendation;
    return typeof value === 'string' && value.trim() ? value : null;
}
