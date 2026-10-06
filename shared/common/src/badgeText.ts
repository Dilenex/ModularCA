/*
 * The text of a StatusBadge or Tag. No React here, so tests/modularca.web.tests can cover it.
 */

/**
 * One casing for every label: a capital first letter, so `active` reads "Active". Nothing else
 * is changed: acronyms (OK, CA, ACME) and mixed-case text are the caller's to spell.
 */
export function badgeText(text: string): string {
    const t = text.trim();
    return t.charAt(0).toUpperCase() + t.slice(1);
}
