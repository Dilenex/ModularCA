/*
 * What the "Parent CA" row of a CA's page shows. No React here, so tests/modularca.web.tests can
 * cover it. An id is never shown: a person reads a name, and follows a link to the parent's page.
 */

/** What to show for a CA's parent. */
export type ParentCaDisplay =
    /** A root: it has no parent. */
    | { kind: 'root'; text: string }
    /** A parent this viewer may see: its name as a link to its page, with its label beside it. */
    | { kind: 'link'; name: string; label: string | null; to: string }
    /** A parent outside what this viewer may see: the server gives nothing that identifies it. */
    | { kind: 'hidden'; text: string };

const text = (value: unknown): string | null => (typeof value === 'string' && value.trim() !== '' ? value : null);

/** What the row says for a parent the server does not identify to this viewer. */
export const PARENT_NOT_VISIBLE = 'Not visible to you';

/**
 * The parent of `ca`, from the hierarchy feed alone. `visible` is every CA the feed returned to
 * this viewer (already limited to the spaces they may see). A parent in that list is linked.
 * For a parent outside the viewer's space fence the server sends no id, name or label of it
 * (`parentCaId` is null and `parentHidden` is true), and the row says it is not visible. The same
 * is said when an id is given for a CA the list does not hold. A name is never taken from anywhere
 * else, so a fenced viewer learns nothing here that the server did not decide to give.
 * Returns null for a CA that is neither a root nor has a parent recorded (one signed elsewhere).
 */
export function parentCaDisplay(ca: any, visible: any[]): ParentCaDisplay | null {
    if (!ca || typeof ca !== 'object') return null;
    const parentId = text(ca.parentCaId);
    if (!parentId) {
        if (ca.parentHidden === true) return { kind: 'hidden', text: PARENT_NOT_VISIBLE };
        return ca.isRoot === true ? { kind: 'root', text: 'None (root)' } : null;
    }
    const parent = Array.isArray(visible) ? visible.find((c) => c && c.id === parentId) : undefined;
    if (parent) {
        const name = text(parent.name) ?? text(parent.label) ?? 'Parent CA';
        const label = text(parent.label);
        return { kind: 'link', name, label: label && label !== name ? label : null, to: `/authorities/manage/${encodeURIComponent(parentId)}` };
    }
    return { kind: 'hidden', text: PARENT_NOT_VISIBLE };
}
