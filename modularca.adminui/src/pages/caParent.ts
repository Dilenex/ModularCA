/**
 * The parent CA the create-CA form should hold, given the CAs that may be parents now.
 *
 * The current choice is kept when it is still a candidate; otherwise the first candidate is
 * taken, or none. The form must re-run this whenever the SET of candidates changes, not only
 * their number: after a scope switch to a subtree of the same size, a count-keyed check kept
 * the old parent's id while the select displayed the new scope's first CA, and Create signed
 * the new CA under a parent the form no longer showed.
 */
export function reconcileParent(candidateKeys: readonly string[], current: string): string {
    if (current && candidateKeys.includes(current)) return current;
    return candidateKeys[0] ?? '';
}

/** A dependency value that changes exactly when the candidate set (or its order) changes. */
export function candidateSetKey(candidateKeys: readonly string[]): string {
    return candidateKeys.join('|');
}
