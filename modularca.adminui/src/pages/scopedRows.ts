/**
 * Narrowing rows to the console's scope, for lists whose rows name their CA by certificate id or
 * by CA id (CRL schedules, signing profiles). Pure, so the pages that follow the scope switcher
 * share one rule and it is covered by unit tests. The profile lists also send the scope to the
 * server (`caQuery()`), which narrows by the same rule over the CAs the database holds; this
 * judges by the CAs the caller is shown, so it never keeps a row the server left out and what a
 * page shows is what this alone would show.
 */

/** An entry of the flat `/api/v1/admin/authorities` list: the CA id and its certificate id. */
export interface AuthorityRef {
    id: string;
    certificateId?: string | null;
}

/**
 * The id of the CA that `ref` names, matched against a CA's id or its certificate id, or `null`
 * when `ref` is empty or no listed CA matches.
 */
export function caIdForRef(ref: string | null | undefined, authorities: readonly AuthorityRef[]): string | null {
    if (!ref) return null;
    const ca = authorities.find(a => a.id === ref || (!!a.certificateId && a.certificateId === ref));
    return ca ? ca.id : null;
}

/**
 * The rows inside the scope, judged by the CA each names through `refOf` and the scope's
 * `inScope` (from `useScope`). Under "all CAs" `inScope` admits everything, so every row is
 * kept. A row naming no CA is kept only with `keepUnbound`; a row naming a CA the list does not
 * hold is out of any narrower scope.
 */
export function rowsInScope<T>(
    rows: readonly T[],
    refOf: (row: T) => string | null | undefined,
    authorities: readonly AuthorityRef[],
    inScope: (caId: string | null | undefined) => boolean,
    options: { keepUnbound?: boolean } = {},
): T[] {
    return rows.filter(row => {
        const ref = refOf(row);
        if (!ref) return options.keepUnbound ? true : inScope(null);
        return inScope(caIdForRef(ref, authorities));
    });
}

/**
 * The ids of the profiles that `rows` inherit from and that `rows` does not hold. A list the
 * server narrowed to a scope leaves out a parent bound to another CA; the page then loads the
 * names it needs rather than show an id where it showed a name.
 */
export function parentsOutside(rows: readonly { id?: string; inheritanceEnabled?: boolean; inheritsFromId?: string | null }[]): string[] {
    const held = new Set(rows.map(r => r.id));
    return [...new Set(rows.filter(r => r.inheritanceEnabled && !!r.inheritsFromId && !held.has(r.inheritsFromId)).map(r => r.inheritsFromId as string))];
}

/** An SSH CA key as `/api/v1/admin/ssh/ca-keys` lists it: its id and the SSH CA it belongs to. */
export interface SshCaKeyRef {
    id: string;
    certificateAuthorityId?: string | null;
}

/**
 * The CA an SSH signing profile signs for, as a `refOf` for `rowsInScope`: the CA of its SSH CA
 * key. A profile whose key is not listed gives the key id itself, which names no CA, so the row is
 * out of any narrower scope rather than taken for an unbound one; a profile with no key gives null.
 */
export function sshSigningProfileCaRef(profile: { sshCaKeyId?: string | null }, caKeys: readonly SshCaKeyRef[]): string | null {
    if (!profile.sshCaKeyId) return null;
    const key = caKeys.find(k => k.id === profile.sshCaKeyId);
    return key?.certificateAuthorityId || profile.sshCaKeyId;
}
