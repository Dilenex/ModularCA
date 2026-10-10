/** A certificate profile a picker can offer. */
export interface CertProfileOption {
    id: string;
    name: string;
}

/**
 * The certificate profiles a request profile designates: its default first, then its allowed
 * list, none twice. The server refuses a request that names another one.
 */
export function designatedCertProfileIds(defaultId: string | null | undefined, allowedIds: string[] | null | undefined): string[] {
    const ids: string[] = [];
    for (const id of [defaultId, ...(allowedIds ?? [])]) {
        if (id && !ids.includes(id)) ids.push(id);
    }
    return ids;
}

/**
 * What an operator's picker offers: the designated profiles in their order when the request
 * profile designates any, every profile when it designates none.
 */
export function offeredCertProfiles(all: CertProfileOption[], designated: string[]): CertProfileOption[] {
    if (designated.length === 0) return all;
    return designated
        .map((id) => all.find((p) => p.id === id))
        .filter((p): p is CertProfileOption => !!p);
}

/**
 * The profile a picker holds after the request profile or the list changed: the request
 * profile's first designated one when it is offered; otherwise the current choice while it is
 * still offered; otherwise the first offered where the list is the designated one, and nothing
 * where it is every profile.
 */
export function settleCertProfile(current: string, offered: CertProfileOption[], designated: string[], offersEverything: boolean): string {
    const wanted = designated.find((id) => offered.some((p) => p.id === id));
    if (wanted) return wanted;
    if (offered.some((p) => p.id === current)) return current;
    return offersEverything ? '' : (offered[0]?.id ?? '');
}
