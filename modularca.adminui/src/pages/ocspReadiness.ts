/** How one CA answers OCSP, as the CA hierarchy feed reports it (`ocspResponder` on each CA). */
export interface CaOcspRow {
    id: string;
    name: string;
    /** `delegated`: a responder certificate signs. `direct`: the CA key signs. `none`: nothing can. */
    mode: string;
    /** Why every OCSP request for this CA is refused; null when it is answered. */
    problem: string | null;
}

/**
 * The CAs that are expected to answer OCSP, from the hierarchy feed, children included. A CA the
 * feed reports nothing for (disabled, no certificate) or as `off` (OCSP not served) is left out.
 * Refusing CAs come first.
 */
export function ocspRows(hierarchy: any[]): CaOcspRow[] {
    const rows: CaOcspRow[] = [];
    const walk = (cas: any[]) => {
        for (const ca of cas || []) {
            const state = ca?.ocspResponder;
            if (state && state.mode !== 'off') {
                rows.push({ id: ca.id, name: ca.name || ca.label || ca.id, mode: state.mode, problem: state.problem ?? null });
            }
            walk(ca?.children);
        }
    };
    walk(hierarchy);
    return rows.sort((a, b) => Number(!!b.problem) - Number(!!a.problem) || a.name.localeCompare(b.name));
}

/**
 * The badge for one CA's `ocspResponder` state, the same on every page that shows it. Null when
 * the feed reports nothing for the CA.
 */
export function ocspStatus(state: { mode?: string; problem?: string | null } | null | undefined):
    { status: 'active' | 'revoked' | 'held' | 'disabled'; label: string } | null {
    if (!state) return null;
    if (state.problem) return { status: 'revoked', label: 'Refusing' };
    if (state.mode === 'off') return { status: 'disabled', label: 'Not served' };
    if (state.mode === 'direct') return { status: 'held', label: 'CA key signs' };
    return { status: 'active', label: 'Answering' };
}

/** The sentence under a refusing CA: what it means for clients, and what to do. */
export const OCSP_REFUSED_CONSEQUENCE =
    'Every OCSP request for a certificate this CA issued is answered "unauthorized". Reissue the OCSP responder under Infrastructure Certificates on the CA\'s page.';
