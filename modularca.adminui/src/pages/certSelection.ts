/**
 * The Certificates page's bulk selection, kept out of React so the scope rule can be tested.
 *
 * Bug hunt 2026-11: the selection was cleared when the URL filters or the CA filter changed, but a
 * space scope reaches the list through the scope context, not the URL. Switching spaces reloaded
 * the list and kept the selection, so bulk revoke could act on certificates from the space the
 * operator had left.
 */

/**
 * A value that changes whenever the set of certificates the page can list changes: the filters,
 * the CA filter, or the console's CA or space scope. The page clears its selection when it does.
 *
 * @param view The current filters as a saved view writes them (no page number).
 * @param caIdFilter The issuing-CA filter, or ''.
 * @param scopeCaId The CA the console scope is pinned to, or null.
 * @param scopeSpaceId The space the console scope is confined to, or null.
 */
export function selectionScopeKey(view: string, caIdFilter: string, scopeCaId: string | null, scopeSpaceId: string | null): string {
    return JSON.stringify([view, caIdFilter, scopeCaId ?? '', scopeSpaceId ?? '']);
}

/**
 * The serials bulk revoke may submit: the selected ones that were listed under the current scope
 * and filters. Anything else in the selection is dropped rather than sent, so a selection that
 * outlived a scope change can never revoke a certificate the page does not show.
 *
 * @param selected The selected keys (serials).
 * @param listed Every row loaded under the current scope and filters, by key; cleared with the selection.
 */
export function revocableSerials(selected: Iterable<string>, listed: ReadonlyMap<string, unknown>): string[] {
    return Array.from(selected).filter((key) => listed.has(key));
}
