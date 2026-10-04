/**
 * Where a ceremony is opened. `/ceremonies/:id` is routed to the Ceremonies page with that
 * ceremony's drawer open, so the link a toast quotes and the one a page navigates to are the same.
 * Free of React and the router so the web tests cover it.
 */

/** The ceremonies list. */
export const CEREMONIES_PATH = '/ceremonies';

/** The router path that opens one ceremony's drawer. */
export function ceremonyPath(id: string): string {
    return `${CEREMONIES_PATH}/${encodeURIComponent(id)}`;
}

/** The full console URL path for a ceremony, for text a person reads (a toast). */
export function ceremonyLink(id: string): string {
    return `/admin${ceremonyPath(id)}`;
}
