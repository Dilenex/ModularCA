/**
 * Whether a sidebar item is the current page.
 *
 * The self-service portal highlights an item for its sub-pages too (`/certificates/abc` under
 * "My Certificates"). That was a plain prefix test, so `/requests` also lit "Request
 * Certificate" (`/request`): two items showed as current. A sub-page starts with the item's path
 * followed by a slash.
 *
 * @param pathname  The current location's path.
 * @param itemPath  The sidebar item's path.
 * @param subPages  Whether the item also covers the pages under it.
 */
export function navItemActive(pathname: string, itemPath: string, subPages: boolean): boolean {
    if (pathname === itemPath) return true;
    return subPages && pathname.startsWith(itemPath.endsWith('/') ? itemPath : `${itemPath}/`);
}
