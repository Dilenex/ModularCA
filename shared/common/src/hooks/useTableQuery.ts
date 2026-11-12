import { useLayoutEffect, useMemo, useRef } from 'react';
import { useSearchParams } from 'react-router-dom';
import { readTableQuery, tableQueryWriter, type TableQueryValues } from '../tableQuery';

/**
 * A table's page, sort and filters, bound to the URL.
 *
 * `useTableQuery('certificates', { page: '1', pageSize: '20', sort: '-notBefore', status: '' })`
 * returns the current values (URL over defaults) and a setter that writes changes into the
 * query string, so a filtered view is a link, survives reload, and works with the browser's
 * back button. Changing anything but the page resets the page to its default, since a filter
 * change invalidates the position. Scope parameters in the URL are left untouched.
 *
 * The setter and reset merge into the query string as it is when they are called, not as it
 * was when they were created: a typed filter's debounce timer holds the setter from the render
 * where typing started, and must not undo a sort, page or scope change made before it fires.
 * Two calls in one tick also build on each other. See `tableQueryWriter`.
 *
 * @param tableId  Names the table; only used as a namespace prefix when `prefixed` is set, for
 *                 pages that hold more than one table.
 */
export function useTableQuery(
    tableId: string,
    defaults: TableQueryValues,
    options: { prefixed?: boolean; replace?: boolean } = {},
): [TableQueryValues, (patch: Partial<TableQueryValues>) => void, () => void] {
    const [searchParams, setSearchParams] = useSearchParams();
    const prefix = options.prefixed ? tableId : '';
    const values = useMemo(() => readTableQuery(searchParams, defaults, prefix), [searchParams, defaults, prefix]);

    // The latest query string and router setter, for setters held across renders. A write
    // updates `latest` at once, so a second call before the router re-renders builds on the
    // first; the router's own value replaces it whenever the URL changes.
    const latest = useRef(searchParams);
    const setLatest = useRef(setSearchParams);
    useLayoutEffect(() => { latest.current = searchParams; }, [searchParams]);
    useLayoutEffect(() => { setLatest.current = setSearchParams; }, [setSearchParams]);

    const replace = options.replace ?? true;
    const writer = useMemo(() => tableQueryWriter(
        () => latest.current,
        (next) => { latest.current = next; setLatest.current(next, { replace }); },
        defaults,
        prefix,
    ), [defaults, prefix, replace]);

    return [values, writer.set, writer.reset];
}
