import { useCallback, useMemo } from 'react';
import { useSearchParams } from 'react-router-dom';
import { readTableQuery, writeTableQuery, type TableQueryValues } from '../tableQuery';

/**
 * A table's page, sort and filters, bound to the URL.
 *
 * `useTableQuery('certificates', { page: '1', pageSize: '20', sort: '-notBefore', status: '' })`
 * returns the current values (URL over defaults) and a setter that writes changes into the
 * query string, so a filtered view is a link, survives reload, and works with the browser's
 * back button. Changing anything but the page resets the page to its default, since a filter
 * change invalidates the position. Scope parameters in the URL are left untouched.
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

    const set = useCallback((patch: Partial<TableQueryValues>) => {
        const current = readTableQuery(searchParams, defaults, prefix);
        const next: TableQueryValues = { ...current, ...(patch as TableQueryValues) };
        const filterChanged = Object.keys(patch).some(k => k !== 'page' && patch[k] !== current[k]);
        if (filterChanged && 'page' in defaults && !('page' in patch)) next.page = defaults.page;
        setSearchParams(writeTableQuery(searchParams, next, defaults, prefix), { replace: options.replace ?? true });
    }, [searchParams, setSearchParams, defaults, prefix, options.replace]);

    const reset = useCallback(() => {
        setSearchParams(writeTableQuery(searchParams, defaults, defaults, prefix), { replace: options.replace ?? true });
    }, [searchParams, setSearchParams, defaults, prefix, options.replace]);

    return [values, set, reset];
}
