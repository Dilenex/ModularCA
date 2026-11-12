import { useEffect, useState } from 'react';
import { latestRequest, type LatestRequest } from '../latestRequest';

/**
 * One `LatestRequest` gate for the life of the component, cancelled on unmount.
 *
 * ```ts
 * const loads = useLatestRequest();
 * const load = () => {
 *     const current = loads.begin();
 *     apiGet(url).then((rows) => { if (current()) setRows(rows); });
 * };
 * ```
 *
 * Use one gate per independent list; two loads that share a gate cancel each other.
 */
export function useLatestRequest(): LatestRequest {
    const [gate] = useState(latestRequest);
    useEffect(() => () => gate.cancel(), [gate]);
    return gate;
}
