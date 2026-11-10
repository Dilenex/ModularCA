/**
 * Keeps only the newest of overlapping loads.
 *
 * A console list reloads when the scope or a filter changes, and again after an edit. Loads
 * overlap: a slow response for the scope the user just left can arrive after the one for the
 * scope they are now in, and would replace it. Each load calls `begin()` before it fetches and
 * checks the returned function before it writes its result; only the most recent load passes.
 * A gate covers loads started from an effect and from an event handler alike, which a
 * `cancelled` flag in an effect's clean-up cannot.
 *
 * Pure; `useLatestRequest` keeps one per component and cancels it on unmount.
 */
export interface LatestRequest {
    /** Starts a load. The returned function answers whether it is still the newest one. */
    begin(): () => boolean;
    /** Makes every load started so far stale. */
    cancel(): void;
}

/** A new, independent gate. */
export function latestRequest(): LatestRequest {
    let generation = 0;
    return {
        begin() {
            const mine = ++generation;
            return () => mine === generation;
        },
        cancel() {
            generation++;
        },
    };
}
