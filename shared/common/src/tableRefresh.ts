/** How often a table that refreshes itself asks for its rows again, unless the table says otherwise. */
export const AUTO_REFRESH_SECONDS = 30;

/**
 * Whether a table with auto-refresh switched on should reload now. It holds off while reloading
 * would pull something out from under the reader: rows are ticked, a row's drawer is open, or
 * the page is not being looked at.
 */
export function autoRefreshDue(state: { enabled: boolean; pageHidden: boolean; selectedCount: number; drawerOpen: boolean }): boolean {
    return state.enabled && !state.pageHidden && state.selectedCount === 0 && !state.drawerOpen;
}

/** What the switch says, for its label and tooltip. */
export function autoRefreshLabel(seconds: number): string {
    return seconds % 60 === 0 ? `Auto ${seconds / 60}m` : `Auto ${seconds}s`;
}
