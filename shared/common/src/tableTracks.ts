/*
 * Grid tracks for DataTable columns. No React here, so tests/modularca.web.tests can cover it.
 *
 * Tables are left-packed: every column is as wide as its content needs (its default width, or
 * the width a user set), and the slack goes to ONE place.
 *
 *  - A table with a flexible column (`flex: true`) gives the slack to that column. Its other
 *    columns stay at their default or user-set width and do not grow, unless one asks to with
 *    `grow: true`.
 *  - A table with no flexible column gets a trailing blank spacer that takes the slack. There,
 *    a column nobody has resized may first grow a little, up to GROWTH times its default, while
 *    there is room: on a wide screen that shows text that would otherwise be cut off beside an
 *    empty spacer. It gives the room back before anything scrolls. Narrow columns (status,
 *    counts, short enums) do not grow: their content already fits.
 *
 * Why the two cases differ: CSS grid hands free space to `minmax(default, limit)` tracks BEFORE
 * a `1fr` track sees any. Beside a blank spacer that costs nothing. Beside a flexible column it
 * starves that column, which sits at its minimum until every growing column is full; on the CA
 * page's certificate history that pushed the action buttons off the table's edge.
 */

/** Default width, in px, of a column that declares none. */
export const DEFAULT_COLUMN_WIDTH = 120;

/** A column at least this wide by default is holding text or an identifier, and may grow. */
export const GROWS_FROM = 150;

/** How far a growing column may go beyond its default. */
export const GROWTH = 1.6;

/** The narrowest a flexible column gets when it declares no minimum, in px. */
export const FLEX_MIN_WIDTH = 80;

/** The trailing blank track of a table with no flexible column: it takes the slack and collapses to nothing. */
export const SPACER_TRACK = 'minmax(0, 1fr)';

/** The widest an unsized column of this default width may become. */
export const growLimit = (defaultWidth: number): number =>
    defaultWidth >= GROWS_FROM ? Math.round(defaultWidth * GROWTH) : defaultWidth;

/**
 * Whether an unsized, non-flexible column may grow into free space. A column that says
 * (`grow: true` or `grow: false`) is taken at its word. One that does not grows only in a table
 * with no flexible column: beside a flexible column the slack is that column's.
 */
export const columnGrows = (grow: boolean | undefined, tableHasFlexColumn: boolean): boolean =>
    grow ?? !tableHasFlexColumn;

/**
 * The CSS grid track for a column that does not flex. A width the user set is kept exactly; an
 * unsized column that may grow gets `minmax(default, limit)`, which the grid fills only from free
 * space; one that may not (`grow = false`) stays at its default. Whether a column may grow is
 * `columnGrows`: callers laying out a whole table use `tableColumnTracks`.
 */
export const columnTrack = (defaultWidth: number | undefined, userWidth: number | undefined, grow = true): string => {
    if (userWidth != null) return `${userWidth}px`;
    const base = defaultWidth ?? DEFAULT_COLUMN_WIDTH;
    if (!grow) return `${base}px`;
    const limit = growLimit(base);
    return limit > base ? `minmax(${base}px, ${limit}px)` : `${base}px`;
};

/** The CSS grid track of a flexible column: never under its minimum, and all the slack above it. */
export const flexTrack = (minWidth: number | undefined): string => `minmax(${minWidth ?? FLEX_MIN_WIDTH}px, 1fr)`;

/** What the track computation reads of a column. */
export interface TrackColumn {
    /** Default pixel width of a column the user has not resized. Ignored when `flex`. */
    defaultWidth?: number;
    /** For a flexible column, the narrowest it gets. */
    minWidth?: number;
    /** This column takes the table's slack. */
    flex?: boolean;
    /** Whether an unsized column of 150px or more may grow; unset, it grows only in a table with no flexible column. */
    grow?: boolean;
}

/**
 * The grid tracks of a table's visible columns, in order, with the trailing spacer when no
 * column flexes. `userWidth` gives the width a user set for a column, if any; it always wins
 * for a column that does not flex.
 */
export function tableColumnTracks<C extends TrackColumn>(
    columns: readonly C[],
    userWidth: (column: C) => number | undefined = () => undefined,
): string[] {
    const hasFlex = columns.some((c) => c.flex);
    const tracks = columns.map((c) =>
        c.flex ? flexTrack(c.minWidth) : columnTrack(c.defaultWidth, userWidth(c), columnGrows(c.grow, hasFlex)));
    if (!hasFlex) tracks.push(SPACER_TRACK);
    return tracks;
}
