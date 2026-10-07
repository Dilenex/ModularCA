/*
 * Grid tracks for DataTable columns. No React here, so tests/modularca.web.tests can cover it.
 *
 * Columns pack to the left at their default widths and a trailing spacer takes the slack, so a
 * table never needs a horizontal scroll bar on a 1920-wide screen. On a wider screen that left
 * text cut off beside empty space. A column nobody has resized may therefore grow, up to
 * GROWTH times its default, while there is room; it gives the room back before anything
 * scrolls. Narrow columns (status, counts, short enums) do not grow: their content already fits.
 */

/** Default width, in px, of a column that declares none. */
export const DEFAULT_COLUMN_WIDTH = 120;

/** A column at least this wide by default is holding text or an identifier, and may grow. */
export const GROWS_FROM = 150;

/** How far a growing column may go beyond its default. */
export const GROWTH = 1.6;

/** The widest an unsized column of this default width may become. */
export const growLimit = (defaultWidth: number): number =>
    defaultWidth >= GROWS_FROM ? Math.round(defaultWidth * GROWTH) : defaultWidth;

/**
 * The CSS grid track for a column that does not flex. A width the user set is kept exactly; an
 * unsized column gets `minmax(default, limit)`, which the grid fills only from free space.
 */
export const columnTrack = (defaultWidth: number | undefined, userWidth: number | undefined): string => {
    if (userWidth != null) return `${userWidth}px`;
    const base = defaultWidth ?? DEFAULT_COLUMN_WIDTH;
    const limit = growLimit(base);
    return limit > base ? `minmax(${base}px, ${limit}px)` : `${base}px`;
};
