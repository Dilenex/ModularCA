/**
 * Arithmetic for the three kinds of track a DataTable writes into `grid-template-columns`:
 * `Npx`, `minmax(Apx, Bpx)` and `minmax(Apx, 1fr)`. It follows the CSS grid track sizing
 * algorithm for a container of a known width, as far as those three kinds need it:
 *
 *  1. every track starts at its minimum;
 *  2. free space is shared equally among the `minmax(A, B)` tracks until each reaches B
 *     ("maximize tracks": a `1fr` track does not take part, its growth limit is its base size);
 *  3. what is left after that goes to the `1fr` tracks, never under their minimum.
 *
 * This is a model, not a browser: it has no fonts, no content and no scroll bar. It is what the
 * layout tests and the widths quoted for a table are computed with.
 */

interface Track { base: number; limit: number; flex: boolean }

function parse(track: string): Track {
    const px = /^(\d+(?:\.\d+)?)px$/.exec(track);
    if (px) return { base: Number(px[1]), limit: Number(px[1]), flex: false };
    const range = /^minmax\((\d+(?:\.\d+)?)(?:px)?, (\d+(?:\.\d+)?)px\)$/.exec(track);
    if (range) return { base: Number(range[1]), limit: Number(range[2]), flex: false };
    const flex = /^minmax\((\d+(?:\.\d+)?)(?:px)?, 1fr\)$/.exec(track);
    if (flex) return { base: Number(flex[1]), limit: Number(flex[1]), flex: true };
    throw new Error(`not a track this model knows: ${track}`);
}

/** The width, in whole px, of each of `tracks` in a grid `width` px wide. */
export function resolveGrid(tracks: readonly string[], width: number): number[] {
    const parsed = tracks.map(parse);
    const sizes = parsed.map((t) => t.base);
    let free = width - sizes.reduce((a, b) => a + b, 0);

    let growing = parsed.map((t, i) => i).filter((i) => !parsed[i].flex && parsed[i].limit > parsed[i].base);
    while (free > 1e-9 && growing.length > 0) {
        const share = free / growing.length;
        const still: number[] = [];
        for (const i of growing) {
            const add = Math.min(share, parsed[i].limit - sizes[i]);
            sizes[i] += add;
            free -= add;
            if (parsed[i].limit - sizes[i] > 1e-9) still.push(i);
        }
        if (still.length === growing.length) break;
        growing = still;
    }

    const flexible = parsed.map((t, i) => i).filter((i) => parsed[i].flex);
    if (flexible.length > 0) {
        const taken = sizes.reduce((sum, size, i) => (parsed[i].flex ? sum : sum + size), 0);
        for (const i of flexible) sizes[i] = Math.max(parsed[i].base, (width - taken) / flexible.length);
    }
    return sizes.map((size) => Math.round(size));
}

/** The narrowest the grid gets before it scrolls: every track at its minimum. */
export function gridFloor(tracks: readonly string[]): number {
    return tracks.map(parse).reduce((sum, t) => sum + t.base, 0);
}
