import { readFileSync, readdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { SPACER_TRACK, columnGrows, columnTrack, growLimit, tableColumnTracks, type TrackColumn } from '@shared/tableTracks';
import { gridFloor, resolveGrid } from './gridArithmetic';

/**
 * Table columns pack left at their defaults so nothing scrolls on a 1920-wide screen. An unsized
 * text column may grow into free space; a width the user set is never changed.
 */
describe('table column tracks', () => {
    it('lets an unsized text column grow to 1.6 times its default', () => {
        expect(columnTrack(180, undefined)).toBe('minmax(180px, 288px)');
        expect(columnTrack(280, undefined)).toBe('minmax(280px, 448px)');
    });

    it('fits a 32-digit serial in the grown serial column', () => {
        // 32 mono characters at 13px are about 250px, plus 24px of cell padding.
        expect(growLimit(180)).toBeGreaterThanOrEqual(274);
    });

    it('keeps narrow columns at their default', () => {
        expect(columnTrack(100, undefined)).toBe('100px');
        expect(columnTrack(149, undefined)).toBe('149px');
        expect(columnTrack(undefined, undefined)).toBe('120px');
    });

    it('keeps a width the user set, exactly', () => {
        expect(columnTrack(280, 500)).toBe('500px');
        expect(columnTrack(280, 90)).toBe('90px');
    });

    it('never makes a column narrower than its default, so nothing scrolls sooner than before', () => {
        for (const width of [60, 120, 150, 240, 320]) {
            const track = columnTrack(width, undefined);
            const min = Number(/(\d+)px/.exec(track)![1]);
            expect(min).toBe(width);
        }
    });
});

/**
 * The rule for a whole table. Tables are left-packed and the slack goes to one place: the
 * flexible column when the table has one, a trailing spacer when it has none. Beside a flexible
 * column no other column grows, because the grid fills a `minmax(default, limit)` track before a
 * `1fr` track gets anything; beside a blank spacer a text column may still grow a little.
 */
describe('the tracks of a whole table', () => {
    const serial: TrackColumn = { defaultWidth: 280 };
    const reason: TrackColumn = { defaultWidth: 170 };
    const count: TrackColumn = { defaultWidth: 100 };
    const note: TrackColumn = { flex: true };

    it('(a) with a flexible column, keeps every other column at its default and gives the slack to the flexible one', () => {
        const tracks = tableColumnTracks([serial, reason, count, note]);

        expect(tracks).toEqual(['280px', '170px', '100px', 'minmax(80px, 1fr)']);
        expect(resolveGrid(tracks, 1000)).toEqual([280, 170, 100, 450]);
        expect(resolveGrid(tracks, 1300)).toEqual([280, 170, 100, 750]);
        // Under its floor the flexible column holds its minimum and the table scrolls.
        expect(resolveGrid(tracks, 500)).toEqual([280, 170, 100, 80]);
        expect(gridFloor(tracks)).toBe(630);
    });

    it('(a) the flexible column takes the slack wherever it stands, and at its own minimum when it names one', () => {
        expect(tableColumnTracks([{ flex: true, minWidth: 230 }, serial])).toEqual(['minmax(230px, 1fr)', '280px']);
        expect(resolveGrid(tableColumnTracks([count, note, serial]), 1000)).toEqual([100, 620, 280]);
    });

    it('(b) with no flexible column, lets text columns grow first and gives the rest to a trailing spacer', () => {
        const tracks = tableColumnTracks([serial, reason, count]);

        expect(tracks).toEqual(['minmax(280px, 448px)', 'minmax(170px, 272px)', '100px', SPACER_TRACK]);
        // Narrower than the defaults: nothing grows, the spacer is empty, the columns are left-packed.
        expect(resolveGrid(tracks, 550)).toEqual([280, 170, 100, 0]);
        // Some room: the two text columns share it equally, the narrow one stays, the spacer is still empty.
        expect(resolveGrid(tracks, 700)).toEqual([355, 245, 100, 0]);
        // Plenty of room: each text column stops at 1.6 times its default and the spacer takes the rest.
        expect(resolveGrid(tracks, 1300)).toEqual([448, 272, 100, 480]);
    });

    it('(c) keeps a width the user set, exactly, in both kinds of table', () => {
        const sized = (c: TrackColumn) => (c === serial ? 420 : c === count ? 64 : undefined);

        expect(tableColumnTracks([serial, reason, count, note], sized)).toEqual(['420px', '170px', '64px', 'minmax(80px, 1fr)']);
        expect(tableColumnTracks([serial, reason, count], sized)).toEqual(['420px', 'minmax(170px, 272px)', '64px', SPACER_TRACK]);
        expect(resolveGrid(tableColumnTracks([serial, reason, count, note], sized), 1000)).toEqual([420, 170, 64, 346]);
    });

    it('(c) gives a flexible column no stored width: it has no resize handle, and the slack is what it is for', () => {
        expect(tableColumnTracks([serial, note], () => 500)).toEqual(['500px', 'minmax(80px, 1fr)']);
    });

    it('(d) lets a column that says grow: true grow anyway, before the flexible column gets anything', () => {
        const eager: TrackColumn = { defaultWidth: 280, grow: true };
        const tracks = tableColumnTracks([eager, reason, note]);

        expect(tracks).toEqual(['minmax(280px, 448px)', '170px', 'minmax(80px, 1fr)']);
        // 530 is the floor. The next 168px all go to the growing column; only then does the flexible one widen.
        expect(resolveGrid(tracks, 630)).toEqual([380, 170, 80]);
        expect(resolveGrid(tracks, 698)).toEqual([448, 170, 80]);
        expect(resolveGrid(tracks, 1000)).toEqual([448, 170, 382]);
    });

    it('(d) keeps a column that says grow: false at its default in a table with no flexible column too', () => {
        expect(tableColumnTracks([{ defaultWidth: 280, grow: false }, reason])).toEqual(['280px', 'minmax(170px, 272px)', SPACER_TRACK]);
    });

    it('decides growth from what the column says, and from the table only when it says nothing', () => {
        expect(columnGrows(undefined, false)).toBe(true);
        expect(columnGrows(undefined, true)).toBe(false);
        expect(columnGrows(true, true)).toBe(true);
        expect(columnGrows(false, false)).toBe(false);
    });

    it('fills the grid exactly at or above its floor, in every kind of table', () => {
        for (const columns of [[serial, reason, count, note], [serial, reason, count], [{ defaultWidth: 280, grow: true }, note]])
            for (const width of [700, 1000, 1300, 1920]) {
                const tracks = tableColumnTracks(columns);
                if (width >= gridFloor(tracks)) expect(resolveGrid(tracks, width).reduce((a, b) => a + b, 0)).toBe(width);
            }
    });
});

/**
 * The console's tables are laid out as the certificates page lays its table out: no flexible
 * column. Every column has a width of its own, the table packs left, wide columns may grow a
 * little, and the spare width is left after the last column. A flexible column takes only what
 * the others leave, and in a narrow place that is nothing: four tables once showed a subject of
 * five characters for it.
 */
describe('no table in the consoles has a flexible column', () => {
    it('no column is declared with flex: true', () => {
        const root = fileURLToPath(new URL('../../../../', import.meta.url));
        const declaring: string[] = [];
        const walk = (dir: string) => {
            for (const entry of readdirSync(dir, { withFileTypes: true })) {
                if (entry.name === 'node_modules' || entry.name === 'dist' || entry.name === 'generated') continue;
                const path = `${dir}/${entry.name}`;
                if (entry.isDirectory()) walk(path);
                else if (/\.tsx?$/.test(entry.name) && readFileSync(path, 'utf8').split('\n').some((l) => !/^\s*(\/\/|\*|\/\*)/.test(l) && /\bflex: true\b/.test(l)))
                    declaring.push(path.slice(root.length).replace(/\\/g, '/'));
            }
        };
        for (const tree of ['modularca.adminui/src', 'modularca.publicui/src', 'modularca.setupui/src', 'modularca.docsui/src'])
            walk(`${root}${tree}`.replace(/\\/g, '/'));
        expect(declaring).toEqual([]);
    });

    it('a table of fixed columns packs left: each keeps at least its default and the spacer takes the rest', () => {
        const columns: TrackColumn[] = [{ defaultWidth: 300, grow: false }, { defaultWidth: 90 }, { defaultWidth: 120 }, { defaultWidth: 120 }, { defaultWidth: 132 }, { defaultWidth: 240, grow: false }];
        const tracks = tableColumnTracks(columns);
        expect(tracks).toEqual(['300px', '90px', '120px', '120px', '132px', '240px', SPACER_TRACK]);
        // The certificate history table at the width it was first looked at: its columns, then 7px to spare.
        expect(resolveGrid(tracks, 1009)).toEqual([300, 90, 120, 120, 132, 240, 7]);
        expect(gridFloor(tracks)).toBe(1002);
    });
});

/**
 * The four recent-certificate tables once had a flexible subject with no width of its own, in a
 * card half the page wide: the fixed columns took the card and the subject fell to 80px
 * ("CN=lo…"). They now carry the subject and serial of the certificates page and stand one to a
 * row, so the subject has a width it cannot lose.
 */
describe('the recent-certificate tables are laid out as the certificates page is', () => {
    const source = (file: string) => readFileSync(fileURLToPath(new URL(`../../../../modularca.adminui/src/${file}`, import.meta.url)), 'utf8');
    const SUBJECT = "{ key: 'subject', header: 'Subject', defaultWidth: 280, minWidth: 160, sortable: true,";
    // Wider than the certificates page's 180: here the serial is shown whole, and 32 digits need about 274px.
    const SERIAL = "{ key: 'serial', header: 'Serial', defaultWidth: 280,";

    it('the certificates page sets the subject at 280 with a floor of 160', () => {
        const page = source('pages/Certificates.tsx');
        expect(page).toContain(SUBJECT);
        expect(page).toContain("{ key: 'serial', header: 'Serial', defaultWidth: 180, sortable: true,");
    });

    it.each([['pages/CertInventory.tsx', 2], ['pages/Compliance.tsx', 2]] as const)('%s declares both of its tables the same way', (file, tables) => {
        const page = source(file);
        expect(page.split(SUBJECT).length - 1).toBe(tables);
        expect(page.split(SERIAL).length - 1).toBe(tables);
        expect(page).not.toMatch(/key: 'subject'[^}]*flex: true/);
    });

    it('neither page puts those tables side by side', () => {
        expect(source('pages/CertInventory.tsx')).not.toMatch(/lg:grid-cols-2 gap-6">\s*\{\/\* 6\. Recently Issued/);
        expect(source('pages/Compliance.tsx')).not.toMatch(/lg:grid-cols-2 gap-6">\s*<Section title="Recent Issuances/);
    });

    it('the subject keeps at least its floor however narrow the table, and its default from 900px up', () => {
        const columns: TrackColumn[] = [{ defaultWidth: 280, minWidth: 160 }, { defaultWidth: 280 }, { defaultWidth: 240 }, { defaultWidth: 150 }];
        const tracks = tableColumnTracks(columns);
        expect(tracks[0]).toBe('minmax(280px, 448px)');
        expect(resolveGrid(['32px', ...tracks, SPACER_TRACK], 1000)[1]).toBeGreaterThanOrEqual(280);
    });
});
