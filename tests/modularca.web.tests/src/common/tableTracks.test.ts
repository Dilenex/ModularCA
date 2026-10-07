import { describe, expect, it } from 'vitest';
import { columnTrack, growLimit } from '@shared/tableTracks';

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
