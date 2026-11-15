import { describe, expect, it } from 'vitest';
import { advisoryBadgeStatus, advisoryBox, advisoryNoticeSeverity, caLifecycleAttention, cryptoperiodRows } from '@adminui/pages/caLifecycle';
import { HISTORY_COLUMN_LAYOUT, validityNotes } from '@adminui/pages/caRenewal';
import { sessionMaximumAdvice } from '@adminui/pages/tighterDefaults';
import { SPACER_TRACK, columnTrack, growLimit, tableColumnTracks } from '@shared/tableTracks';
import { gridFloor, resolveGrid } from '../common/gridArithmetic';

const words = (text: string): number => text.trim().split(/\s+/).length;

/**
 * A notice is information, not a deadline: blue. Amber is a warning, red is critical. The same
 * three tones on the CA page, in the Security Baseline on System Health, and in the renewal and
 * creation dialogs and the ceremony record.
 */
describe('the color of a CA notice', () => {
    it('is informational for a notice, amber for a warning and red only for critical, as an inline notice', () => {
        expect(advisoryNoticeSeverity({ severity: 'notice' })).toBe('info');
        expect(advisoryNoticeSeverity({ severity: 'warning' })).toBe('warning');
        expect(advisoryNoticeSeverity({ severity: 'critical' })).toBe('error');
        expect(advisoryNoticeSeverity({})).toBe('info');
        expect(advisoryNoticeSeverity(null)).toBe('info');
    });

    it('is the blue, amber and red badge in the Security Baseline', () => {
        expect(advisoryBadgeStatus({ severity: 'notice' })).toBe('pending');
        expect(advisoryBadgeStatus({ severity: 'warning' })).toBe('held');
        expect(advisoryBadgeStatus({ severity: 'critical' })).toBe('revoked');
        expect(advisoryBadgeStatus({})).toBe('pending');
    });

    it('uses the console\'s status tokens for a hand-built box, and never amber for a notice', () => {
        expect(advisoryBox('notice')).toEqual({ box: 'border-info/40 bg-info-soft', text: 'text-info' });
        expect(advisoryBox('warn')).toEqual({ box: 'border-warn/40 bg-warn-soft', text: 'text-warn' });
        expect(advisoryBox('crit')).toEqual({ box: 'border-crit/40 bg-crit-soft', text: 'text-crit' });
        expect(`${advisoryBox('notice').box} ${advisoryBox('notice').text}`).not.toContain('warn');
    });

    it('leaves a notice out of the dashboard\'s "Needs attention"', () => {
        const cas = [{ caId: 'a', caName: 'A', keyAdvisories: [{ reason: 'CaProfilesOutliveCertificate', severity: 'notice', title: 'T', message: 'M' }] }];
        expect(caLifecycleAttention(cas)).toEqual([]);
    });
});

describe('the length of what the console itself says', () => {
    const now = new Date('2026-11-13T00:00:00Z');

    it('keeps each validity note of the creation and renewal dialogs to 40 words', () => {
        const notes = [...validityNotes(true, 50, true, now), ...validityNotes(false, 50, true, now)];
        expect(notes.map((n) => n.reason).sort()).toEqual(
            ['CaRsaKeyBelow3072Past2030', 'CaRsaKeyBelow3072Past2030', 'CaValidityBeyondCommonPractice', 'CaValidityBeyondCommonPractice']);
        for (const note of notes) expect(words(note.message), note.message).toBeLessThanOrEqual(40);
    });

    it('says the same thing as the server about a long validity and about RSA past 2030', () => {
        const [rsa, long] = validityNotes(true, 30, true, now);
        expect(rsa.severity).toBe('warning');
        expect(rsa.message).toContain('only through 2030');
        expect(long.severity).toBe('notice');
        expect(long.message).toBe('More than 25 years is longer than common practice for a root CA (10 to 25 years). Nothing is refused; a shorter certificate can be renewed later.');
    });

    it('keeps the session sentences of the Security Baseline to 40 words', () => {
        for (const hours of [0, 13, 720, 87600]) expect(words(sessionMaximumAdvice(hours)!)).toBeLessThanOrEqual(40);
    });
});

describe('the longest profile validity on a CA page', () => {
    it('says when the only profile with a maximum is one of the CA\'s own infrastructure profiles', () => {
        const rows = cryptoperiodRows({ certificateNotAfter: '2036-01-01T00:00:00Z', longestProfileValidityDays: 3650, longestProfileName: 'OCSP Responder', longestProfileIsInfrastructure: true });
        const row = rows.find((r) => r.label.startsWith('Longest validity'))!;
        expect(row.label).toBe('Longest validity its profiles allow (infrastructure only)');
        expect(row.value).toContain('OCSP Responder');
    });

    it('is the end-entity profile otherwise', () => {
        const rows = cryptoperiodRows({ certificateNotAfter: '2036-01-01T00:00:00Z', longestProfileValidityDays: 397, longestProfileName: 'TLS Server' });
        expect(rows.find((r) => r.label.startsWith('Longest validity'))!.label).toBe('Longest validity its profiles allow');
    });
});

/**
 * The history table once showed STATUS and HOW 190px wide and its last column at 70px with the
 * two actions wrapped. The cause: an unsized column of 150px or more was a `minmax(default,
 * 1.6 × default)` track, and the grid fills such tracks from free space BEFORE the `1fr` track of
 * a flexing column. The serial (300), status (170) and how (170) columns took the free space and
 * the flexing last column stayed at its 80px minimum. It was first fixed here with a per-column
 * `grow: false`; now no table with a flexible column grows its other columns, and this one says
 * nothing about growth at all.
 */
describe('the columns of the certificate history table', () => {
    const layout = HISTORY_COLUMN_LAYOUT;
    const fixed = [layout.serial, layout.status, layout.notBefore, layout.notAfter, layout.origin];
    const columns = [layout.serial, layout.status, layout.notBefore, layout.notAfter, layout.origin, layout.download];
    const tracks = tableColumnTracks(columns);

    it('has no flexible column, as the certificates page has none, and neither wide column grows', () => {
        for (const c of columns) expect('flex' in c).toBe(false);
        expect(layout.serial.grow).toBe(false);
        expect(layout.download.grow).toBe(false);
        // Every column at its own width, then the spacer that takes what is left.
        expect(tracks).toEqual(['300px', '90px', '120px', '120px', '132px', '240px', SPACER_TRACK]);
    });

    it('yields the layout the owner set at his 1,009px table: 300, 90, 120, 120, 132, 240, and 7px to spare', () => {
        expect(resolveGrid(tracks, 1009)).toEqual([300, 90, 120, 120, 132, 240, 7]);
        // Wider, the columns stay as they are and the spare width is left after the last one.
        expect(resolveGrid(tracks, 1300)).toEqual([300, 90, 120, 120, 132, 240, 298]);
        expect(gridFloor(tracks)).toBe(1002);
    });

    it('gives the last column room for its two actions side by side', () => {
        expect(layout.download.defaultWidth).toBeGreaterThanOrEqual(layout.download.minWidth!);
        expect(layout.download.minWidth).toBeGreaterThanOrEqual(220);
    });

    it('fits his 1,009px table without a horizontal scroll bar', () => {
        const floor = columns.reduce((sum, c) => sum + c.defaultWidth!, 0);
        expect(floor).toBeLessThanOrEqual(1009);
    });

    it('lands on the layout the owner set by hand: a 300px serial, a badge-wide status, 120px dates, a 132px origin', () => {
        expect(layout.serial.defaultWidth).toBe(300);
        expect(layout.status.defaultWidth).toBeLessThanOrEqual(96);
        expect(layout.notBefore.defaultWidth).toBe(120);
        expect(layout.notAfter.defaultWidth).toBe(120);
        expect(layout.origin.defaultWidth).toBeLessThan(150);
        // At his 1,009px the last column gets what he gave it, within a few pixels.
        const remainder = 1009 - fixed.reduce((sum, c) => sum + c.defaultWidth!, 0);
        expect(Math.abs(remainder - 250)).toBeLessThanOrEqual(5);
    });

    it('keeps a width a user set, whatever the default became', () => {
        expect(columnTrack(layout.status.defaultWidth, 190, false)).toBe('190px');
        expect(columnTrack(layout.serial.defaultWidth, 420, false)).toBe('420px');
        const sized = tableColumnTracks(columns, (c) => (c === layout.status ? 190 : c === layout.serial ? 420 : undefined));
        expect(sized).toEqual(['420px', '190px', '120px', '120px', '132px', '240px', SPACER_TRACK]);
    });
});

describe('a column that does not grow', () => {
    it('stays at its default where a growing one would take free space', () => {
        expect(columnTrack(300, undefined)).toBe(`minmax(300px, ${growLimit(300)}px)`);
        expect(columnTrack(300, undefined, false)).toBe('300px');
        expect(columnTrack(undefined, undefined, false)).toBe('120px');
    });
});
