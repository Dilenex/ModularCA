import { describe, expect, it } from 'vitest';
import type { CertificateLifecycleSummaryModel } from '@shared/generated';
import {
    attentionTone, canReissue, channelNote, durationPhrase, expiringLink, expiryHandling, expiryHandlingNote, expiryLevel, expiryPhrase,
    expiryScheduleText, expiryState, lifecycleHealth, lifecycleTone, neverWarns, relativeTime, sortAttention,
} from '@adminui/pages/certLifecycle';

const NOW = new Date('2026-10-05T12:00:00Z');
const MIN = 60_000;
const HOUR = 60 * MIN;
const DAY = 24 * HOUR;
const at = (ms: number) => new Date(NOW.getTime() + ms).toISOString();

function summary(patch: Partial<CertificateLifecycleSummaryModel> = {}): CertificateLifecycleSummaryModel {
    return {
        generatedAt: NOW.toISOString(), replacementWindowDays: 90, total: 0, active: 0, revoked: 0, expired: 0,
        inExpiryWarning: 0, inExpiryWarningNotReplaced: 0, inExpiryAlert: 0, inExpiryAlertNotReplaced: 0,
        expiringWithin7Days: 0, expiringWithin30Days: 0, expiringWithin7DaysNotReplaced: 0, expiringWithin30DaysNotReplaced: 0,
        expiredReplaced: 0, expiredNotReplaced: 0, retiredOrDismissed: 0, expiredUnchecked: 0, recentlyExpiredNotReplaced: 0,
        attentionTotal: 0, attention: [], byCa: [], ...patch,
    };
}

describe('relative time', () => {
    it('picks the largest unit that fits and rounds down', () => {
        expect(durationPhrase(30_000)).toBe('less than a minute');
        expect(durationPhrase(MIN)).toBe('1 minute');
        expect(durationPhrase(59 * MIN)).toBe('59 minutes');
        expect(durationPhrase(5 * HOUR + 59 * MIN)).toBe('5 hours');
        expect(durationPhrase(DAY)).toBe('1 day');
        expect(durationPhrase(3 * DAY + 23 * HOUR)).toBe('3 days');
        expect(durationPhrase(59 * DAY)).toBe('59 days');
        expect(durationPhrase(90 * DAY)).toBe('3 months');
        expect(durationPhrase(800 * DAY)).toBe('2 years');
    });

    it('says ago for the past and in for the future', () => {
        expect(relativeTime(at(-3 * DAY), NOW)).toBe('3 days ago');
        expect(relativeTime(at(5 * DAY + HOUR), NOW)).toBe('in 5 days');
        expect(expiryPhrase(at(-3 * DAY), NOW)).toBe('expired 3 days ago');
        expect(expiryPhrase(at(5 * DAY), NOW)).toBe('expires in 5 days');
        expect(expiryPhrase(at(2 * HOUR), NOW)).toBe('expires in 2 hours');
    });

    it('classifies expiry, revoked first', () => {
        expect(expiryState({ notAfter: at(-DAY) }, NOW)).toBe('expired');
        expect(expiryState({ notAfter: at(10 * DAY) }, NOW)).toBe('expiring');
        expect(expiryState({ notAfter: at(40 * DAY) }, NOW)).toBe('active');
        expect(expiryState({ notAfter: at(-DAY), revoked: true }, NOW)).toBe('revoked');
    });
});

describe('stored expiry instants', () => {
    // A 10-hour certificate issued an hour ago: warning at 3 h left, alert at 1 h left.
    const tenHour = { notAfter: at(9 * HOUR), expiryWarningAt: at(6 * HOUR), expiryAlertAt: at(8 * HOUR) };
    // A one-year certificate 100 days from expiry: in its warning (about 110 days), not its alert (about 37).
    const year = { notAfter: at(100 * DAY), expiryWarningAt: at(-10 * DAY), expiryAlertAt: at(63 * DAY) };

    it('follows the instants, not a fixed 30 days', () => {
        expect(expiryState(tenHour, NOW)).toBe('active');
        expect(expiryLevel(tenHour, NOW)).toBe('none');
        expect(lifecycleTone(tenHour, false, NOW)).toBe('ok');
        expect(expiryState(year, NOW)).toBe('expiring');
        expect(expiryLevel(year, NOW)).toBe('warning');
        expect(lifecycleTone(year, false, NOW)).toBe('warn');
    });

    it('is critical once the alert has started', () => {
        const alerted = { ...tenHour, expiryWarningAt: at(-2 * HOUR), expiryAlertAt: at(-MIN) };
        expect(expiryLevel(alerted, NOW)).toBe('alert');
        expect(lifecycleTone(alerted, false, NOW)).toBe('crit');
        expect(attentionTone(alerted, NOW)).toBe('crit');
        expect(attentionTone({ ...alerted, expiryAlertAt: at(HOUR) }, NOW)).toBe('warn');
    });

    it('never warns when the profile says so, but an unreplaced expiry stays red', () => {
        const never = { notAfter: at(2 * HOUR), expiryWarningAt: at(2 * HOUR), expiryAlertAt: at(2 * HOUR) };
        expect(neverWarns(never)).toBe(true);
        expect(expiryState(never, NOW)).toBe('active');
        expect(lifecycleTone(never, false, NOW)).toBe('ok');
        const expired = { notAfter: at(-HOUR), expiryWarningAt: at(-HOUR), expiryAlertAt: at(-HOUR) };
        expect(expiryState(expired, NOW)).toBe('expired');
        expect(lifecycleTone(expired, false, NOW)).toBe('crit');
        expect(lifecycleTone(expired, true, NOW)).toBe('neutral');
    });

    it('falls back to 30 and 7 days for a row without instants', () => {
        expect(expiryLevel({ notAfter: at(6 * DAY) }, NOW)).toBe('alert');
        expect(expiryLevel({ notAfter: at(20 * DAY) }, NOW)).toBe('warning');
        expect(expiryLevel({ notAfter: at(60 * DAY) }, NOW)).toBe('none');
        expect(expiryState({ notAfter: at(20 * DAY), expiryWarningAt: null }, NOW)).toBe('expiring');
    });

    it('describes the schedule for the certificate page', () => {
        const iso = (d: string) => d.slice(0, 10);
        expect(expiryScheduleText(year, iso)).toBe(`Warns from ${year.expiryWarningAt.slice(0, 10)}; alert from ${year.expiryAlertAt.slice(0, 10)}`);
        expect(expiryScheduleText({ notAfter: at(DAY), expiryWarningAt: at(DAY), expiryAlertAt: at(DAY) })).toBe('No expiry warning (profile)');
        expect(expiryScheduleText({ notAfter: at(DAY) })).toBeNull();
    });
});

describe('tone rules', () => {
    it('keeps a replaced certificate neutral however expired', () => {
        expect(lifecycleTone(at(-2 * DAY), true, NOW)).toBe('neutral');
        expect(lifecycleTone(at(3 * DAY), true, NOW)).toBe('neutral');
    });

    it('is critical for a recent expiry or one within 7 days, a warning further out', () => {
        expect(lifecycleTone(at(-2 * DAY), false, NOW)).toBe('crit');
        expect(lifecycleTone(at(-45 * DAY), false, NOW)).toBe('warn');
        expect(lifecycleTone(at(6 * DAY), false, NOW)).toBe('crit');
        expect(lifecycleTone(at(20 * DAY), false, NOW)).toBe('warn');
        expect(lifecycleTone(at(60 * DAY), false, NOW)).toBe('ok');
        expect(attentionTone({ notAfter: at(-DAY) }, NOW)).toBe('crit');
    });

    it('does not shout about expired certificates that were all replaced', () => {
        const expired = lifecycleHealth(summary({ expired: 12, expiredReplaced: 12 }), NOW).find(h => h.key === 'expired')!;
        expect(expired.tone).toBe('neutral');
        expect(expired.to).toBe('/certificates?status=expired');
    });

    it('is critical for a recent unreplaced expiry and links to the unreplaced list', () => {
        const expired = lifecycleHealth(summary({ expired: 5, expiredNotReplaced: 2, recentlyExpiredNotReplaced: 1 }), NOW).find(h => h.key === 'expired')!;
        expect(expired.tone).toBe('crit');
        expect(expired.to).toBe('/certificates?status=expired&replaced=no');
        expect(expired.detail).toContain('1 certificate expired in the last 30 days');
    });

    it('warns for an older unreplaced expiry', () => {
        expect(lifecycleHealth(summary({ expired: 5, expiredNotReplaced: 2 }), NOW).find(h => h.key === 'expired')!.tone).toBe('warn');
    });

    it('grades expiring certificates by the unreplaced ones in their warning and alert', () => {
        const health = (p: Partial<CertificateLifecycleSummaryModel>) => lifecycleHealth(summary(p), NOW).find(h => h.key === 'expiring')!;
        const crit = health({ inExpiryWarning: 3, inExpiryAlert: 1, inExpiryAlertNotReplaced: 1, inExpiryWarningNotReplaced: 3 });
        expect(crit.tone).toBe('crit');
        expect(crit.to).toBe('/certificates?status=alert&replaced=no');
        const warn = health({ inExpiryWarning: 3, inExpiryWarningNotReplaced: 2 });
        expect(warn.tone).toBe('warn');
        expect(warn.to).toBe('/certificates?status=expiring&replaced=no');
        expect(warn.detail).toBe('2 certificates in their expiry warning with no replacement');
        const handled = health({ inExpiryWarning: 3 });
        expect(handled.tone).toBe('ok');
        expect(handled.to).toBe('/certificates?status=expiring');
        expect(health({}).tone).toBe('ok');
    });

    it('ignores the deprecated fixed-window counts', () => {
        const health = lifecycleHealth(summary({ expiringWithin30Days: 5, expiringWithin30DaysNotReplaced: 5, expiringWithin7DaysNotReplaced: 2 }), NOW)
            .find(h => h.key === 'expiring')!;
        expect(health).toMatchObject({ tone: 'ok', detail: 'No certificate is in its expiry warning' });
    });

    it('links to the expiring and alert lists', () => {
        expect(expiringLink()).toBe('/certificates?status=expiring&replaced=no');
        expect(expiringLink(true)).toBe('/certificates?status=alert&replaced=no');
        expect(expiringLink(false, false)).toBe('/certificates?status=expiring');
    });
});

describe('attention ordering', () => {
    it('puts expired first, most recent first, then expiring soonest first', () => {
        const items = [
            { serialNumber: 'soon-10', notAfter: at(10 * DAY) },
            { serialNumber: 'old', notAfter: at(-20 * DAY) },
            { serialNumber: 'soon-2', notAfter: at(2 * DAY) },
            { serialNumber: 'recent', notAfter: at(-HOUR) },
        ];
        expect(sortAttention(items, NOW).map(i => i.serialNumber)).toEqual(['recent', 'old', 'soon-2', 'soon-10']);
        expect(items[0].serialNumber).toBe('soon-10');
    });

    it('breaks ties by serial', () => {
        const items = [{ serialNumber: 'b', notAfter: at(DAY) }, { serialNumber: 'a', notAfter: at(DAY) }];
        expect(sortAttention(items, NOW).map(i => i.serialNumber)).toEqual(['a', 'b']);
    });
});

describe('channel notes and reissue', () => {
    it('points an ACME certificate at its client', () => {
        expect(channelNote('ACME')).toContain('ACME client');
        expect(channelNote(null)).toContain('not on record');
    });

    it('offers reissue as the certificate page does', () => {
        expect(canReissue({ revoked: false })).toBe(true);
        expect(canReissue({ revoked: true, revocationReason: 'CertificateHold' })).toBe(true);
        expect(canReissue({ revoked: true, revocationReason: 'KeyCompromise' })).toBe(false);
        expect(canReissue({ revoked: false, retiredAt: NOW.toISOString() })).toBe(false);
    });
});

describe('retired and dismissed certificates', () => {
    it('names how an expiry was handled, retirement first', () => {
        expect(expiryHandling({})).toBeNull();
        expect(expiryHandling({ expiryWarningDismissedAt: at(-DAY) })).toBe('dismissed');
        expect(expiryHandling({ retiredAt: at(-DAY), expiryWarningDismissedAt: at(-DAY) })).toBe('retired');
    });

    it('says a retired certificate needs a new enrollment and a dismissed one still renews', () => {
        expect(expiryHandlingNote({ retiredAt: at(-DAY), retiredBy: 'ops', retiredReason: 'host decommissioned' }))
            .toBe('Retired by ops: host decommissioned. It stays valid until it expires, but is not renewed or reissued; its subject needs a new enrollment.');
        expect(expiryHandlingNote({ expiryWarningDismissedAt: at(-DAY) })).toContain('can still be renewed');
        expect(expiryHandlingNote({})).toBeNull();
    });

    it('counts retired and dismissed certificates as handled on the dashboard', () => {
        const items = lifecycleHealth(summary({ inExpiryWarning: 2, retiredOrDismissed: 2 }), NOW);
        expect(items.find(i => i.key === 'expiring')).toMatchObject({ tone: 'ok', detail: '2 certificates in their expiry warning, each replaced, retired or dismissed' });
        const expired = lifecycleHealth(summary({ expired: 1, retiredOrDismissed: 1 }), NOW).find(i => i.key === 'expired');
        expect(expired).toMatchObject({ tone: 'neutral', detail: '1 certificate expired; every one from the last 90 days was replaced, retired or dismissed' });
    });
});
