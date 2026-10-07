import { describe, expect, it } from 'vitest';
import type { CertificateLifecycleSummaryModel } from '@shared/generated';
import {
    attentionTone, canReissue, channelNote, durationPhrase, expiryPhrase, expiryState, lifecycleHealth,
    lifecycleTone, relativeTime, sortAttention,
} from '@adminui/pages/certLifecycle';

const NOW = new Date('2026-10-05T12:00:00Z');
const MIN = 60_000;
const HOUR = 60 * MIN;
const DAY = 24 * HOUR;
const at = (ms: number) => new Date(NOW.getTime() + ms).toISOString();

function summary(patch: Partial<CertificateLifecycleSummaryModel> = {}): CertificateLifecycleSummaryModel {
    return {
        generatedAt: NOW.toISOString(), replacementWindowDays: 90, total: 0, active: 0, revoked: 0, expired: 0,
        expiringWithin7Days: 0, expiringWithin30Days: 0, expiringWithin7DaysNotReplaced: 0, expiringWithin30DaysNotReplaced: 0,
        expiredReplaced: 0, expiredNotReplaced: 0, expiredUnchecked: 0, recentlyExpiredNotReplaced: 0,
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

    it('grades expiring certificates by the unreplaced ones', () => {
        const health = (p: Partial<CertificateLifecycleSummaryModel>) => lifecycleHealth(summary(p), NOW).find(h => h.key === 'expiring')!;
        expect(health({ expiringWithin30Days: 3, expiringWithin7Days: 1, expiringWithin7DaysNotReplaced: 1, expiringWithin30DaysNotReplaced: 3 }).tone).toBe('crit');
        const warn = health({ expiringWithin30Days: 3, expiringWithin30DaysNotReplaced: 2 });
        expect(warn.tone).toBe('warn');
        expect(warn.to).toMatch(/^\/certificates\?status=active&replaced=no&notAfterTo=\d{4}-\d{2}-\d{2}$/);
        expect(health({ expiringWithin30Days: 3 }).tone).toBe('ok');
        expect(health({}).tone).toBe('ok');
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
    });
});
