import { describe, expect, it } from 'vitest';
import type { ValidityCeilingPreflight } from '@shared/generated';
import {
    toDateInputValue, validityCeilingUrl, validUntilLimit, validUntilNotAfter,
} from '@adminui/pages/validUntil';

/**
 * The "Valid until" date picker on issuing an approved request (the request page and the bulk issue
 * dialog).
 *
 * Bug hunt 2026-11, admin console: the picker's max came from the raw certificate profile's period
 * added to now and cut to a UTC calendar date, and the chosen day was submitted as 23:59:59 UTC. So
 * the last day offered ran up to a day past the server's ceiling, which refuses a notAfter beyond
 * it, and near midnight the day shown was not the operator's day.
 *
 * Every expected value is built from local components, so the suite holds in whatever timezone it
 * runs in; a literal that only holds on a UTC host would pass on CI and hide the bug elsewhere.
 */

function preflight(effectiveNotAfter: Date, notBefore = new Date(2026, 10, 8, 9, 55)): ValidityCeilingPreflight {
    return {
        resolution: {
            notBefore: notBefore.toISOString(),
            effectiveNotAfter: effectiveNotAfter.toISOString(),
            effectiveMaxDays: 365,
            boundBy: 'CertProfile',
            certProfileNotAfter: effectiveNotAfter.toISOString(),
            spaceNotAfter: null,
            issuingCaNotAfter: null,
        },
        signingProfileName: 'issuing',
        certProfileName: 'TLS Server',
        certProfileValidityPeriodMax: 'P1Y',
        issuingCaName: 'Issuing CA',
        issuingCaNotAfter: null,
        spaceName: null,
        spaceMaxValidityDays: 0,
        spaceBehavior: 'Shorten',
        spaceCeilingApplies: true,
    } as ValidityCeilingPreflight;
}

describe('toDateInputValue', () => {
    it('is the local calendar day, not the UTC one', () => {
        // Half past midnight local is the previous UTC day anywhere east of UTC.
        expect(toDateInputValue(new Date(2026, 0, 2, 0, 30))).toBe('2026-01-02');
        expect(toDateInputValue(new Date(2026, 0, 2, 23, 30))).toBe('2026-01-02');
    });
});

describe('the picker limit', () => {
    it('is the local day the server ceiling falls on', () => {
        const ceiling = new Date(2027, 10, 8, 23, 30);
        expect(validUntilLimit(preflight(ceiling))?.maxDate).toBe('2027-11-08');
        const early = new Date(2027, 10, 8, 0, 15);
        expect(validUntilLimit(preflight(early))?.maxDate).toBe('2027-11-08');
    });

    it('carries the ceiling instant, to show and to clamp to', () => {
        const ceiling = new Date(2027, 10, 8, 10, 0);
        expect(validUntilLimit(preflight(ceiling))?.latest.getTime()).toBe(ceiling.getTime());
    });

    it('is absent while the ceiling is unknown or already passed', () => {
        expect(validUntilLimit(null)).toBeNull();
        const start = new Date(2026, 10, 8, 10, 0);
        expect(validUntilLimit(preflight(start, start))).toBeNull();
    });
});

describe('the notAfter submitted for a chosen day', () => {
    const ceiling = new Date(2027, 10, 8, 10, 0);
    const p = preflight(ceiling);

    it('never passes the server ceiling on the last day offered', () => {
        // The old picker sent 23:59:59 UTC on this day: past a ceiling of 10:00 local.
        const submitted = validUntilNotAfter(validUntilLimit(p)!.maxDate, p)!;
        expect(new Date(submitted).getTime()).toBeLessThanOrEqual(ceiling.getTime());
        expect(submitted).toBe(ceiling.toISOString());
    });

    it('is the end of the chosen local day before the last one', () => {
        expect(validUntilNotAfter('2027-11-07', p)).toBe(new Date(2027, 10, 7, 23, 59, 59).toISOString());
    });

    it('is the end of the chosen local day when the ceiling is unknown; the server decides', () => {
        expect(validUntilNotAfter('2030-01-01', null)).toBe(new Date(2030, 0, 1, 23, 59, 59).toISOString());
    });

    it('is omitted for a blank or unreadable day', () => {
        expect(validUntilNotAfter('', p)).toBeUndefined();
        expect(validUntilNotAfter('not-a-day', p)).toBeUndefined();
    });
});

describe('the pre-flight a request asks for', () => {
    it('names the request\'s signing and certificate profiles', () => {
        const url = validityCeilingUrl({ signingProfileId: 's 1', certificateProfileId: 'c1' })!;
        expect(url).toBe('/api/v1/admin/certificates/validity-ceiling?signingProfileId=s%201&certProfileId=c1');
    });

    it('measures from the start the request asked for, as issuance does', () => {
        const url = validityCeilingUrl({ signingProfileId: 's1', certProfileId: 'c1', requestedNotBefore: '2027-01-01T00:00:00Z' })!;
        expect(new URL(url, 'https://x').searchParams.get('notBefore')).toBe('2027-01-01T00:00:00Z');
    });

    it('is not asked without both profiles', () => {
        expect(validityCeilingUrl({ signingProfileId: 's1' })).toBeNull();
        expect(validityCeilingUrl({ certificateProfileId: 'c1' })).toBeNull();
        expect(validityCeilingUrl(null)).toBeNull();
    });
});
