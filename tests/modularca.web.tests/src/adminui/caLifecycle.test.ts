import { describe, expect, it } from 'vitest';
import {
    CA_LIFECYCLE_DEFAULTS, advisoryTitle, advisoryTone, caLifecycleAttention, caLifecycleBody, caLifecycleProblem, caLifecycleSummary,
    cryptoperiodRows, daysPhrase,
} from '@adminui/pages/caLifecycle';

describe('the CA lifecycle settings card', () => {
    it('sends the three numbers, with the defaults for what the page has not loaded', () => {
        expect(caLifecycleBody(null)).toEqual(CA_LIFECYCLE_DEFAULTS);
        expect(caLifecycleBody({ rootExpiryNoticeDays: 0, keyUsagePeriodDays: 3650 }))
            .toEqual({ rootExpiryNoticeDays: 0, intermediateExpiryNoticeDays: 365, keyUsagePeriodDays: 3650 });
    });

    it('refuses a value outside 0 to 36500 days and accepts the bounds', () => {
        expect(caLifecycleProblem(CA_LIFECYCLE_DEFAULTS)).toBeNull();
        expect(caLifecycleProblem({ ...CA_LIFECYCLE_DEFAULTS, keyUsagePeriodDays: 36500 })).toBeNull();
        expect(caLifecycleProblem({ ...CA_LIFECYCLE_DEFAULTS, keyUsagePeriodDays: 36501 })).toContain('key usage period');
        expect(caLifecycleProblem({ ...CA_LIFECYCLE_DEFAULTS, rootExpiryNoticeDays: -1 })).toContain('root CA');
        expect(caLifecycleProblem({ ...CA_LIFECYCLE_DEFAULTS, intermediateExpiryNoticeDays: 1.5 })).toContain('intermediate CA');
    });

    it('summarizes the card in one line', () => {
        expect(caLifecycleSummary(CA_LIFECYCLE_DEFAULTS)).toBe('Root 730d / intermediate 365d before expiry; key usage period off');
        expect(caLifecycleSummary({ rootExpiryNoticeDays: 0, intermediateExpiryNoticeDays: 0, keyUsagePeriodDays: 1095 }))
            .toBe('Root off / intermediate off before expiry; key usage period 1095d');
    });
});

describe('a CA notice in the console', () => {
    it('takes its tone from the severity and is something to plan for without one', () => {
        expect(advisoryTone({ severity: 'critical' })).toBe('crit');
        expect(advisoryTone({ severity: 'warning' })).toBe('warn');
        expect(advisoryTone({ severity: 'notice' })).toBe('notice');
        expect(advisoryTone({})).toBe('notice');
        expect(advisoryTone(null)).toBe('notice');
    });

    it('is headed by the title the server sends, or by what the console said before', () => {
        expect(advisoryTitle({ reason: 'CaCertificateExpiring', title: 'Certificate expires in 3 months' })).toBe('Certificate expires in 3 months');
        expect(advisoryTitle({ reason: 'CaRsaKeyBelow3072' })).toBe('Replace before 2031');
        expect(advisoryTitle({ reason: 'Other', title: ' ' })).toBe('Notice');
    });
});

describe('the lifetime section of a CA page', () => {
    it('has no rows without the facts', () => {
        expect(cryptoperiodRows(null)).toEqual([]);
        expect(cryptoperiodRows(undefined)).toEqual([]);
    });

    it('shows each fact with its unit and where it comes from', () => {
        const rows = cryptoperiodRows({
            keyInUseSince: '2020-01-01T00:00:00Z', keyInUseSinceSource: 'earliest certificate', keyInUseDays: 2500, certificateCount: 2,
            certificateNotAfter: '2030-06-30T00:00:00Z', daysRemaining: 400, latestIssuedNotAfter: '2029-01-01T00:00:00Z',
            longestProfileValidityDays: 397, longestProfileName: 'TLS Server', parentName: 'Root', parentCertificateNotAfter: '2040-01-01T00:00:00Z',
        });
        expect(rows.map((r) => [r.label, r.value])).toEqual([
            ['Key in use since', '2020-01-01 (6.8 years)'],
            ['Certificates over this key', '2 (renewed 1 time)'],
            ['Current certificate expires', '2030-06-30 (in 400 days)'],
            ['Latest expiry it has issued', '2029-01-01'],
            ['Longest validity its profiles allow', '397 days (TLS Server)'],
            ["Parent's certificate expires", '2040-01-01 (Root)'],
        ]);
        expect(rows[0].hint).toBe('earliest certificate');
    });

    it('says so when the certificate has expired, was never renewed, or has issued nothing still valid', () => {
        const rows = cryptoperiodRows({ certificateCount: 1, certificateNotAfter: '2020-01-01T00:00:00Z', daysRemaining: -3 });
        expect(rows.map((r) => r.value)).toEqual(['1 (never renewed)', '2020-01-01 (expired 3 days ago)', 'No unexpired certificate']);
    });

    it('words days as days under two years and as years after', () => {
        expect(daysPhrase(1)).toBe('1 day');
        expect(daysPhrase(729)).toBe('729 days');
        expect(daysPhrase(730)).toBe('2 years');
        expect(daysPhrase(null)).toBe('-');
    });
});

describe('CAs under Needs attention', () => {
    const health = (cas: unknown) => ({ status: 'healthy', checks: { caLifecycle: { status: 'attention', cas } } });
    const expiring = { reason: 'CaCertificateExpiring', severity: 'warning', title: 'Certificate expires in 20 days', message: 'Renew it.' };
    const expired = { reason: 'CaCertificateExpired', severity: 'critical', title: 'Certificate expired', message: 'It expired.' };
    const planning = { reason: 'CaCertificateExpiring', severity: 'notice', title: 'Certificate expires in 2 years', message: 'Plan.' };

    it('lists nothing when the answer is missing or unreadable', () => {
        expect(caLifecycleAttention(null)).toEqual([]);
        expect(caLifecycleAttention({})).toEqual([]);
        expect(caLifecycleAttention({ checks: { caLifecycle: { cas: 'x' } } })).toEqual([]);
    });

    it('leaves out a CA whose notices are only something to plan for', () => {
        expect(caLifecycleAttention(health([{ caId: 'a', caName: 'Root', keyAdvisories: [planning] }]))).toEqual([]);
    });

    it('lists a CA once, with its most pressing notice and a link to its page', () => {
        const items = caLifecycleAttention(health([
            { caId: 'a b', caName: 'Issuing', keyAdvisories: [planning, expiring, expired] },
            { caId: 'c', caName: '', keyAdvisories: [expiring] },
            { caName: 'no id', keyAdvisories: [expired] },
        ]));
        expect(items).toEqual([
            { caId: 'a b', caName: 'Issuing', tone: 'crit', title: 'Issuing: Certificate expired', message: 'It expired.', to: '/authorities/manage/a%20b' },
            { caId: 'c', caName: 'c', tone: 'warn', title: 'c: Certificate expires in 20 days', message: 'Renew it.', to: '/authorities/manage/c' },
        ]);
    });
});
