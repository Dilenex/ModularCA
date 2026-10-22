import { describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import {
    REVIEW_DATE_ACTS_ON_NOTHING, SSH_CA_MAX_VALIDITY_HOURS, SSH_CA_REVIEW_MAX_YEARS_AHEAD, SSH_CA_REVIEW_WARNING_DAYS, SSH_CA_REVIEW_YEARS, WHY_ONE_TYPE,
    emptySshCaKeyForm, hoursProblem, hoursText, reviewByProblem, reviewByToSend, sshCaKeyBody, sshCaKeyReview, withHours, withKind,
} from '@adminui/pages/sshCaDefaults';

/**
 * The form that creates an SSH CA key and the key's advisory review date
 * (docs/architecture/ssh-defaults.md). The numbers were decided by the owner on 2026-10-08:
 * a test here fails when one is changed, on either side.
 */

const day = (iso: string) => `on ${iso.slice(0, 10)}`;
const NOW = new Date('2026-10-08T12:00:00Z');
const inDays = (days: number) => new Date(NOW.getTime() + days * 86_400_000).toISOString();

describe('the decided numbers', () => {
    it('are 24 hours and 2 years for a user key, 8760 hours and 5 years for a host key', () => {
        expect(SSH_CA_MAX_VALIDITY_HOURS).toEqual({ user: 24, host: 8760 });
        expect(SSH_CA_REVIEW_YEARS).toEqual({ user: 2, host: 5 });
        expect(SSH_CA_REVIEW_WARNING_DAYS).toBe(90);
        expect(SSH_CA_REVIEW_MAX_YEARS_AHEAD).toBe(10);
    });

    it('are the numbers the server holds', () => {
        const source = readFileSync(resolve(__dirname, '../../../../ModularCA.Shared/Utils/SshCaKeyDefaults.cs'), 'utf8');
        const constant = (name: string) => {
            const found = new RegExp(`public const int ${name} = (\\d+);`).exec(source);
            expect(found, name).not.toBeNull();
            return Number(found![1]);
        };
        expect(constant('UserMaxValidityHours')).toBe(SSH_CA_MAX_VALIDITY_HOURS.user);
        expect(constant('HostMaxValidityHours')).toBe(SSH_CA_MAX_VALIDITY_HOURS.host);
        expect(constant('UserReviewYears')).toBe(SSH_CA_REVIEW_YEARS.user);
        expect(constant('HostReviewYears')).toBe(SSH_CA_REVIEW_YEARS.host);
        expect(constant('ReviewWarningDays')).toBe(SSH_CA_REVIEW_WARNING_DAYS);
        expect(constant('MaxReviewYearsAhead')).toBe(SSH_CA_REVIEW_MAX_YEARS_AHEAD);
    });
});

describe('the form that creates an SSH CA key', () => {
    it('opens as a user key with 24 hours', () => {
        const form = emptySshCaKeyForm();
        expect(form.kind).toBe('user');
        expect(form.maxValidityHours).toBe('24');
        expect(form.hoursEdited).toBe(false);
    });

    it('follows the type until the hours are edited', () => {
        const host = withKind(emptySshCaKeyForm(), 'host');
        expect(host.maxValidityHours).toBe('8760');
        expect(withKind(host, 'user').maxValidityHours).toBe('24');

        const edited = withHours(host, '4380');
        expect(edited.hoursEdited).toBe(true);
        expect(withKind(edited, 'user').maxValidityHours).toBe('4380');
        expect(withKind(withKind(edited, 'user'), 'host').maxValidityHours).toBe('4380');
    });

    it('keeps only digits in the hours field', () => {
        expect(withHours(emptySshCaKeyForm(), '1 2h').maxValidityHours).toBe('12');
    });

    it('sends one type, never both and never neither', () => {
        const user = sshCaKeyBody({ ...emptySshCaKeyForm(), name: 'Users' });
        expect(user).toMatchObject({ name: 'Users', isUserCa: true, isHostCa: false, maxValidityHours: 24 });

        const host = sshCaKeyBody(withKind({ ...emptySshCaKeyForm(), name: 'Hosts' }, 'host'));
        expect(host).toMatchObject({ name: 'Hosts', isUserCa: false, isHostCa: true, maxValidityHours: 8760 });
    });

    it('sends the hours that were typed, and the default for the type when the field is empty', () => {
        expect(sshCaKeyBody(withHours(emptySshCaKeyForm(), '8')).maxValidityHours).toBe(8);
        expect(sshCaKeyBody(withHours(emptySshCaKeyForm(), '')).maxValidityHours).toBe(24);
        expect(sshCaKeyBody(withHours(withKind(emptySshCaKeyForm(), 'host'), '')).maxValidityHours).toBe(8760);
    });

    it('refuses zero hours and accepts an empty field', () => {
        expect(hoursProblem(withHours(emptySshCaKeyForm(), '0'))).toMatch(/at least 1 hour/);
        expect(hoursProblem(withHours(emptySshCaKeyForm(), ''))).toBeNull();
        expect(hoursProblem(emptySshCaKeyForm())).toBeNull();
    });

    it('sends the key size only when one was chosen', () => {
        expect(sshCaKeyBody(emptySshCaKeyForm()).keySize).toBeUndefined();
        expect(sshCaKeyBody({ ...emptySshCaKeyForm(), keyType: 'rsa', keySize: '4096' }).keySize).toBe(4096);
    });

    it('says why there is one type', () => {
        expect(WHY_ONE_TYPE).toMatch(/servers/);
        expect(WHY_ONE_TYPE).toMatch(/clients/);
        expect(WHY_ONE_TYPE).toMatch(/lifetimes/);
        expect(WHY_ONE_TYPE).toMatch(/leaked host CA key/);
    });

    it('writes hours with the unit a reader thinks in', () => {
        expect(hoursText(1)).toBe('1 hour');
        expect(hoursText(24)).toBe('24 hours');
        expect(hoursText(720)).toBe('720 hours (30 days)');
        expect(hoursText(8760)).toBe('8760 hours (1 year)');
        expect(hoursText(17520)).toBe('17520 hours (2 years)');
    });
});

describe('when a key is shown as due for review', () => {
    it('is not due more than 90 days before the date', () => {
        const review = sshCaKeyReview({ reviewBy: inDays(91) }, NOW, day);
        expect(review.state).toBe('later');
        expect(review.badge).toBeNull();
        expect(review.warning).toBeNull();
    });

    it('is due from 90 days before the date', () => {
        const review = sshCaKeyReview({ reviewBy: inDays(90) }, NOW, day);
        expect(review.state).toBe('soon');
        expect(review.daysLeft).toBe(90);
        expect(review.badge).toEqual({ status: 'held', label: 'Review in 90 d' });
        expect(review.warning).toContain('is due for review');
        expect(review.warning).toContain('in 90 days');
    });

    it('counts a part of a day as a day', () => {
        const review = sshCaKeyReview({ reviewBy: new Date(NOW.getTime() + 3_600_000).toISOString() }, NOW, day);
        expect(review.daysLeft).toBe(1);
        expect(review.warning).toContain('in 1 day.');
    });

    it('stays due after the date', () => {
        for (const days of [0, -1, -400]) {
            const review = sshCaKeyReview({ reviewBy: inDays(days) }, NOW, day);
            expect(review.state).toBe('past');
            expect(review.badge).toEqual({ status: 'held', label: 'Review due' });
            expect(review.warning).toContain('was due for review');
        }
    });

    it('is never due without a date, with an unreadable date, or when the key is disabled', () => {
        expect(sshCaKeyReview({}, NOW, day).state).toBe('none');
        expect(sshCaKeyReview({ reviewBy: null }, NOW, day).state).toBe('none');
        expect(sshCaKeyReview({ reviewBy: 'soon' }, NOW, day).state).toBe('none');
        expect(sshCaKeyReview({ reviewBy: inDays(-5), isEnabled: false }, NOW, day).warning).toBeNull();
    });

    it('never says the key stops working', () => {
        expect(REVIEW_DATE_ACTS_ON_NOTHING).toMatch(/^Nothing stops working on this date\./);
        for (const days of [30, -30]) {
            const warning = sshCaKeyReview({ reviewBy: inDays(days) }, NOW, day).warning!;
            expect(warning).not.toMatch(/expire|disabled|revoked|stop/i);
        }
    });
});

describe('moving the review date', () => {
    const field = (d: Date) => `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, '0')}-${String(d.getDate()).padStart(2, '0')}`;
    const localNow = new Date(2026, 9, 8, 12, 0, 0);

    it('sends the end of the chosen day', () => {
        const sent = new Date(reviewByToSend('2028-10-08')!);
        expect([sent.getFullYear(), sent.getMonth(), sent.getDate(), sent.getHours(), sent.getMinutes()]).toEqual([2028, 9, 8, 23, 59]);
        expect(reviewByToSend('')).toBeNull();
    });

    it('accepts a date in the future up to ten years ahead', () => {
        expect(reviewByProblem(field(new Date(2026, 9, 9)), localNow)).toBeNull();
        expect(reviewByProblem(field(new Date(2028, 9, 8)), localNow)).toBeNull();
        expect(reviewByProblem(field(new Date(2036, 9, 7)), localNow)).toBeNull();
    });

    it('refuses a date in the past, one too far ahead and no date', () => {
        expect(reviewByProblem(field(new Date(2026, 9, 7)), localNow)).toMatch(/in the future/);
        expect(reviewByProblem(field(new Date(2036, 9, 9)), localNow)).toMatch(/at most 10 years ahead/);
        expect(reviewByProblem('', localNow)).toMatch(/Choose a date/);
    });
});
