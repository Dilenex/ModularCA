/**
 * Pure helpers behind the form that creates an SSH CA key and behind the key's advisory review
 * date: what the form pre-fills, what it sends, and when a key is shown as due for review.
 *
 * The numbers are the server's (ModularCA.Shared/Utils/SshCaKeyDefaults.cs); a test reads that
 * file and holds these to it. The design is docs/architecture/ssh-defaults.md.
 */

import { dateFieldValue, dayText, endOfDayIso, type DayFormat } from './sshLoginNames';

/** What a new SSH CA key signs. The form offers one or the other, never both. */
export type SshCaKeyKind = 'user' | 'host';

/** The longest certificate a new key signs, in hours, by what it signs. */
export const SSH_CA_MAX_VALIDITY_HOURS: Record<SshCaKeyKind, number> = { user: 24, host: 8760 };

/** How many years after its creation a key is due for review, by what it signs. */
export const SSH_CA_REVIEW_YEARS: Record<SshCaKeyKind, number> = { user: 2, host: 5 };

/** A key is shown as due for review this many days before its review date. */
export const SSH_CA_REVIEW_WARNING_DAYS = 90;

/** A review date can be set at most this many years ahead. */
export const SSH_CA_REVIEW_MAX_YEARS_AHEAD = 10;

/** Why the form asks for one type, said once on the form. */
export const WHY_ONE_TYPE =
    'One type per key: the two public keys go to different places (a user CA key to servers, a host CA key to clients), '
    + 'they need different lifetimes, and a leaked host CA key then cannot mint logins.';

/* ── the generate form ───────────────────────────────────────────────────── */

export interface SshCaKeyForm {
    name: string;
    keyType: string;
    keySize: string;
    kind: SshCaKeyKind;
    /** Hours as typed. */
    maxValidityHours: string;
    /** Whether the administrator has typed in the hours field; until then it follows the type. */
    hoursEdited: boolean;
}

/** The form as it opens: a user key, with the longest certificate pre-filled for a user key. */
export function emptySshCaKeyForm(): SshCaKeyForm {
    return { name: '', keyType: 'ed25519', keySize: '', kind: 'user', maxValidityHours: String(SSH_CA_MAX_VALIDITY_HOURS.user), hoursEdited: false };
}

/** The form after the type is chosen: the hours follow the type until they have been edited. */
export function withKind(form: SshCaKeyForm, kind: SshCaKeyKind): SshCaKeyForm {
    return form.hoursEdited ? { ...form, kind } : { ...form, kind, maxValidityHours: String(SSH_CA_MAX_VALIDITY_HOURS[kind]) };
}

/** The form after the administrator typed in the hours field. Only digits are kept. */
export function withHours(form: SshCaKeyForm, typed: string): SshCaKeyForm {
    return { ...form, maxValidityHours: typed.replace(/\D/g, ''), hoursEdited: true };
}

/** "24 hours", "8760 hours (1 year)": hours with the unit a reader thinks in. */
export function hoursText(hours: number): string {
    const unit = `${hours} ${hours === 1 ? 'hour' : 'hours'}`;
    if (hours >= 8760 && hours % 8760 === 0) return `${unit} (${hours / 8760} ${hours === 8760 ? 'year' : 'years'})`;
    if (hours >= 48 && hours % 24 === 0) return `${unit} (${hours / 24} days)`;
    return unit;
}

/** What is wrong with the hours field, or null. An empty field is the default for the type. */
export function hoursProblem(form: SshCaKeyForm): string | null {
    if (form.maxValidityHours === '') return null;
    return Number(form.maxValidityHours) >= 1 ? null : 'The longest certificate is at least 1 hour.';
}

/** The body of POST /api/v1/admin/ssh/ca-keys for the form: one of the two flags, never both. */
export function sshCaKeyBody(form: SshCaKeyForm): {
    name: string; keyType: string; keySize?: number; isUserCa: boolean; isHostCa: boolean; maxValidityHours: number;
} {
    const hours = Number(form.maxValidityHours);
    return {
        name: form.name || 'SSH CA Key',
        keyType: form.keyType,
        keySize: form.keySize ? parseInt(form.keySize, 10) : undefined,
        isUserCa: form.kind === 'user',
        isHostCa: form.kind === 'host',
        maxValidityHours: form.maxValidityHours !== '' && hours >= 1 ? hours : SSH_CA_MAX_VALIDITY_HOURS[form.kind],
    };
}

/* ── the review date ─────────────────────────────────────────────────────── */

/** What `GET /api/v1/admin/ssh/ca-keys` says about one key that the review date is read from. */
export interface SshCaKeyReviewFields {
    reviewBy?: string | null;
    isEnabled?: boolean;
}

export type SshCaKeyReviewState = 'none' | 'later' | 'soon' | 'past';

export interface SshCaKeyReview {
    state: SshCaKeyReviewState;
    /** Whole days until the review date, rounded up; null without a date, and once it has passed. */
    daysLeft: number | null;
    /** The badge beside the key's name; null when the key is not due. */
    badge: { status: 'held'; label: string } | null;
    /** The warning sentence; null when the key is not due. */
    warning: string | null;
}

const DAY_MS = 86_400_000;

/** Said wherever the review date is shown. */
export const REVIEW_DATE_ACTS_ON_NOTHING =
    'Nothing stops working on this date. The key keeps signing, its certificates stay valid and its revocation list is still served. '
    + 'The date is a reminder to decide whether the key should still be in use.';

/**
 * Whether a key is due for review at `now`: within SSH_CA_REVIEW_WARNING_DAYS of its review
 * date, or past it. A key with no date, and a disabled key, is never due.
 */
export function sshCaKeyReview(key: SshCaKeyReviewFields, now: Date, formatDay: DayFormat = dayText): SshCaKeyReview {
    const none: SshCaKeyReview = { state: 'none', daysLeft: null, badge: null, warning: null };
    if (!key.reviewBy || key.isEnabled === false) return none;
    const at = new Date(key.reviewBy).getTime();
    if (Number.isNaN(at)) return none;

    const left = at - now.getTime();
    const day = formatDay(key.reviewBy);
    if (left <= 0) {
        return { state: 'past', daysLeft: null, badge: { status: 'held', label: 'Review due' }, warning: `This key was due for review on ${day}. Review it, then move the date.` };
    }
    const daysLeft = Math.ceil(left / DAY_MS);
    if (left <= SSH_CA_REVIEW_WARNING_DAYS * DAY_MS) {
        const inDays = daysLeft === 1 ? 'in 1 day' : `in ${daysLeft} days`;
        return {
            state: 'soon', daysLeft,
            badge: { status: 'held', label: `Review in ${daysLeft} d` },
            warning: `This key is due for review on ${day}, ${inDays}.`,
        };
    }
    return { state: 'later', daysLeft, badge: null, warning: null };
}

/** The value of the date field for a key's stored review date. */
export function reviewDateFieldValue(key: SshCaKeyReviewFields): string {
    return dateFieldValue(key.reviewBy);
}

/** The moment a date field names as a review date: the end of that day, in the reader's time zone. */
export function reviewByToSend(dateField: string): string | null {
    return endOfDayIso(dateField);
}

/** What is wrong with a new review date, or null: it is in the future and at most ten years ahead. */
export function reviewByProblem(dateField: string, now: Date): string | null {
    const iso = reviewByToSend(dateField);
    if (!iso) return 'Choose a date.';
    const at = new Date(iso);
    if (at.getTime() <= now.getTime()) return 'The review date must be in the future.';
    const latest = new Date(now);
    latest.setFullYear(latest.getFullYear() + SSH_CA_REVIEW_MAX_YEARS_AHEAD);
    if (at.getTime() > latest.getTime()) return `The review date can be at most ${SSH_CA_REVIEW_MAX_YEARS_AHEAD} years ahead.`;
    return null;
}
